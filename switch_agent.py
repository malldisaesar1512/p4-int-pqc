#!/usr/bin/env python3
"""
FASE 5 (+ baseline klasik): Switch Agent -- jalan SATU PER SWITCH (s1, s2, s3).

Menerima kunci baru lewat kanal TLS, lalu memasang kunci itu ke switch-nya
SENDIRI lewat P4Runtime lokal (127.0.0.1, nggak pernah keluar jaringan).

Mendukung dua mode (--mode):
  pqc        (default) -- ML-KEM768 (key exchange) + ML-DSA-65 (autentikasi)
  classical  -- X25519 (key exchange) + ECDSA P-256 (autentikasi), buat
                baseline pembanding klasik di eksperimen Fase 7.

Cara pakai (CONTOH, 3 terminal/tab berbeda, satu per switch):
  python3 switch_agent.py --switch s1 --grpc 127.0.0.1:50051 --device-id 0 --listen 6001 --mode pqc
  python3 switch_agent.py --switch s2 --grpc 127.0.0.1:50052 --device-id 1 --listen 6002 --mode pqc
  python3 switch_agent.py --switch s3 --grpc 127.0.0.1:50053 --device-id 2 --listen 6003 --mode pqc

Ganti --mode classical (di ketiganya) buat jalanin baseline klasik --
JANGAN campur mode beda di tiap switch, controller.py juga harus pakai
--mode yang sama persis.
"""

import argparse
import hashlib
import os
import subprocess
import sys
import time

UTILS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'utils')
sys.path.append(UTILS_PATH)

import p4runtime_lib.bmv2          # noqa: E402
import p4runtime_lib.helper        # noqa: E402
from p4runtime_lib.switch import ShutdownAllSwitchConnections  # noqa: E402

P4INFO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "build", "siphash.p4.p4info.txtpb")

OPENSSL_HOME = "/home/ubuntu22/openssl35"
OPENSSL_BIN = os.path.join(OPENSSL_HOME, "bin", "openssl")
OPENSSL_ENV = os.environ.copy()
OPENSSL_ENV["LD_LIBRARY_PATH"] = (
    os.path.join(OPENSSL_HOME, "lib64") + ":" +
    os.path.join(OPENSSL_HOME, "lib") + ":" +
    OPENSSL_ENV.get("LD_LIBRARY_PATH", "")
)

MODE_CONFIG = {
    "pqc": {
        "groups": "MLKEM768",
        "sig_algo": "ML-DSA-65",
        "cert": "/home/ubuntu22/pqc_agent_cert.pem",
        "key": "/home/ubuntu22/pqc_agent_key.pem",
    },
    "classical": {
        "groups": "X25519",
        "sig_algo": "EC",
        "ec_curve": "prime256v1",
        "cert": "/home/ubuntu22/classical_agent_cert.pem",
        "key": "/home/ubuntu22/classical_agent_key.pem",
    },
}


def ensure_cert(cfg):
    """Bikin cert self-signed sekali kalau belum ada (dipakai ulang tiap
    restart s_server, biar nggak generate ulang tiap rotasi)."""
    if os.path.exists(cfg["cert"]) and os.path.exists(cfg["key"]):
        return
    print(f"[switch_agent] generate cert {cfg['sig_algo']} (sekali saja)...")
    if cfg["sig_algo"] == "EC":
        subprocess.run([OPENSSL_BIN, "ecparam", "-genkey", "-name", cfg["ec_curve"], "-out", cfg["key"]],
                        check=True, env=OPENSSL_ENV)
    else:
        subprocess.run([OPENSSL_BIN, "genpkey", "-algorithm", cfg["sig_algo"], "-out", cfg["key"]],
                        check=True, env=OPENSSL_ENV)
    subprocess.run([OPENSSL_BIN, "req", "-x509", "-new", "-key", cfg["key"],
                     "-out", cfg["cert"], "-days", "3650", "-subj", "/CN=switch-agent"],
                    check=True, env=OPENSSL_ENV)


def receive_one_key(listen_port, cfg):
    """Jalankan openssl s_server SEKALI, tunggu satu baris data (kunci dalam
    hex), lalu proses berhenti (kembali dipanggil lagi oleh loop utama utk
    rotasi berikutnya). Mengembalikan (key_int, elapsed_detik) atau None."""
    cmd = [
        OPENSSL_BIN, "s_server",
        "-accept", str(listen_port),
        "-cert", cfg["cert"], "-key", cfg["key"],
        "-tls1_3", "-groups", cfg["groups"],
        "-naccept", "1",
        "-quiet",
    ]
    t0 = time.time()
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, bufsize=1, env=OPENSSL_ENV)
    try:
        line = proc.stdout.readline()
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
    elapsed = time.time() - t0

    line = line.strip()
    if not line:
        return None
    try:
        key_int = int(line, 16)
    except ValueError:
        print(f"[switch_agent] data diterima tapi bukan hex valid: {line!r}")
        return None
    return key_int, elapsed


def push_mac_key_local(p4info_helper, conn, key_value):
    entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.mac_key_table",
        default_action=True,
        action_name="MyIngress.set_mac_key",
        action_params={"key": key_value},
    )
    conn.WriteTableEntry(entry)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--switch", required=True, help="nama switch, mis. s1")
    parser.add_argument("--grpc", required=True, help="alamat P4Runtime switch, mis. 127.0.0.1:50051")
    parser.add_argument("--device-id", type=int, required=True)
    parser.add_argument("--listen", type=int, required=True, help="port TLS utk nerima kunci")
    parser.add_argument("--mode", choices=["pqc", "classical"], default="pqc")
    parser.add_argument("--apply-log", default=None,
                        help="(opsional) CSV: tiap kunci terpasang, tulis epoch,switch,fingerprint. "
                             "Dipakai rotation_test.py utk mengukur jendela rotasi.")
    args = parser.parse_args()
    cfg = MODE_CONFIG[args.mode]

    if not os.path.exists(P4INFO_PATH):
        print(f"[switch_agent] ERROR: p4info tidak ketemu di {P4INFO_PATH}")
        sys.exit(1)

    ensure_cert(cfg)

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(P4INFO_PATH)
    conn = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name=args.switch, address=args.grpc, device_id=args.device_id)
    conn.MasterArbitrationUpdate()
    print(f"[switch_agent:{args.switch}] siap, mode={args.mode} (groups={cfg['groups']}), "
          f"dengerin di port {args.listen}, P4Runtime ke {args.grpc}")

    try:
        while True:
            result = receive_one_key(args.listen, cfg)
            if result is None:
                continue
            key_int, elapsed = result
            try:
                push_mac_key_local(p4info_helper, conn, key_int)
                t_applied = time.time()   # tepat setelah WriteTableEntry sukses
                if args.apply_log:
                    fp = hashlib.sha256(format(key_int, "x").encode()).hexdigest()[:8]
                    with open(args.apply_log, "a") as lf:
                        lf.write(f"{t_applied:.6f},{args.switch},{fp}\n")
                print(f"[switch_agent:{args.switch}] kunci baru {hex(key_int)} terpasang "
                      f"(waktu kirim+terima [{args.mode}]: {elapsed*1000:.2f} ms)")
            except Exception as e:
                print(f"[switch_agent:{args.switch}] GAGAL pasang kunci -> {e}")
    except KeyboardInterrupt:
        print(f"\n[switch_agent:{args.switch}] berhenti.")
    finally:
        ShutdownAllSwitchConnections()


if __name__ == "__main__":
    main()