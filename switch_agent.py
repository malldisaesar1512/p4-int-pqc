#!/usr/bin/env python3
"""
FASE 5: Switch Agent -- jalan SATU PER SWITCH (s1, s2, s3).

Menerima kunci baru lewat kanal PQC-TLS (ML-KEM768 utk key exchange,
ML-DSA65 utk autentikasi server), lalu memasang kunci itu ke switch-nya
SENDIRI lewat P4Runtime lokal (127.0.0.1, nggak pernah keluar jaringan).

Dipanggil lewat subprocess ke binary `openssl` (BUKAN modul ssl Python),
karena modul ssl Python di sistem ini masih ke-link ke OpenSSL 3.0 yang
belum punya ML-KEM/ML-DSA, sementara binary `openssl` di PATH ($HOME/openssl35)
sudah versi 4.0 yang asli punya PQC. Lihat riwayat chat utk detail kenapa.

Cara pakai (CONTOH, 3 terminal/tab berbeda, satu per switch):
  python3 switch_agent.py --switch s1 --grpc 127.0.0.1:50051 --device-id 0 --listen 6001
  python3 switch_agent.py --switch s2 --grpc 127.0.0.1:50052 --device-id 1 --listen 6002
  python3 switch_agent.py --switch s3 --grpc 127.0.0.1:50053 --device-id 2 --listen 6003
"""

import argparse
import os
import subprocess
import sys
import time

UTILS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'utils')
sys.path.append(UTILS_PATH)

import p4runtime_lib.bmv2          # noqa: E402
import p4runtime_lib.helper        # noqa: E402
from p4runtime_lib.switch import ShutdownAllSwitchConnections  # noqa: E402

P4INFO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "build", "int_source.p4.p4info.txtpb")
CERT_PATH = os.path.expanduser("~/pqc_agent_cert.pem")
KEY_PATH = os.path.expanduser("~/pqc_agent_key.pem")


def ensure_cert():
    """Bikin cert ML-DSA self-signed sekali kalau belum ada (dipakai ulang
    tiap restart s_server, biar nggak generate ulang tiap rotasi)."""
    if os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
        return
    print("[switch_agent] generate cert ML-DSA (sekali saja)...")
    subprocess.run(["openssl", "genpkey", "-algorithm", "ML-DSA-65", "-out", KEY_PATH], check=True)
    subprocess.run(["openssl", "req", "-x509", "-new", "-key", KEY_PATH,
                     "-out", CERT_PATH, "-days", "3650", "-subj", "/CN=switch-agent"], check=True)


def receive_one_key(listen_port):
    """Jalankan openssl s_server SEKALI, tunggu satu baris data (kunci dalam
    hex), lalu proses berhenti (kembali dipanggil lagi oleh loop utama utk
    rotasi berikutnya). Mengembalikan (key_int, elapsed_detik) atau None."""
    cmd = [
        "openssl", "s_server",
        "-accept", str(listen_port),
        "-cert", CERT_PATH, "-key", KEY_PATH,
        "-tls1_3", "-groups", "MLKEM768",
        "-naccept", "1",
        "-quiet",
    ]
    t0 = time.time()
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, bufsize=1)
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
    parser.add_argument("--listen", type=int, required=True, help="port PQC-TLS utk nerima kunci")
    args = parser.parse_args()

    if not os.path.exists(P4INFO_PATH):
        print(f"[switch_agent] ERROR: p4info tidak ketemu di {P4INFO_PATH}")
        sys.exit(1)

    ensure_cert()

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(P4INFO_PATH)
    conn = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name=args.switch, address=args.grpc, device_id=args.device_id)
    conn.MasterArbitrationUpdate()
    print(f"[switch_agent:{args.switch}] siap, dengerin PQC-TLS di port {args.listen}, "
          f"P4Runtime ke {args.grpc}")

    try:
        while True:
            result = receive_one_key(args.listen)
            if result is None:
                continue
            key_int, elapsed = result
            try:
                push_mac_key_local(p4info_helper, conn, key_int)
                print(f"[switch_agent:{args.switch}] kunci baru {hex(key_int)} terpasang "
                      f"(waktu kirim+terima PQC: {elapsed*1000:.2f} ms)")
            except Exception as e:
                print(f"[switch_agent:{args.switch}] GAGAL pasang kunci -> {e}")
    except KeyboardInterrupt:
        print(f"\n[switch_agent:{args.switch}] berhenti.")
    finally:
        ShutdownAllSwitchConnections()


if __name__ == "__main__":
    main()