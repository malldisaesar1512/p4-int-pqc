#!/usr/bin/env python3
"""
FASE 5: Switch Agent -- jalan SATU PER SWITCH (s1, s2, s3).

Menerima kunci baru lewat kanal PQC-TLS (ML-KEM768 utk key exchange,
ML-DSA65 utk autentikasi server), lalu memasang kunci itu ke switch-nya
SENDIRI lewat P4Runtime lokal (127.0.0.1, nggak pernah keluar jaringan).

OpenSSL dipanggil lewat subprocess (BUKAN modul ssl Python),
karena Python system masih link ke OpenSSL 3.0.
OpenSSL eksperimen menggunakan ~/openssl35.

Cara pakai:
  python3 switch_agent.py --switch s1 --grpc 127.0.0.1:50051 --device-id 0 --listen 6001
  python3 switch_agent.py --switch s2 --grpc 127.0.0.1:50052 --device-id 1 --listen 6002
  python3 switch_agent.py --switch s3 --grpc 127.0.0.1:50053 --device-id 2 --listen 6003
"""

import argparse
import os
import subprocess
import sys
import time

UTILS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', '..', 'utils'
)
sys.path.append(UTILS_PATH)

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections


P4INFO_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "build",
    "int_source.p4.p4info.txtpb"
)

CERT_PATH = os.path.expanduser("~/pqc_agent_cert.pem")
KEY_PATH = os.path.expanduser("~/pqc_agent_key.pem")

# OpenSSL 3.5 khusus eksperimen
OPENSSL_BIN = os.path.expanduser("~/openssl35/bin/openssl")

# Library OpenSSL 3.5
OPENSSL_HOME = os.path.expanduser("~/openssl35")
OPENSSL_LIB64 = os.path.join(OPENSSL_HOME, "lib64")
OPENSSL_LIB = os.path.join(OPENSSL_HOME, "lib")

OPENSSL_ENV = os.environ.copy()
OPENSSL_ENV["LD_LIBRARY_PATH"] = (
    OPENSSL_LIB64 + ":" +
    OPENSSL_LIB + ":" +
    OPENSSL_ENV.get("LD_LIBRARY_PATH", "")
)


def ensure_cert():
    """Bikin cert ML-DSA self-signed sekali kalau belum ada."""

    if os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
        return

    print("[switch_agent] generate cert ML-DSA (sekali saja)...")

    subprocess.run(
        [
            OPENSSL_BIN,
            "genpkey",
            "-algorithm",
            "ML-DSA-65",
            "-out",
            KEY_PATH,
        ],
        check=True,
        env=OPENSSL_ENV,
    )

    subprocess.run(
        [
            OPENSSL_BIN,
            "req",
            "-x509",
            "-new",
            "-key",
            KEY_PATH,
            "-out",
            CERT_PATH,
            "-days",
            "3650",
            "-subj",
            "/CN=switch-agent",
        ],
        check=True,
        env=OPENSSL_ENV,
    )


def receive_one_key(listen_port):
    """
    Jalankan openssl s_server SEKALI, tunggu satu baris data (kunci hex),
    lalu proses berhenti.

    Mengembalikan:
        (key_int, elapsed_detik)
    atau:
        None
    """

    cmd = [
        OPENSSL_BIN,
        "s_server",
        "-accept", str(listen_port),
        "-cert", CERT_PATH,
        "-key", KEY_PATH,
        "-tls1_3",
        "-groups", "MLKEM768",
        "-naccept", "1",
        "-quiet",
    ]

    t0 = time.time()

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=OPENSSL_ENV,
    )

    try:
        # Tunggu hasil dari TLS client.
        line = proc.stdout.readline()

        # Kalau s_server gagal start, stderr akan berisi alasannya.
        if not line and proc.poll() is not None:
            stderr = proc.stderr.read().strip()

            if stderr:
                print(
                    f"[switch_agent] ERROR openssl s_server: {stderr}"
                )
            else:
                print(
                    "[switch_agent] ERROR: openssl s_server berhenti."
                )

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
        print(
            f"[switch_agent] data diterima tapi bukan hex valid: {line!r}"
        )
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

    parser.add_argument(
        "--switch",
        required=True,
        help="nama switch, mis. s1"
    )

    parser.add_argument(
        "--grpc",
        required=True,
        help="alamat P4Runtime switch, mis. 127.0.0.1:50051"
    )

    parser.add_argument(
        "--device-id",
        type=int,
        required=True
    )

    parser.add_argument(
        "--listen",
        type=int,
        required=True,
        help="port PQC-TLS utk nerima kunci"
    )

    args = parser.parse_args()

    if not os.path.exists(P4INFO_PATH):
        print(
            f"[switch_agent] ERROR: p4info tidak ketemu di "
            f"{P4INFO_PATH}"
        )
        sys.exit(1)

    # Cek OpenSSL 3.5
    try:
        result = subprocess.run(
            [OPENSSL_BIN, "version"],
            check=True,
            capture_output=True,
            text=True,
            env=OPENSSL_ENV,
        )

        print(
            f"[switch_agent] {result.stdout.strip()}"
        )

    except Exception as e:
        print(
            f"[switch_agent] ERROR OpenSSL: {e}"
        )
        sys.exit(1)

    ensure_cert()

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(
        P4INFO_PATH
    )

    conn = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name=args.switch,
        address=args.grpc,
        device_id=args.device_id
    )

    conn.MasterArbitrationUpdate()

    print(
        f"[switch_agent:{args.switch}] siap, "
        f"dengerin PQC-TLS di port {args.listen}, "
        f"P4Runtime ke {args.grpc}"
    )

    try:
        while True:

            result = receive_one_key(
                args.listen
            )

            if result is None:
                time.sleep(0.1)
                continue

            key_int, elapsed = result

            try:

                push_mac_key_local(
                    p4info_helper,
                    conn,
                    key_int
                )

                print(
                    f"[switch_agent:{args.switch}] "
                    f"kunci baru {hex(key_int)} terpasang "
                    f"(waktu kirim+terima PQC: "
                    f"{elapsed * 1000:.2f} ms)"
                )

            except Exception as e:

                print(
                    f"[switch_agent:{args.switch}] "
                    f"GAGAL pasang kunci -> {e}"
                )

    except KeyboardInterrupt:

        print(
            f"\n[switch_agent:{args.switch}] berhenti."
        )

    finally:

        ShutdownAllSwitchConnections()


if __name__ == "__main__":
    main()