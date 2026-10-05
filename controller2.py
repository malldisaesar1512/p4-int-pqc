#!/usr/bin/env python3
"""
FASE 5: Controller -- kirim kunci lewat PQC-TLS ke switch_agent.py di tiap
switch (BUKAN langsung P4Runtime lagi -- itu tugas switch_agent.py sekarang).

Alurnya:
  controller.py --(generate kunci baru)--> openssl s_client (PQC-TLS,
  ML-KEM768 + ML-DSA65) --> switch_agent.py (tiap switch) --> P4Runtime
  lokal switch itu sendiri.

Jalankan SETELAH ketiga switch_agent.py (s1, s2, s3) sudah jalan dan
dengerin di port masing-masing.
"""

import argparse
import os
import random
import subprocess
import time

# --- Konfigurasi OpenSSL 3.5 eksperimen (pola sama persis spt switch_agent.py) ---
OPENSSL_HOME = os.path.expanduser("~/openssl35")
OPENSSL_BIN = os.path.join(OPENSSL_HOME, "bin", "openssl")
OPENSSL_ENV = os.environ.copy()
OPENSSL_ENV["LD_LIBRARY_PATH"] = (
    os.path.join(OPENSSL_HOME, "lib64") + ":" +
    os.path.join(OPENSSL_HOME, "lib") + ":" +
    OPENSSL_ENV.get("LD_LIBRARY_PATH", "")
)

AGENTS = [
    {"name": "s1", "host": "127.0.0.1", "port": 6001},
    {"name": "s2", "host": "127.0.0.1", "port": 6002},
    {"name": "s3", "host": "127.0.0.1", "port": 6003},
]


def send_key_pqc(host, port, key_hex, timeout=5):
    """Kirim satu baris hex key ke switch_agent lewat openssl s_client
    (PQC-TLS: ML-KEM768 key exchange). Return elapsed detik, atau None
    kalau gagal."""
    cmd = [
        OPENSSL_BIN, "s_client",
        "-connect", f"{host}:{port}",
        "-tls1_3", "-groups", "MLKEM768",
        "-quiet", "-verify_quiet", "-no_ign_eof",
    ]
    t0 = time.time()
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, text=True, env=OPENSSL_ENV)
        proc.stdin.write(key_hex + "\n")
        proc.stdin.flush()
        proc.stdin.close()
        proc.wait(timeout=timeout)
    except Exception as e:
        print(f"    GAGAL kirim ke {host}:{port} -> {e}")
        return None
    return time.time() - t0


def main(rotate_interval):
    print(f"[controller] {OPENSSL_BIN}")
    print(f"[controller] mode PQC-TLS aktif. Pastikan switch_agent.py sudah")
    print(f"             jalan di ketiga switch sebelum lanjut.\n")

    try:
        while True:
            new_key = random.getrandbits(32)
            key_hex = format(new_key, "x")
            print(f"[controller] rotasi mac_key -> {hex(new_key)}  (jam {time.strftime('%H:%M:%S')})")
            for agent in AGENTS:
                elapsed = send_key_pqc(agent["host"], agent["port"], key_hex)
                if elapsed is not None:
                    print(f"  - {agent['name']}: terkirim via PQC-TLS ({elapsed*1000:.2f} ms)")
            time.sleep(rotate_interval)
    except KeyboardInterrupt:
        print("\n[controller] dihentikan oleh user.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=int, default=15, help="detik antar rotasi key (default 15)")
    args = parser.parse_args()
    main(args.interval)