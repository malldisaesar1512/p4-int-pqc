#!/usr/bin/env python3
"""
FASE 5: Controller -- sekarang kirim kunci lewat PQC-TLS, BUKAN langsung
P4Runtime lagi (itu udah pindah tugasnya ke switch_agent.py yang jalan di
tiap switch).

Alurnya sekarang:
  controller.py --(generate kunci baru)--> openssl s_client (PQC-TLS,
  ML-KEM768 + ML-DSA65) --> switch_agent.py (tiap switch) --> P4Runtime
  lokal switch itu sendiri.

Controller TIDAK PERNAH lagi nyentuh P4Runtime langsung -- itu correct
by design, karena yang mau diukur/diamankan adalah kanal DISTRIBUSI
kunci-nya, bukan instalasinya ke switch (itu tetap lokal & trusted).

Jalankan SETELAH ketiga switch_agent.py (s1, s2, s3) sudah jalan dan
dengerin di port masing-masing.
"""

import argparse
import random
import subprocess
import sys
import time

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
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-tls1_3", "-groups", "MLKEM768",
        "-quiet", "-verify_quiet", "-no_ign_eof",
    ]
    t0 = time.time()
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, text=True)
        proc.stdin.write(key_hex + "\n")
        proc.stdin.flush()
        proc.stdin.close()
        proc.wait(timeout=timeout)
    except Exception as e:
        print(f"    GAGAL kirim ke {host}:{port} -> {e}")
        return None
    return time.time() - t0


def main(rotate_interval):
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