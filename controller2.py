#!/usr/bin/env python3
"""
FASE 5 (+ baseline klasik): Controller -- kirim kunci lewat TLS ke
switch_agent.py di tiap switch (BUKAN langsung P4Runtime -- itu tugas
switch_agent.py).

Mendukung --mode pqc (default, ML-KEM768) atau --mode classical (X25519).
HARUS sama persis dengan --mode yang dipakai ketiga switch_agent.py.
"""

import argparse
import hashlib
import os
import secrets
import subprocess
import time

OPENSSL_HOME = "/home/ubuntu22/openssl35"
OPENSSL_BIN = os.path.join(OPENSSL_HOME, "bin", "openssl")
OPENSSL_ENV = os.environ.copy()
OPENSSL_ENV["LD_LIBRARY_PATH"] = (
    os.path.join(OPENSSL_HOME, "lib64") + ":" +
    os.path.join(OPENSSL_HOME, "lib") + ":" +
    OPENSSL_ENV.get("LD_LIBRARY_PATH", "")
)

GROUPS_BY_MODE = {"pqc": "MLKEM768", "classical": "X25519"}

AGENTS = [
    {"name": "s1", "host": "127.0.0.1", "port": 6001},
    {"name": "s2", "host": "127.0.0.1", "port": 6002},
    {"name": "s3", "host": "127.0.0.1", "port": 6003},
]


def send_key(host, port, key_hex, groups, timeout=5):
    cmd = [
        OPENSSL_BIN, "s_client",
        "-connect", f"{host}:{port}",
        "-tls1_3", "-groups", groups,
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


def main(rotate_interval, mode, log_path=None, count=0):
    groups = GROUPS_BY_MODE[mode]
    print(f"[controller] mode={mode} (groups={groups}). Pastikan switch_agent.py")
    print(f"             sudah jalan di ketiga switch dgn --mode {mode} juga.\n")

    done = 0
    try:
        while True:
            if count and done >= count:
                break
            new_key = secrets.randbits(128)   # kunci SipHash 128-bit, dari CSPRNG (bukan random.*)
            key_hex = format(new_key, "x")
            if log_path:
                fp = hashlib.sha256(key_hex.encode()).hexdigest()[:8]
                with open(log_path, "a") as lf:
                    lf.write(f"{time.time():.6f},{fp}\n")   # awal rotasi
            print(f"[controller] rotasi mac_key -> {hex(new_key)[:10]}... (128-bit)  (jam {time.strftime('%H:%M:%S')})")
            for agent in AGENTS:
                elapsed = send_key(agent["host"], agent["port"], key_hex, groups)
                if elapsed is not None:
                    print(f"  - {agent['name']}: terkirim via {mode} ({elapsed*1000:.2f} ms)")
            done += 1
            if count and done >= count:
                break
            time.sleep(rotate_interval)
    except KeyboardInterrupt:
        print("\n[controller] dihentikan oleh user.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=int, default=15)
    parser.add_argument("--log", default=None, help="(opsional) CSV awal tiap rotasi: epoch,fingerprint")
    parser.add_argument("--count", type=int, default=0, help="berhenti setelah N rotasi (0 = terus)")
    parser.add_argument("--mode", choices=["pqc", "classical"], default="pqc")
    args = parser.parse_args()
    main(args.interval, args.mode, args.log, args.count)