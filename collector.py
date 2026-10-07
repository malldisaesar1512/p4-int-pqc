#!/usr/bin/env python3
"""
Telemetry Collector -- nerima laporan dari sink_agent.py lewat TLS
(PQC atau klasik, tergantung --mode).

HARUS pakai --mode yang SAMA dengan sink_agent.py yang ngirim ke sini.
"""

import argparse
import os
import subprocess
import time

OPENSSL_HOME = "/home/ubuntu22/openssl35"
OPENSSL_BIN = os.path.join(OPENSSL_HOME, "bin", "openssl")
OPENSSL_ENV = os.environ.copy()
OPENSSL_ENV["LD_LIBRARY_PATH"] = (
    f"{OPENSSL_HOME}/lib64:" f"{OPENSSL_HOME}/lib:" f"{OPENSSL_ENV.get('LD_LIBRARY_PATH', '')}"
)

MODE_CONFIG = {
    "pqc": {
        "groups": "MLKEM768",
        "sig_algo": "ML-DSA-65",
        "cert": "/home/ubuntu22/pqc_collector_cert.pem",
        "key": "/home/ubuntu22/pqc_collector_key.pem",
    },
    "classical": {
        "groups": "X25519",
        "sig_algo": "EC",
        "ec_curve": "prime256v1",
        "cert": "/home/ubuntu22/classical_collector_cert.pem",
        "key": "/home/ubuntu22/classical_collector_key.pem",
    },
}


def ensure_cert(cfg):
    if os.path.exists(cfg["cert"]) and os.path.exists(cfg["key"]):
        return
    print(f"[collector] generate cert {cfg['sig_algo']}...")
    if cfg["sig_algo"] == "EC":
        subprocess.run([OPENSSL_BIN, "ecparam", "-genkey", "-name", cfg["ec_curve"], "-out", cfg["key"]],
                        check=True, env=OPENSSL_ENV)
    else:
        subprocess.run([OPENSSL_BIN, "genpkey", "-algorithm", cfg["sig_algo"], "-out", cfg["key"]],
                        check=True, env=OPENSSL_ENV)
    subprocess.run([OPENSSL_BIN, "req", "-x509", "-new", "-key", cfg["key"], "-out", cfg["cert"],
                     "-days", "3650", "-subj", "/CN=telemetry-collector"], check=True, env=OPENSSL_ENV)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=int, default=7001)
    parser.add_argument("--mode", choices=["pqc", "classical"], default="pqc")
    args = parser.parse_args()
    cfg = MODE_CONFIG[args.mode]

    print(subprocess.run([OPENSSL_BIN, "version"], capture_output=True, text=True, env=OPENSSL_ENV).stdout.strip())

    ensure_cert(cfg)

    print(f"[collector] siap menerima mode={args.mode} (groups={cfg['groups']}) di port {args.listen}")

    while True:
        cmd = [
            OPENSSL_BIN, "s_server",
            "-accept", str(args.listen),
            "-cert", cfg["cert"], "-key", cfg["key"],
            "-tls1_3", "-groups", cfg["groups"],
            "-naccept", "1",
            "-quiet",
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, env=OPENSSL_ENV)
        try:
            line = proc.stdout.readline()
            while line:
                print(f"[collector] REPORT: {line.strip()}", flush=True)
                line = proc.stdout.readline()
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
        time.sleep(0.1)


if __name__ == "__main__":
    main()