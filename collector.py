#!/usr/bin/env python3

import argparse
import os
import subprocess
import time

OPENSSL = os.path.expanduser("~/openssl35/bin/openssl")
OPENSSL_HOME = os.path.expanduser("~/openssl35")

CERT = os.path.expanduser("~/pqc_collector_cert.pem")
KEY = os.path.expanduser("~/pqc_collector_key.pem")

ENV = os.environ.copy()
ENV["LD_LIBRARY_PATH"] = (
    f"{OPENSSL_HOME}/lib64:"
    f"{OPENSSL_HOME}/lib:"
    f"{ENV.get('LD_LIBRARY_PATH', '')}"
)

def ensure_cert():
    if os.path.exists(CERT) and os.path.exists(KEY):
        return

    print("[collector] generate ML-DSA-65 certificate...")

    subprocess.run(
        [
            OPENSSL,
            "genpkey",
            "-algorithm", "ML-DSA-65",
            "-out", KEY
        ],
        check=True,
        env=ENV
    )

    subprocess.run(
        [
            OPENSSL,
            "req",
            "-x509",
            "-new",
            "-key", KEY,
            "-out", CERT,
            "-days", "3650",
            "-subj", "/CN=telemetry-collector"
        ],
        check=True,
        env=ENV
    )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--listen",
        type=int,
        default=7001
    )
    args = parser.parse_args()

    print(
        subprocess.run(
            [OPENSSL, "version"],
            capture_output=True,
            text=True,
            env=ENV
        ).stdout.strip()
    )

    ensure_cert()

    print(
        f"[collector] siap menerima PQC-TLS "
        f"di port {args.listen}"
    )

    while True:

        cmd = [
            OPENSSL,
            "s_server",
            "-accept", str(args.listen),
            "-cert", CERT,
            "-key", KEY,
            "-tls1_3",
            "-groups", "MLKEM768",
            "-sigalgs", "ML-DSA-65",
            "-naccept", "1",
            "-quiet"
        ]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=ENV
        )

        try:
            line = proc.stdout.readline()

            while line:
                print(
                    f"[collector] REPORT: {line.strip()}",
                    flush=True
                )
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