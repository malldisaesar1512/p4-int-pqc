#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import time

OPENSSL_HOME = "/home/ubuntu22/openssl35"
OPENSSL = f"{OPENSSL_HOME}/bin/openssl"

CERT = "/home/ubuntu22/pqc_collector_cert.pem"

ENV = os.environ.copy()
ENV["LD_LIBRARY_PATH"] = (
    f"{OPENSSL_HOME}/lib64:"
    f"{OPENSSL_HOME}/lib:"
    f"{ENV.get('LD_LIBRARY_PATH', '')}"
)

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--host",
        default="127.0.0.1"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=7001
    )

    args = parser.parse_args()

    report = {
        "type": "INT_REPORT",
        "timestamp": time.time(),
        "switches": [
            {
                "switch_id": 1,
                "queue_depth": 12,
                "ingress_timestamp": 123456,
                "mac": "0xdeadbeef"
            },
            {
                "switch_id": 2,
                "queue_depth": 8,
                "ingress_timestamp": 234567,
                "mac": "0xdeadbeef"
            },
            {
                "switch_id": 3,
                "queue_depth": 5,
                "ingress_timestamp": 345678,
                "mac": "0xdeadbeef"
            }
        ]
    }

    message = json.dumps(report)

    cmd = [
        OPENSSL,
        "s_client",
        "-connect", f"{args.host}:{args.port}",
        "-tls1_3",
        "-groups", "MLKEM768",
        "-sigalgs", "ML-DSA-65",
        "-CAfile", CERT,
        "-quiet",
        "-no_ign_eof"
    ]

    print("[export_test] kirim report via PQC-TLS...")

    t0 = time.perf_counter()

    result = subprocess.run(
        cmd,
        input=message + "\n",
        capture_output=True,
        text=True,
        env=ENV,
        timeout=10
    )

    elapsed = (
        time.perf_counter() - t0
    )

    if result.returncode != 0:

        print(
            "[export_test] GAGAL\n"
            + result.stderr
        )

        return

    print(
        f"[export_test] berhasil "
        f"({elapsed * 1000:.2f} ms)"
    )

if __name__ == "__main__":
    main()