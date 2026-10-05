#!/usr/bin/env python3
"""
FASE 7: Experiment harness.
- Apply tc/netem ke h2
- Start sink_agent.py
- Kirim N paket dari h1 dalam satu proses
- Tunggu drain/export selesai
- Clear profile
Prasyarat:
- Mininet sudah make run
- collector.py sudah jalan di h2
- controller.py + switch_agent.py sudah jalan
"""

import argparse
import os
import subprocess
import time

MNINET_M = "/home/ubuntu22/mininet/util/m"
BASIC_DIR = "/home/ubuntu22/tutorials/exercises/basic"
P4_INT_PQC_DIR = os.path.join(BASIC_DIR, "p4-int-pqc")
PYTHON_VENV = "/home/ubuntu22/p4dev-python-venv/bin/python3"
NETPROFILE_SH = os.path.join(P4_INT_PQC_DIR, "netprofile.sh")
SINK_AGENT_PY = os.path.join(P4_INT_PQC_DIR, "sink_agent.py")
SEND_TEST_PY = os.path.join(P4_INT_PQC_DIR, "send_int_test.py")
PROFILES = ["ideal", "moderate", "severe"]

def run_in_h2(args_list, background=False, timeout=None):
    cmd = ["sudo", MNINET_M, "h2"] + args_list
    if background:
        return subprocess.Popen(cmd)
    return subprocess.run(cmd, timeout=timeout)

def run_in_h1(args_list, timeout=60):
    cmd = ["sudo", MNINET_M, "h1"] + args_list
    return subprocess.run(cmd, timeout=timeout)

def apply_profile(profile_name):
    print(f"[harness] menerapkan profil: {profile_name}")
    run_in_h2(["bash", NETPROFILE_SH, profile_name], timeout=15)

def clear_profile():
    print("[harness] clear network profile")
    run_in_h2(["bash", NETPROFILE_SH, "clear"], timeout=15)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reps", type=int, default=50, help="jumlah paket per profil")
    parser.add_argument("--csv", default=os.path.join(BASIC_DIR, "results.csv"))
    parser.add_argument("--rep-interval", type=float, default=6.0, help="interval antar paket")
    parser.add_argument("--drain-time", type=float, default=60.0, help="waktu tambahan setelah paket terakhir")
    args = parser.parse_args()

    print(f"[harness] CSV: {args.csv}")
    print(f"[harness] repetitions: {args.reps}")
    print(f"[harness] interval: {args.rep_interval}s")
    print(f"[harness] drain: {args.drain_time}s")

    for profile in PROFILES:
        print(f"\n{'='*60}")
        print(f"[harness] PROFIL: {profile}")
        print(f"{'='*60}")

        apply_profile(profile)
        time.sleep(2)

        send_time = max(0, (args.reps - 1) * args.rep_interval)
        duration = send_time + args.drain_time + 30

        print(f"[harness] start sink_agent ({duration:.0f}s)")
        sink_proc = run_in_h2([
            PYTHON_VENV, "-u", SINK_AGENT_PY,
            "--collector-host", "127.0.0.1",
            "--collector-port", "7001",
            "--csv", args.csv,
            "--profile-label", profile,
            "--duration", str(duration)
        ], background=True)

        time.sleep(5)

        print(f"[harness] mengirim {args.reps} paket dari h1...")
        try:
            run_in_h1([
                PYTHON_VENV, "-u", SEND_TEST_PY,
                "10.0.2.2", str(args.reps), str(args.rep_interval)
            ], timeout=send_time + args.drain_time + 30)
        except subprocess.TimeoutExpired:
            print("[harness] [!] sender timeout")

        print(f"[harness] drain {args.drain_time:.0f}s...")
        time.sleep(args.drain_time)

        print("[harness] menunggu sink_agent selesai...")
        try:
            sink_proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            print("[harness] [!] sink_agent belum berhenti, terminate...")
            sink_proc.terminate()
            try:
                sink_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sink_proc.kill()

        clear_profile()
        print(f"[harness] profil {profile} selesai.")

    print(f"\n[harness] SEMUA PROFIL SELESAI")
    print(f"[harness] hasil: {args.csv}")

if __name__ == "__main__":
    main()