#!/usr/bin/env python3
"""
FASE 7: Experiment harness -- satu alur kerja otomatis.

Untuk setiap profil jaringan (ideal, moderate, severe):
  1. Terapkan tc/netem ke interface lo milik h2 (via netprofile.sh)
  2. Nyalakan sink_agent.py (di dalam h2) dengan --csv & --profile-label,
     plus --duration supaya dia keluar sendiri (bukan di-kill paksa dari
     luar namespace -- itu rawan proses nyangkut, lihat histori chat)
  3. Kirim paket test dari h1 sebanyak --reps kali (default kecil dulu,
     naikkan ke 30 setelah terbukti jalan bersih)
  4. Tunggu sink_agent keluar sendiri (durasi abis)
  5. Bersihkan profil jaringan, lanjut ke profil berikutnya

PRASYARAT sebelum run ini:
  - Mininet sudah `make run` dan jalan
  - collector.py sudah jalan duluan DI DALAM h2 (manual, di tab lain) --
    harness ini TIDAK menyalakan collector, karena collector dimaksudkan
    tetap hidup across semua profil (merepresentasikan server yang selalu
    on), beda dari sink_agent yang di-restart tiap ganti profil.
  - controller.py + ketiga switch_agent.py sudah jalan (manual, tab lain)
    -- harness ini TIDAK ikut campur urusan rotasi mac_key.

CATATAN JUJUR: ini kode paling kompleks & paling belum teruji di seluruh
proyek ini (orkestrasi banyak subprocess lintas-namespace). Sangat
mungkin perlu 1-2 putaran perbaikan setelah dicoba beneran -- jangan
kaget, itu arahnya emang gitu.
"""

import argparse
import os
import subprocess
import time

MNINET_M = os.path.expanduser("~/mininet/util/m")
BASIC_DIR = os.path.expanduser("~/tutorials/exercises/basic")
P4_INT_PQC_DIR = os.path.join(BASIC_DIR, "p4-int-pqc")
PYTHON_VENV = os.path.expanduser("~/p4dev-python-venv/bin/python3")
NETPROFILE_SH = os.path.join(P4_INT_PQC_DIR, "netprofile.sh")
SINK_AGENT_PY = os.path.join(P4_INT_PQC_DIR, "sink_agent.py")
SEND_TEST_PY = os.path.join(P4_INT_PQC_DIR, "send_int_test.py")

PROFILES = ["ideal", "moderate", "severe"]


def run_in_h2(args_list, background=False, timeout=None):
    """Jalankan command di namespace h2 lewat `m`. background=True utk
    proses yang sengaja dibiarkan jalan lama (sink_agent)."""
    cmd = ["sudo", MNINET_M, "h2"] + args_list
    if background:
        return subprocess.Popen(cmd)
    return subprocess.run(cmd, timeout=timeout)


def run_in_h1(args_list, timeout=60):
    cmd = ["sudo", MNINET_M, "h1"] + args_list
    return subprocess.run(cmd, timeout=timeout)


def apply_profile(profile_name):
    print(f"[harness] menerapkan profil jaringan: {profile_name}")
    run_in_h2(["bash", NETPROFILE_SH, profile_name], timeout=15)


def clear_profile():
    run_in_h2(["bash", NETPROFILE_SH, "clear"], timeout=15)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reps", type=int, default=5,
                         help="jumlah repetisi per profil (default 5 utk validasi dulu; naikkan ke 30 utk data final)")
    parser.add_argument("--csv", default=os.path.join(BASIC_DIR, "results.csv"))
    parser.add_argument("--rep-interval", type=float, default=2.0,
                         help="jeda detik antar repetisi, beri waktu export tiap siklus")
    args = parser.parse_args()

    print(f"[harness] output CSV: {args.csv}")
    print(f"[harness] repetisi per profil: {args.reps}\n")

    for profile in PROFILES:
        print(f"\n{'='*60}")
        print(f"[harness] === PROFIL: {profile} ===")
        print(f"{'='*60}")

        apply_profile(profile)
        time.sleep(1)

        # Perkiraan durasi sink_agent perlu hidup: tiap repetisi ~rep_interval
        # detik, ditambah buffer start-up & buffer akhir.
        duration = args.reps * args.rep_interval + 15

        print(f"[harness] start sink_agent.py (durasi {duration:.0f}s, label={profile})")
        sink_proc = run_in_h2([
            PYTHON_VENV, "-u", SINK_AGENT_PY,
            "--collector-host", "127.0.0.1", "--collector-port", "7001",
            "--csv", args.csv, "--profile-label", profile,
            "--duration", str(duration),
        ], background=True)

        time.sleep(3)  # beri waktu sink_agent mulai sniffing

        for rep in range(1, args.reps + 1):
            print(f"[harness]   repetisi {rep}/{args.reps}: kirim paket dari h1")
            try:
                run_in_h1([PYTHON_VENV, "-u", SEND_TEST_PY, "10.0.2.2", "1", "0.1"], timeout=10)
            except subprocess.TimeoutExpired:
                print(f"[harness]   [!] repetisi {rep} timeout saat kirim, lanjut saja")
            time.sleep(args.rep_interval)

        print(f"[harness] menunggu sink_agent.py selesai (durasi habis)...")
        try:
            sink_proc.wait(timeout=duration + 20)
        except subprocess.TimeoutExpired:
            print(f"[harness]   [!] sink_agent tidak keluar sendiri, kemungkinan macet -- cek manual nanti")
            sink_proc.terminate()

        clear_profile()
        print(f"[harness] profil {profile} selesai.\n")

    print(f"\n[harness] SEMUA PROFIL SELESAI. Hasil ada di: {args.csv}")


if __name__ == "__main__":
    main()