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

MENDUKUNG --algo pqc (default) ATAU --algo classical, buat dapetin data
baseline klasik sbg pembanding. PENTING: --algo di harness ini CUMA
ngatur mode sink_agent.py yang DIA nyalain sendiri. collector.py,
controller.py, dan ketiga switch_agent.py (yang jalan manual di tab
lain) HARUS DIRESTART MANUAL dengan --mode yang SAMA sebelum jalanin
harness ini -- harness TIDAK otomatis ganti mode komponen2 itu.

PRASYARAT sebelum run ini:
  - Mininet sudah `make run` dan jalan
  - collector.py sudah jalan DI DALAM h2 dengan --mode YANG SESUAI
    (manual, di tab lain) -- harness ini TIDAK menyalakan collector.
  - controller.py + ketiga switch_agent.py sudah jalan dengan --mode
    YANG SAMA (manual, tab lain) -- harness TIDAK ikut campur ini.

  Jadi alur buat dapetin data kedua algoritma:
    1. Jalankan semua komponen manual dengan --mode pqc (switch_agent x3,
       controller, collector), lalu: sudo python3 harness.py --algo pqc --reps 50
    2. Ctrl+C semua komponen manual itu, nyalakan ULANG dengan --mode
       classical, lalu: sudo python3 harness.py --algo classical --reps 50
    3. results.csv berisi kedua algoritma, dibedakan kolom "algo".

CATATAN JUJUR: ini kode paling kompleks & paling belum teruji di seluruh
proyek ini (orkestrasi banyak subprocess lintas-namespace). Sangat
mungkin perlu 1-2 putaran perbaikan setelah dicoba beneran -- jangan
kaget, itu arahnya emang gitu.
"""

import argparse
import csv
import os
import subprocess
import threading
import time

import psutil

# SENGAJA path absolut, BUKAN os.path.expanduser("~/..."), karena harness
# ini dijalankan pakai sudo -- "~" buat root itu /root, bukan /home/ubuntu22.
# (Bug yang sama persis sudah kejadian berkali-kali di file lain, lihat
# histori chat.)
MNINET_M = "/home/ubuntu22/mininet/util/m"
BASIC_DIR = "/home/ubuntu22/tutorials/exercises/basic"
P4_INT_PQC_DIR = os.path.join(BASIC_DIR, "p4-int-pqc")
PYTHON_VENV = "/home/ubuntu22/p4dev-python-venv/bin/python3"
NETPROFILE_SH = os.path.join(P4_INT_PQC_DIR, "netprofile.sh")
SINK_AGENT_PY = os.path.join(P4_INT_PQC_DIR, "sink_agent.py")
SEND_TEST_PY = os.path.join(P4_INT_PQC_DIR, "send_int_test.py")

PROFILES = ["ideal", "moderate", "severe"]

# Proses NYATA yang mau dipantau CPU/RAM-nya selagi sistem beneran jalan
# (bukan proses isolated spt measure_bytes.py). simple_switch_grpc
# diikutkan juga biar kebaca beban di sisi P4 switch (walau crypto-nya
# sendiri nggak jalan di situ, switch tetap kerja verifikasi SipHash/CRC
# dan forwarding, jadi tetap relevan dibandingkan).
PROCESS_PATTERNS = {
    "controller": "controller2.py",
    "switch_agent": "switch_agent.py",
    "collector": "collector.py",
    "sink_agent": "sink_agent.py",
    "simple_switch_grpc": "simple_switch_grpc",
}


# Nama proses pembungkus (sudo / m / mnexec / shell) yang cmdline-nya juga
# memuat nama script, tapi BUKAN proses kerja sebenarnya -- dibuang supaya
# satu komponen tidak terhitung 2-3x.
WRAPPER_NAMES = {"sudo", "m", "mnexec", "bash", "sh", "dash", "pgrep"}


def find_pids(patterns):
    result = {name: [] for name in patterns}
    me = os.getpid()
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if p.info["pid"] == me or (p.info["name"] or "") in WRAPPER_NAMES:
                continue
            argv = p.info["cmdline"] or []
            cmd = " ".join(argv)
            exe = os.path.basename(argv[0]) if argv else ""
            for label, pat in patterns.items():
                # Biner switch dicocokkan lewat nama executable-nya (argv[0]),
                # bukan substring, supaya launcher Mininet/run_exercise.py yang
                # cuma menyebut "simple_switch_grpc" di argumennya tidak ikut.
                matched = (exe == pat) if pat == "simple_switch_grpc" else (pat in cmd)
                if matched:
                    result[label].append(p.info["pid"])
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return result


class ResourceMonitor:
    """Thread background yang nyampling CPU% & RSS memory proses-proses
    asli (controller, switch_agent x3, sink_agent, collector, switch P4)
    tiap `interval` detik, SELAMA satu profil jaringan berlangsung."""

    def __init__(self, csv_path, algo_label, profile_label, interval=1.0):
        self.csv_path = csv_path
        self.algo_label = algo_label
        self.profile_label = profile_label
        self.interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._proc_cache = {}

    def _run(self):
        is_new = not os.path.exists(self.csv_path)
        with open(self.csv_path, "a", newline="") as f:
            writer = csv.writer(f)
            if is_new:
                writer.writerow(["timestamp", "algo", "profile", "process", "pid", "cpu_percent", "rss_kb"])
            # Priming call wajib: panggilan pertama cpu_percent() selalu
            # balikin 0.0/nggak akurat, baru akurat dari panggilan kedua.
            pid_map = find_pids(PROCESS_PATTERNS)
            print("[harness] PID terdeteksi (harapan: controller=1, switch_agent=3, collector=1, sink_agent=1, simple_switch_grpc=3): "
                  + ", ".join(f"{k}={len(v)}" for k, v in pid_map.items()), flush=True)
            for name, pids in pid_map.items():
                for pid in pids:
                    try:
                        p = psutil.Process(pid)
                        p.cpu_percent()
                        self._proc_cache[pid] = p
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

            while not self._stop.is_set():
                self._stop.wait(self.interval)
                pid_map = find_pids(PROCESS_PATTERNS)
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                for name, pids in pid_map.items():
                    for pid in pids:
                        try:
                            if pid not in self._proc_cache:
                                self._proc_cache[pid] = psutil.Process(pid)
                                self._proc_cache[pid].cpu_percent()
                                continue  # skip baris ini, priming dulu
                            p = self._proc_cache[pid]
                            cpu = p.cpu_percent()
                            rss_kb = p.memory_info().rss / 1024
                            writer.writerow([ts, self.algo_label, self.profile_label,
                                              name, pid, f"{cpu:.2f}", f"{rss_kb:.1f}"])
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                f.flush()

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)


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
    parser.add_argument("--algo", choices=["pqc", "classical"], default="pqc",
                         help="HARUS sama dgn mode collector.py/controller.py/switch_agent.py yg lagi jalan manual")
    parser.add_argument("--resource-csv", default=os.path.join(BASIC_DIR, "resource_usage.csv"))
    args = parser.parse_args()

    print(f"[harness] output CSV: {args.csv}")
    print(f"[harness] algoritma: {args.algo}")
    print(f"[harness] repetisi per profil: {args.reps}")
    print(f"[harness] PASTIKAN collector/controller/switch_agent manual sudah jalan dgn --mode {args.algo} !\n")
    time.sleep(3)

    for profile in PROFILES:
        print(f"\n{'='*60}")
        print(f"[harness] === PROFIL: {profile} ===")
        print(f"{'='*60}")

        apply_profile(profile)
        time.sleep(1)

        # Perkiraan durasi sink_agent perlu hidup. PENTING: tiap repetisi
        # BUKAN cuma rep_interval -- ada overhead nyata dari spawn proses
        # lewat mnexec + import scapy tiap kali send_int_test.py dipanggil
        # (~1-2 detik ekstra per repetisi), dan di profil jaringan yg
        # buruk, waktu itu bisa lebih lama lagi. Kasih buffer besar &
        # kalikan 2x biar aman, daripada sink_agent exit duluan sebelum
        # semua repetisi selesai terkirim (itu yg kejadian sebelumnya).
        overhead_per_rep = 3.0
        duration = args.reps * (args.rep_interval + overhead_per_rep) * 1.3 + 30

        print(f"[harness] start sink_agent.py (durasi {duration:.0f}s, label={profile})")
        sink_proc = run_in_h2([
            PYTHON_VENV, "-u", SINK_AGENT_PY,
            "--collector-host", "127.0.0.1", "--collector-port", "7001",
            "--mode", args.algo,
            "--csv", args.csv, "--profile-label", profile,
            "--duration", str(duration),
        ], background=True)

        time.sleep(3)  # beri waktu sink_agent mulai sniffing

        print(f"[harness] mulai pantau CPU/RAM proses asli -> {args.resource_csv}")
        monitor = ResourceMonitor(args.resource_csv, args.algo, profile, interval=1.0)
        monitor.start()

        for rep in range(1, args.reps + 1):
            print(f"[harness]   repetisi {rep}/{args.reps}: kirim paket dari h1")
            try:
                run_in_h1([PYTHON_VENV, "-u", SEND_TEST_PY, "10.0.2.2", "1", "0.1"], timeout=10)
            except subprocess.TimeoutExpired:
                print(f"[harness]   [!] repetisi {rep} timeout saat kirim, lanjut saja")
            time.sleep(args.rep_interval)

        print(f"[harness] repetisi selesai, tunggu 5s buffer lalu coba hentikan sink_agent...")
        time.sleep(5)

        monitor.stop()
        print(f"[harness] monitor CPU/RAM dihentikan.")
        sink_proc.terminate()
        try:
            sink_proc.wait(timeout=10)
            print(f"[harness] sink_agent berhenti dgn cepat.")
        except subprocess.TimeoutExpired:
            # terminate() kadang nggak nyampe ke proses asli di dalam
            # namespace h2 (lewat sudo+m, sinyal nggak selalu propagate).
            # Fallback: tunggu durasi otomatisnya habis (lebih lama, tapi
            # pasti berhenti karena sink_agent.py sendiri yg exit).
            print(f"[harness]   terminate() tidak langsung berhasil, menunggu durasi otomatis habis (bisa beberapa menit)...")
            try:
                sink_proc.wait(timeout=duration + 20)
                print(f"[harness] sink_agent akhirnya berhenti sendiri.")
            except subprocess.TimeoutExpired:
                print(f"[harness]   [!] sink_agent tetap tidak keluar -- lanjut paksa ke profil berikutnya, cek manual nanti (kemungkinan proses nyangkut)")

        clear_profile()
        print(f"[harness] profil {profile} selesai.\n")

    print(f"\n[harness] SEMUA PROFIL SELESAI. Hasil ada di: {args.csv}")


if __name__ == "__main__":
    main()