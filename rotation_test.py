#!/usr/bin/env python3
"""
FASE 9: Ukur paket hilang SAAT ROTASI KUNCI SipHash.

Latar: controller2.py mengirim kunci baru ke s1, s2, s3 SATU PER SATU (lewat
PQC-TLS). Selama jendela itu kunci tiap switch tidak seragam, sehingga MAC
yang dibuat hop N tidak lolos verifikasi hop N+1 -> paket di-drop. Skrip ini
mengukur berapa paket hilang per rotasi dan seberapa lebar jendelanya.

Alur `run` (jalankan dgn sudo, dari host, BUKAN dari dalam Mininet CLI):
  1. receiver di h2  : catat (seq, waktu terima) tiap paket uji
  2. sender di h1    : kirim paket bernomor urut pada laju tetap (--rate)
  3. controller2.py  : rotasi kunci --rotations kali tiap --interval detik
  4. analisis        : cocokkan paket hilang dgn jendela rotasi
                       (waktu terpasang kunci di s1/s2/s3 dari --apply-log)

PRASYARAT (manual, tab lain):
  - Mininet jalan (make run) dgn int_source/siphash.p4 yg sudah ter-compile
  - switch_agent.py x3 jalan dgn --mode <sama> DAN
        --apply-log /tmp/rot_apply.csv
  - collector.py TIDAK perlu.
  - controller2.py JANGAN dijalankan manual (skrip ini yg menyalakan).

Contoh:
  sudo /home/ubuntu22/p4dev-python-venv/bin/python3 rotation_test.py run \
       --mode pqc --rate 200 --rotations 20 --interval 8 --tag pqc

Sub-perintah internal (dipanggil otomatis, tidak perlu manual): send, recv.
"""

import argparse
import csv
import os
import socket
import statistics
import struct
import subprocess
import sys
import time

MNINET_M = "/home/ubuntu22/mininet/util/m"
PYTHON_VENV = "/home/ubuntu22/p4dev-python-venv/bin/python3"
HERE = os.path.dirname(os.path.abspath(__file__))
SELF = os.path.abspath(__file__)

MAGIC = b"ROTTEST1"          # 8 byte, penanda payload uji
PAYLOAD_FMT = "!8sId"        # magic, seq (uint32), t_send (double)
PAYLOAD_LEN = struct.calcsize(PAYLOAD_FMT)
DST_IP = "10.0.2.2"
SRC_IP = "10.0.1.1"


# ----------------------------------------------------------------- util frame
def pick_iface(forced=None):
    if forced:
        return forced
    names = sorted(n for n in os.listdir("/sys/class/net") if n != "lo")
    for n in names:
        if "eth0" in n:
            return n
    return names[0]


def ip_checksum(hdr: bytes) -> int:
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_frame(src_mac: bytes, seq: int, t_send: float) -> bytes:
    payload = struct.pack(PAYLOAD_FMT, MAGIC, seq, t_send)
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", 12345, 54321, udp_len, 0) + payload   # checksum 0 = sah utk IPv4
    total = 20 + len(udp)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, seq & 0xFFFF, 0, 64, 17, 0,
                      socket.inet_aton(SRC_IP), socket.inet_aton(DST_IP))
    iph = iph[:10] + struct.pack("!H", ip_checksum(iph)) + iph[12:]
    eth = b"\xff" * 6 + src_mac + b"\x08\x00"
    return eth + iph + udp


def parse_seq(frame: bytes):
    """Return (seq, has_int) atau None kalau bukan paket uji."""
    if len(frame) < 14:
        return None
    etype = struct.unpack("!H", frame[12:14])[0]
    if etype == 0x1212:                       # ada section INT: shim.len (word 4-byte) di byte ke-2 shim
        if len(frame) < 18:
            return None
        ip_off = 14 + frame[16] * 4
        has_int = True
    elif etype == 0x0800:
        ip_off = 14
        has_int = False
    else:
        return None
    if len(frame) < ip_off + 20:
        return None
    ihl = (frame[ip_off] & 0x0F) * 4
    pay = ip_off + ihl + 8
    if len(frame) < pay + PAYLOAD_LEN:
        return None
    magic, seq, _ = struct.unpack(PAYLOAD_FMT, frame[pay:pay + PAYLOAD_LEN])
    if magic != MAGIC:
        return None
    return seq, has_int


# ----------------------------------------------------------------- sender/receiver
def cmd_send(a):
    iface = pick_iface(a.iface)
    mac = bytes.fromhex(open(f"/sys/class/net/{iface}/address").read().strip().replace(":", ""))
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((iface, 0))
    n = int(a.duration * a.rate)
    step = 1.0 / a.rate
    rows = []
    t0 = time.perf_counter()
    for seq in range(n):
        target = t0 + seq * step
        while True:
            dt = target - time.perf_counter()
            if dt <= 0:
                break
            if dt > 0.002:
                time.sleep(dt - 0.001)
        ts = time.time()
        sock.send(build_frame(mac, seq, ts))
        rows.append((seq, f"{ts:.6f}"))
    with open(a.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["seq", "t_send"])
        w.writerows(rows)
    print(f"[send] {n} paket terkirim lewat {iface} @ {a.rate} pps -> {a.out}", flush=True)


def cmd_recv(a):
    iface = pick_iface(a.iface)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((iface, 0))
    sock.settimeout(0.2)
    end = time.time() + a.duration
    rows = []
    while time.time() < end:
        try:
            data, sa = sock.recvfrom(65535)
        except socket.timeout:
            continue
        if sa[2] == socket.PACKET_OUTGOING:      # abaikan salinan keluar (penting kalau uji di lo)
            continue
        r = parse_seq(data)
        if r:
            rows.append((r[0], f"{time.time():.6f}", int(r[1])))
    with open(a.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["seq", "t_recv", "has_int"])
        w.writerows(rows)
    print(f"[recv] {len(rows)} paket uji diterima di {iface} -> {a.out}", flush=True)


# ----------------------------------------------------------------- analisis
def read_csv(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def analyze(tx_path, rx_path, apply_path, ctrl_path, tol, out_csv, rate, label):
    tx = {int(r["seq"]): float(r["t_send"]) for r in read_csv(tx_path)}
    rx_rows = read_csv(rx_path)
    rx = {}
    dup = 0
    for r in rx_rows:
        s = int(r["seq"])
        if s in rx:
            dup += 1
        rx[s] = float(r["t_recv"])
    lost = sorted(s for s in tx if s not in rx)
    lost_t = {s: tx[s] for s in lost}
    no_int = sum(1 for r in rx_rows if r["has_int"] == "0")

    # jendela tiap rotasi: dari apply tercepat sampai apply terlama di antara switch
    applies = {}
    for line in open(apply_path):
        parts = line.strip().split(",")
        if len(parts) == 3:
            t, sw, fp = float(parts[0]), parts[1], parts[2]
            applies.setdefault(fp, {})[sw] = t
    ctrl_start = {}
    for line in open(ctrl_path):
        parts = line.strip().split(",")
        if len(parts) == 2:
            ctrl_start[parts[1]] = float(parts[0])

    rotations = []
    for fp, t0 in sorted(ctrl_start.items(), key=lambda kv: kv[1]):
        sw = applies.get(fp, {})
        if len(sw) < 3:
            rotations.append(dict(fp=fp, complete=False, t0=t0))
            continue
        wa, wb = min(sw.values()), max(sw.values())
        rotations.append(dict(
            fp=fp, complete=True, t0=t0, wa=wa, wb=wb,
            window_ms=(wb - wa) * 1000,
            ctrl_to_first_ms=(wa - t0) * 1000,
            s1_s2_ms=(sw["s2"] - sw["s1"]) * 1000 if "s1" in sw and "s2" in sw else float("nan"),
            s2_s3_ms=(sw["s3"] - sw["s2"]) * 1000 if "s2" in sw and "s3" in sw else float("nan"),
        ))

    assigned = set()
    for r in rotations:
        if not r["complete"]:
            r["lost"] = None
            continue
        lo, hi = r["wa"] - tol, r["wb"] + tol
        mine = [s for s, t in lost_t.items() if lo <= t <= hi]
        r["lost"] = len(mine)
        r["expected"] = rate * (r["wb"] - r["wa"])
        assigned.update(mine)
    outside = [s for s in lost if s not in assigned]

    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["label", "key_fp", "complete", "window_ms", "ctrl_to_first_apply_ms", "s1_to_s2_ms",
                    "s2_to_s3_ms", "lost_packets", "expected_by_window"])
        for r in rotations:
            if r["complete"]:
                w.writerow([label, r["fp"], 1, f"{r['window_ms']:.2f}", f"{r['ctrl_to_first_ms']:.2f}",
                            f"{r['s1_s2_ms']:.2f}", f"{r['s2_s3_ms']:.2f}", r["lost"], f"{r['expected']:.1f}"])
            else:
                w.writerow([label, r["fp"], 0, "", "", "", "", "", ""])

    comp = [r for r in rotations if r["complete"]]
    print("\n================= HASIL ROTASI KUNCI =================")
    print(f"label                : {label}")
    print(f"paket terkirim       : {len(tx)}  (laju {rate} pps)")
    print(f"paket diterima unik  : {len(rx)}  (duplikat {dup}, tanpa INT {no_int})")
    print(f"paket hilang total   : {len(lost)}")
    print(f"  di dalam jendela   : {len(assigned)}")
    print(f"  di luar jendela    : {len(outside)}   <- harusnya ~0 kalau tidak ada sebab lain")
    print(f"rotasi lengkap       : {len(comp)} dari {len(rotations)}")
    if comp:
        wins = [r["window_ms"] for r in comp]
        losts = [r["lost"] for r in comp]
        print(f"jendela rotasi (ms)  : median {statistics.median(wins):.1f}  mean {statistics.mean(wins):.1f}  "
              f"min {min(wins):.1f}  max {max(wins):.1f}")
        print(f"paket hilang/rotasi  : median {statistics.median(losts):.1f}  mean {statistics.mean(losts):.2f}  "
              f"min {min(losts)}  max {max(losts)}")
        print(f"selisih s1->s2 (ms)  : median {statistics.median(r['s1_s2_ms'] for r in comp):.1f}")
        print(f"selisih s2->s3 (ms)  : median {statistics.median(r['s2_s3_ms'] for r in comp):.1f}")
        print(f"CSV per-rotasi       : {out_csv}")
    print("=======================================================\n")


# ----------------------------------------------------------------- orkestrasi
def m_cmd(host, args_list):
    return ["sudo", MNINET_M, host] + args_list


def cmd_run(a):
    tag = a.tag or a.mode
    tx = f"/tmp/rot_tx_{tag}.csv"
    rx = f"/tmp/rot_rx_{tag}.csv"
    ctrl_log = "/tmp/rot_ctrl.csv"
    for p in (ctrl_log, a.apply_log):
        if os.path.exists(p):
            os.remove(p)

    warmup, cooldown = 4.0, 6.0
    ctrl_time = a.rotations * a.interval
    duration = warmup + ctrl_time + cooldown

    print(f"[run] mode={a.mode} rate={a.rate}pps rotasi={a.rotations} interval={a.interval}s "
          f"durasi~{duration:.0f}s tag={tag}")
    print(f"[run] pastikan switch_agent x3 jalan dgn --mode {a.mode} --apply-log {a.apply_log}\n", flush=True)

    recv = subprocess.Popen(m_cmd("h2", [PYTHON_VENV, "-u", SELF, "recv", "--duration", str(duration + 4),
                                          "--out", rx]))
    time.sleep(2)
    send = subprocess.Popen(m_cmd("h1", [PYTHON_VENV, "-u", SELF, "send", "--rate", str(a.rate),
                                          "--duration", str(duration), "--out", tx]))
    time.sleep(warmup)
    print("[run] mulai rotasi kunci...", flush=True)
    ctrl = subprocess.run([PYTHON_VENV, "-u", os.path.join(HERE, "controller2.py"), "--mode", a.mode,
                           "--interval", str(a.interval), "--count", str(a.rotations), "--log", ctrl_log])
    if ctrl.returncode != 0:
        print(f"[run] controller2.py keluar dgn kode {ctrl.returncode} -- cek pesan di atas")
    print("[run] rotasi selesai, tunggu sender/receiver...", flush=True)
    send.wait()
    recv.wait()
    time.sleep(0.5)

    out_csv = os.path.join(a.out_dir, f"rotation_{tag}.csv")
    analyze(tx, rx, a.apply_log, ctrl_log, a.tol, out_csv, a.rate, tag)


def cmd_analyze(a):
    tag = a.tag or a.mode
    analyze(f"/tmp/rot_tx_{tag}.csv", f"/tmp/rot_rx_{tag}.csv", a.apply_log, "/tmp/rot_ctrl.csv",
            a.tol, os.path.join(a.out_dir, f"rotation_{tag}.csv"), a.rate, tag)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("send")
    s.add_argument("--rate", type=float, default=200)
    s.add_argument("--duration", type=float, required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--iface", default=None)

    r = sub.add_parser("recv")
    r.add_argument("--duration", type=float, required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--iface", default=None)

    for name in ("run", "analyze"):
        p = sub.add_parser(name)
        p.add_argument("--mode", choices=["pqc", "classical"], default="pqc")
        p.add_argument("--rate", type=float, default=200, help="paket/detik dari h1")
        p.add_argument("--rotations", type=int, default=20)
        p.add_argument("--interval", type=int, default=8, help="detik antar rotasi")
        p.add_argument("--tol", type=float, default=0.05,
                       help="toleransi (detik) sebelum/sesudah jendela utk paket yg masih in-flight")
        p.add_argument("--apply-log", default="/tmp/rot_apply.csv")
        p.add_argument("--tag", default=None, help="label output (default = mode)")
        p.add_argument("--out-dir", default=HERE)

    a = ap.parse_args()
    {"send": cmd_send, "recv": cmd_recv, "run": cmd_run, "analyze": cmd_analyze}[a.cmd](a)


if __name__ == "__main__":
    main()