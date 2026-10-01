#!/usr/bin/env python3
"""
Sink Agent - dashboard terminal live.
Jalankan TERUS-MENERUS di h2: `h2 python3 -u sink_agent.py`
(beda dari receive_int_test.py yang sekali print per paket, ini ngumpulin
statistik berjalan dan nampilin dashboard yang di-refresh tiap 1 detik.)

METRIK YANG DITAMPILKAN & KENAPA:
- Queue depth per switch, jumlah paket per switch, throughput per switch:
  semuanya dihitung dari data INT (metadata per-hop), ini valid karena
  masing-masing angka itu murni pengukuran LOKAL di switch tsb, tidak
  butuh perbandingan jam antar-proses.
- Latency end-to-end (h1 -> h2): dihitung dari SATU jam saja (wall-clock
  h2, dibandingkan dengan waktu kirim yang ditempel h1 di payload paket).
  INI SENGAJA TIDAK memakai selisih `ingress_timestamp` antar switch dari
  BMv2, karena `standard_metadata.egress_global_timestamp` dihitung sejak
  proses simple_switch itu sendiri nyala -- BUKAN jam yang disinkronkan
  antar switch. Menghitung "latency antar-hop" dari situ akan menghasilkan
  angka yang salah total (bisa ratusan ms, padahal jaringan ini virtual
  dalam satu VM yang sama).
"""

import time
import struct
import threading
import json
import os
import subprocess
from collections import deque, defaultdict
from scapy.all import Packet, bind_layers, ByteField, ShortField, IntField, Ether, IP, AsyncSniffer

TYPE_INT = 0x1212
ROLLING_WINDOW = 20  # jumlah sampel terakhir dipakai utk rolling avg & throughput


class INTShim(Packet):
    name = "INTShim"
    fields_desc = [ByteField("int_type", 1), ByteField("rsvd", 0), ByteField("len", 0), ByteField("dscp", 0)]

class INTHeader(Packet):
    name = "INTHeader"
    fields_desc = [ByteField("ver_flags", 0), ByteField("ins_cnt", 3), ByteField("max_hop_cnt", 8),
                   ByteField("total_hop_cnt", 0), ShortField("instruction_mask", 0), ShortField("rsvd", 0)]

class INTMetadata(Packet):
    name = "INTMetadata"
    fields_desc = [IntField("switch_id", 0), IntField("ingress_timestamp", 0),
                   IntField("queue_depth", 0), IntField("mac", 0)]

bind_layers(Ether, INTShim, type=TYPE_INT)
bind_layers(INTShim, INTHeader)

lock = threading.Lock()
stats = defaultdict(lambda: {
    "count": 0,
    "queue_depths": deque(maxlen=ROLLING_WINDOW),
    "recent_times": deque(maxlen=ROLLING_WINDOW),
})
e2e_latencies_ms = deque(maxlen=ROLLING_WINDOW)
total_packets = 0

META_ENTRY_SIZE = 16  # byte per entri (switch_id + ts + queue_depth + mac, masing2 4 byte)

# ============================================================
# PQC EXPORT CONFIG
# ============================================================

OPENSSL_HOME = "/home/ubuntu22/openssl35"
OPENSSL_BIN = f"{OPENSSL_HOME}/bin/openssl"

COLLECTOR_HOST = "127.0.0.1"
COLLECTOR_PORT = 7001

COLLECTOR_CERT = "/home/ubuntu22/pqc_collector_cert.pem"

EXPORT_INTERVAL = 1.0

OPENSSL_ENV = os.environ.copy()
OPENSSL_ENV["LD_LIBRARY_PATH"] = (
    f"{OPENSSL_HOME}/lib64:"
    f"{OPENSSL_HOME}/lib:"
    f"{OPENSSL_ENV.get('LD_LIBRARY_PATH', '')}"
)

export_stop = threading.Event()


def parse_int_metadata_stack(hdr):
    """Kembalikan (list_hop, sisa_bytes_setelah_stack). Dipakai di satu
    tempat saja (handle_packet) supaya ukuran entri (16 byte) tidak
    terduplikasi jadi dua sumber kebenaran yang bisa saling berbeda."""
    raw = bytes(hdr.payload)
    n = hdr.total_hop_cnt
    hops = []
    off = 0
    for _ in range(n):
        chunk = raw[off:off + META_ENTRY_SIZE]
        if len(chunk) < META_ENTRY_SIZE:
            break
        hops.append(INTMetadata(chunk))
        off += META_ENTRY_SIZE
    return hops, raw[off:]


def handle_packet(pkt):
    global total_packets
    if not pkt.haslayer(INTShim):
        return
    hdr = pkt.getlayer(INTHeader)
    if hdr is None:
        return

    hops, ip_bytes = parse_int_metadata_stack(hdr)
    now = time.time()

    with lock:
        total_packets += 1
        for m in hops:
            s = stats[m.switch_id]
            s["count"] += 1
            s["queue_depths"].append(m.queue_depth)
            s["recent_times"].append(now)

    # PENTING: ip_bytes (sisa raw setelah metadata stack) adalah paket IP
    # asli. scapy TIDAK otomatis mem-parsing ini sbg layer IP (kita tidak
    # bind_layers dari INTHeader ke IP -- jumlah metadata dinamis, tidak
    # bisa dipetakan statis). pkt.getlayer(IP) akan selalu None di sini.
    if len(ip_bytes) >= 20:
        try:
            ip_pkt = IP(ip_bytes)
            raw_payload = bytes(ip_pkt.payload)  # UDP header (8B) + data
            if len(raw_payload) >= 8:
                sent_ts = struct.unpack("!d", raw_payload[-8:])[0]
                latency_ms = (now - sent_ts) * 1000
                if 0 <= latency_ms < 60_000:
                    with lock:
                        e2e_latencies_ms.append(latency_ms)
        except Exception:
            pass


def throughput_pps(switch_id):
    times = stats[switch_id]["recent_times"]
    if len(times) < 2:
        return 0.0
    span = times[-1] - times[0]
    return (len(times) - 1) / span if span > 0 else 0.0

def build_int_report():
    """
    Membuat snapshot statistik INT untuk dikirim ke Collector.
    """

    now = time.time()

    with lock:
        report = {
            "type": "INT_REPORT",
            "timestamp": now,
            "total_packets": total_packets,
            "switches": {},
        }

        for sw_id, value in stats.items():

            qd = list(value["queue_depths"])
            times = list(value["recent_times"])

            avg_qd = (
                sum(qd) / len(qd)
                if qd else 0.0
            )

            if len(times) >= 2:
                span = times[-1] - times[0]
                pps = (
                    (len(times) - 1) / span
                    if span > 0 else 0.0
                )
            else:
                pps = 0.0

            report["switches"][str(sw_id)] = {
                "count": value["count"],
                "avg_queue_depth": avg_qd,
                "throughput_pps": pps,
            }

        latencies = list(e2e_latencies_ms)

        if latencies:
            report["latency_avg_ms"] = (
                sum(latencies) / len(latencies)
            )
            report["latency_samples"] = len(latencies)
        else:
            report["latency_avg_ms"] = None
            report["latency_samples"] = 0

    return report

def send_report_pqc(report):
    """
    Kirim satu INT report melalui TLS 1.3:
      - ML-KEM768
      - ML-DSA-65
    """

    payload = json.dumps(
        report,
        separators=(",", ":")
    ) + "\n"

    cmd = [
        OPENSSL_BIN,
        "s_client",
        "-connect",
        f"{COLLECTOR_HOST}:{COLLECTOR_PORT}",
        "-tls1_3",
        "-groups",
        "MLKEM768",
        "-sigalgs",
        "ML-DSA-65",
        "-CAfile",
        COLLECTOR_CERT,
        "-quiet",
        "-no_ign_eof",
    ]

    start = time.perf_counter()

    try:
        result = subprocess.run(
            cmd,
            input=payload,
            capture_output=True,
            text=True,
            timeout=10,
            env=OPENSSL_ENV,
        )

        elapsed_ms = (
            time.perf_counter() - start
        ) * 1000

        if result.returncode == 0:
            print(
                f"[PQC-EXPORT] report terkirim "
                f"({elapsed_ms:.2f} ms)",
                flush=True
            )
        else:
            print(
                f"[PQC-EXPORT] GAGAL "
                f"(exit={result.returncode})",
                flush=True
            )

            if result.stderr.strip():
                print(
                    f"[PQC-EXPORT] stderr: "
                    f"{result.stderr.strip()}",
                    flush=True
                )

    except Exception as e:
        print(
            f"[PQC-EXPORT] ERROR: {e}",
            flush=True
        )

def export_loop():
    """
    Kirim snapshot INT secara periodik.
    """

    while not export_stop.wait(EXPORT_INTERVAL):

        report = build_int_report()

        if report["total_packets"] == 0:
            continue

        send_report_pqc(report)

def render_dashboard():
    while True:
        time.sleep(1)
        with lock:
            snapshot = {sw: dict(v) for sw, v in stats.items()}
            lat_snapshot = list(e2e_latencies_ms)
            total = total_packets

        print("\033c", end="")  # clear layar (ANSI escape)
        print("=== Dashboard Telemetry INT (live, refresh 1 detik) ===\n")
        print("Topologi:  h1 --- s1 --- s2 --- s3 --- h2\n")

        print(f"{'Switch':<10}{'Paket':<10}{'Avg Queue Depth':<20}{'Throughput (pps)':<18}")
        print("-" * 58)
        for sw_id in sorted(snapshot.keys()):
            v = snapshot[sw_id]
            qd = v["queue_depths"]
            avg_qd = sum(qd) / len(qd) if qd else 0
            print(f"s{sw_id:<9}{v['count']:<10}{avg_qd:<20.2f}{throughput_pps(sw_id):<18.2f}")

        print()
        if lat_snapshot:
            avg_lat = sum(lat_snapshot) / len(lat_snapshot)
            print(f"Latency end-to-end h1->h2 (rata-rata {len(lat_snapshot)} paket terakhir): {avg_lat:.3f} ms")
        else:
            print("Latency end-to-end: belum ada data (pastikan pakai send_int_test.py versi terbaru)")

        print(f"\nTotal paket INT diterima sejak start: {total}")
        print("(Kalau ada paket di-drop karena MAC invalid di P4, itu TIDAK akan")
        print(" muncul di sini -- bandingkan angka ini dengan jumlah yang dikirim")
        print(" h1 utk tau apakah ada yang hilang di tengah jalan)")
        print("\n(Ctrl+C untuk berhenti)")


def main():
    sniffer = AsyncSniffer(
        iface="eth0",
        prn=handle_packet,
        store=False,
        filter="ether proto 0x1212"
    )

    sniffer.start()

    exporter = threading.Thread(
        target=export_loop,
        daemon=True
    )

    exporter.start()

    try:
        render_dashboard()

    except KeyboardInterrupt:
        export_stop.set()
        sniffer.stop()
        print("\nBerhenti.")


if __name__ == "__main__":
    main()