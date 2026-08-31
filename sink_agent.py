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
    fields_desc = [IntField("switch_id", 0), IntField("ingress_timestamp", 0), IntField("queue_depth", 0)]

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


def parse_int_metadata_stack(hdr):
    raw = bytes(hdr.payload)
    n = hdr.total_hop_cnt
    hops = []
    off = 0
    for _ in range(n):
        chunk = raw[off:off + 12]
        if len(chunk) < 12:
            break
        hops.append(INTMetadata(chunk))
        off += 12
    return hops


def handle_packet(pkt):
    global total_packets
    if not pkt.haslayer(INTShim):
        return
    hdr = pkt.getlayer(INTHeader)
    if hdr is None:
        return

    hops = parse_int_metadata_stack(hdr)
    now = time.time()

    with lock:
        total_packets += 1
        for m in hops:
            s = stats[m.switch_id]
            s["count"] += 1
            s["queue_depths"].append(m.queue_depth)
            s["recent_times"].append(now)

    # Latency end-to-end: baca 8 byte terakhir payload IP sbg waktu kirim h1
    ip_layer = pkt.getlayer(IP)
    if ip_layer is not None:
        raw_payload = bytes(ip_layer.payload)
        if len(raw_payload) >= 8:
            try:
                sent_ts = struct.unpack("!d", raw_payload[-8:])[0]
                latency_ms = (now - sent_ts) * 1000
                if 0 <= latency_ms < 60_000:
                    with lock:
                        e2e_latencies_ms.append(latency_ms)
            except struct.error:
                pass


def throughput_pps(switch_id):
    times = stats[switch_id]["recent_times"]
    if len(times) < 2:
        return 0.0
    span = times[-1] - times[0]
    return (len(times) - 1) / span if span > 0 else 0.0


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
        print("\n(Ctrl+C untuk berhenti)")


def main():
    sniffer = AsyncSniffer(iface="eth0", prn=handle_packet, store=False,
                            filter="ether proto 0x1212")
    sniffer.start()
    try:
        render_dashboard()
    except KeyboardInterrupt:
        sniffer.stop()
        print("\nBerhenti.")


if __name__ == "__main__":
    main()
