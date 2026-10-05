#!/usr/bin/env python3
"""
Sink Agent - dashboard terminal live + export laporan ke Telemetry Collector
lewat PQC-TLS (Fase 6).

Jalankan TERUS-MENERUS di h2: `python3 -u sink_agent.py`

METRIK YANG DITAMPILKAN & KENAPA:
- Queue depth per switch, jumlah paket per switch, throughput per switch:
  semuanya dihitung dari data INT (metadata per-hop), ini valid karena
  masing-masing angka itu murni pengukuran LOKAL di switch tsb, tidak
  butuh perbandingan jam antar-proses.
- Latency end-to-end (h1 -> h2): dihitung dari SATU jam saja (wall-clock
  h2, dibandingkan dengan waktu kirim yang ditempel h1 di payload paket).
  INI SENGAJA TIDAK memakai selisih `ingress_timestamp` antar switch dari
  BMv2, karena itu tidak disinkronkan antar proses switch (lihat histori
  chat utk penjelasan lengkap).

FASE 6 (baru): setiap 1 detik (bareng refresh dashboard), ringkasan
statistik dikirim ke Telemetry Collector lewat openssl s_client (PQC-TLS,
ML-KEM768 + ML-DSA65) -- pola PERSIS seperti controller.py mengirim kunci
ke switch_agent.py di Fase 5. Waktu kirim (handshake + transfer) dicatat
sebagai metrik, ditampilkan juga di dashboard.
"""

import argparse
import os
import struct
import subprocess
import threading
import time
from collections import deque, defaultdict
from scapy.all import Packet, bind_layers, ByteField, ShortField, IntField, Ether, IP, AsyncSniffer

TYPE_INT = 0x1212
ROLLING_WINDOW = 20  # jumlah sampel terakhir dipakai utk rolling avg & throughput

# --- Konfigurasi OpenSSL 3.5 eksperimen (sama persis pola switch_agent.py) ---
OPENSSL_HOME = os.path.expanduser("~/openssl35")
OPENSSL_BIN = os.path.join(OPENSSL_HOME, "bin", "openssl")
OPENSSL_ENV = os.environ.copy()
OPENSSL_ENV["LD_LIBRARY_PATH"] = (
    os.path.join(OPENSSL_HOME, "lib64") + ":" +
    os.path.join(OPENSSL_HOME, "lib") + ":" +
    OPENSSL_ENV.get("LD_LIBRARY_PATH", "")
)


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
last_export_ms = None       # waktu PQC-TLS export terakhir (ms), None = belum pernah
last_export_ok = None       # True/False/None

META_ENTRY_SIZE = 16  # byte per entri (switch_id + ts + queue_depth + mac, masing2 4 byte)


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


def build_report_line(snapshot, lat_snapshot, total):
    """Satu baris ringkas (CSV sederhana) yang dikirim ke Collector.
    Format: total_paket;switch_id:count:avg_qd:pps,...;avg_latency_ms
    """
    parts = []
    for sw_id in sorted(snapshot.keys()):
        v = snapshot[sw_id]
        qd = v["queue_depths"]
        avg_qd = sum(qd) / len(qd) if qd else 0
        parts.append(f"{sw_id}:{v['count']}:{avg_qd:.2f}:{throughput_pps(sw_id):.2f}")
    avg_lat = sum(lat_snapshot) / len(lat_snapshot) if lat_snapshot else -1
    return f"{total};" + ",".join(parts) + f";{avg_lat:.3f}"


def export_to_collector(report_line, host, port, timeout=5):
    """Kirim satu baris laporan ke Telemetry Collector lewat PQC-TLS.
    Return elapsed detik kalau sukses, None kalau gagal."""
    cmd = [
        OPENSSL_BIN, "s_client",
        "-connect", f"{host}:{port}",
        "-tls1_3", "-groups", "MLKEM768",
        "-quiet", "-verify_quiet", "-no_ign_eof",
    ]
    t0 = time.time()
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, text=True, env=OPENSSL_ENV)
        proc.stdin.write(report_line + "\n")
        proc.stdin.flush()
        proc.stdin.close()
        proc.wait(timeout=timeout)
    except Exception:
        return None
    return time.time() - t0


def render_dashboard(collector_host, collector_port):
    global last_export_ms, last_export_ok
    while True:
        time.sleep(1)
        with lock:
            snapshot = {sw: dict(v) for sw, v in stats.items()}
            lat_snapshot = list(e2e_latencies_ms)
            total = total_packets

        # Export ke collector lewat PQC-TLS (nonblocking terhadap tampilan:
        # kalau collector belum siap/gagal, dashboard tetap jalan normal)
        if total > 0:
            report_line = build_report_line(snapshot, lat_snapshot, total)
            elapsed = export_to_collector(report_line, collector_host, collector_port)
            if elapsed is not None:
                last_export_ms = elapsed * 1000
                last_export_ok = True
            else:
                last_export_ok = False

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

        print(f"\n--- Export ke Telemetry Collector ({collector_host}:{collector_port}), PQC-TLS ---")
        if last_export_ok is None:
            print("Belum ada percobaan export (menunggu paket pertama)")
        elif last_export_ok:
            print(f"Sukses, waktu kirim (handshake+transfer): {last_export_ms:.2f} ms")
        else:
            print("GAGAL -- pastikan collector.py sudah jalan & port benar")

        print("\n(Ctrl+C untuk berhenti)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector-host", default="127.0.0.1")
    parser.add_argument("--collector-port", type=int, default=7001)
    args = parser.parse_args()

    sniffer = AsyncSniffer(iface="eth0", prn=handle_packet, store=False,
                            filter="ether proto 0x1212")
    sniffer.start()
    try:
        render_dashboard(args.collector_host, args.collector_port)
    except KeyboardInterrupt:
        sniffer.stop()
        print("\nBerhenti.")


if __name__ == "__main__":
    main()