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
import csv
import os
import resource
import socket
import struct
import subprocess
import threading
import time
from collections import deque, defaultdict
from scapy.all import Packet, bind_layers, ByteField, ShortField, IntField, Ether, IP, TCP, AsyncSniffer

TYPE_INT = 0x1212
ROLLING_WINDOW = 20  # jumlah sampel terakhir dipakai utk rolling avg & throughput

# --- Konfigurasi OpenSSL 3.5 eksperimen ---
# SENGAJA pakai path absolut, BUKAN os.path.expanduser("~/openssl35"),
# karena script ini kadang dijalankan lewat `sudo ~/mininet/util/m h2 ...`
# yang bikin proses jalan sbg root -- dan "~" buat root itu /root, BUKAN
# /home/ubuntu22, jadi expanduser akan salah resolve ke /root/openssl35
# yang nggak ada.
OPENSSL_HOME = "/home/ubuntu22/openssl35"
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


last_export_error = None


GROUPS_BY_MODE = {"pqc": "MLKEM768", "classical": "X25519"}


class LoByteCounter:
    """Hitung byte TCP di loopback TANPA dobel. Di `lo`, tiap paket muncul
    2x di PF_PACKET (salinan OUTGOING saat dikirim + salinan HOST saat
    diterima), sehingga sniffer biasa (scapy/tcpdump -w) menghitung dobel.
    Di sini hanya salinan PACKET_OUTGOING yang dihitung. Satuan = byte frame
    termasuk header Ethernet 14B (sama dgn 'Data size' di capinfos).
    Raw socket tanpa scapy -> overhead per paket juga jauh lebih kecil."""

    def __init__(self, iface, port):
        self.port = port
        self.total = 0
        self._stop = threading.Event()
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        self.sock.bind((iface, 0))
        self.sock.settimeout(0.05)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                data, sa = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if sa[2] != socket.PACKET_OUTGOING:
                continue
            if len(data) < 38 or data[12:14] != b"\x08\x00" or data[23] != 6:
                continue
            ihl = (data[14] & 0x0F) * 4
            off = 14 + ihl
            if len(data) < off + 4:
                continue
            sport = int.from_bytes(data[off:off + 2], "big")
            dport = int.from_bytes(data[off + 2:off + 4], "big")
            if sport == self.port or dport == self.port:
                self.total += len(data)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=1)
        self.sock.close()
        return self.total


def export_to_collector(report_line, host, port, groups, timeout=15):
    """Kirim satu baris laporan ke Telemetry Collector lewat TLS (PQC atau
    klasik, tergantung `groups`). Return (elapsed_detik, total_bytes, cpu_ms_anak) kalau
    sukses, (None, 0, 0.0) kalau gagal (alasan gagalnya ke last_export_error).

    total_bytes dihitung dari CAPTURE TRAFIK BENERAN (raw AF_PACKET, interface lo, tanpa dobel)
    selama handshake+kirim berlangsung -- bukan estimasi teoretis. Ini
    SENGAJA dilakukan di sini (bukan di tool terpisah kayak
    measure_bytes.py) supaya ikut kena efek kondisi jaringan non-ideal
    (mis. retransmission TCP akibat packet loss di profil severe), yang
    nggak akan kelihatan kalau diukur di kondisi bersih/terisolasi."""
    global last_export_error
    counter = LoByteCounter("lo", port)

    cmd = [
        OPENSSL_BIN, "s_client",
        "-connect", f"{host}:{port}",
        "-tls1_3", "-groups", groups,
        "-quiet", "-verify_quiet", "-no_ign_eof",
    ]
    elapsed = None
    cpu_ms = 0.0
    try:
        ru0 = resource.getrusage(resource.RUSAGE_CHILDREN)
        t0 = time.perf_counter()
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE, text=True, env=OPENSSL_ENV)
        _, stderr = proc.communicate(input=report_line + "\n", timeout=timeout)
        # PENTING: stopwatch dihentikan LANGSUNG di sini, SEBELUM
        # sniffer.stop(). Sebelumnya `time.time() - t0` dihitung setelah
        # blok finally, sehingga waktu sniffer.stop() (scapy join thread,
        # ~puluhan-100 ms) ikut kehitung sbg "waktu kirim".
        elapsed = time.perf_counter() - t0
        ru1 = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu_ms = ((ru1.ru_utime - ru0.ru_utime) + (ru1.ru_stime - ru0.ru_stime)) * 1000
        if proc.returncode != 0:
            last_export_error = f"exit code {proc.returncode}: {stderr.strip()[:200]}"
            return None, 0, 0.0
    except subprocess.TimeoutExpired:
        proc.kill()
        last_export_error = "timeout"
        return None, 0, 0.0
    except Exception as e:
        last_export_error = f"{type(e).__name__}: {e}"
        return None, 0, 0.0
    finally:
        time.sleep(0.05)   # kasih waktu paket FIN/ACK terakhir tertangkap utk hitung byte (di luar stopwatch)
        total_bytes = counter.stop()

    return elapsed, total_bytes, cpu_ms


def write_csv_row(csv_path, profile_label, algo_label, total, snapshot, lat_snapshot,
                   export_ms, export_ok, export_bytes, client_cpu_ms=0.0):
    """Tulis satu baris hasil pengukuran ke CSV (append mode), dipakai
    harness.py (Fase 7) buat ngumpulin data eksperimen. Kolom switch
    di-hardcode s1/s2/s3 sesuai topologi testbed ini -- bukan dibikin
    fully-dynamic, karena overkill utk 3 switch tetap."""
    is_new = not os.path.exists(csv_path)
    with open(csv_path, "a", newline="") as f:
        writer = csv.writer(f)
        if is_new:
            writer.writerow([
                "timestamp", "algo", "profile", "total_packets",
                "s1_count", "s1_avg_qd", "s1_pps",
                "s2_count", "s2_avg_qd", "s2_pps",
                "s3_count", "s3_avg_qd", "s3_pps",
                "avg_latency_ms", "export_ms", "export_ok", "export_bytes", "client_cpu_ms",
            ])
        row = [time.strftime("%Y-%m-%d %H:%M:%S"), algo_label, profile_label, total]
        for sw_id in (1, 2, 3):
            v = snapshot.get(sw_id)
            if v:
                qd = v["queue_depths"]
                avg_qd = sum(qd) / len(qd) if qd else 0
                row += [v["count"], f"{avg_qd:.2f}", f"{throughput_pps(sw_id):.2f}"]
            else:
                row += [0, "0.00", "0.00"]
        avg_lat = sum(lat_snapshot) / len(lat_snapshot) if lat_snapshot else ""
        row += [f"{avg_lat:.3f}" if avg_lat != "" else "", f"{export_ms:.2f}" if export_ms else "",
                 export_ok, export_bytes, f"{client_cpu_ms:.2f}"]
        writer.writerow(row)


export_in_progress = threading.Event()


def _do_export_async(report_line, host, port, groups, csv_path, profile_label, algo_label, total, snapshot, lat_snapshot):
    """Dijalankan di thread terpisah supaya export yang lambat (mis. di
    profil jaringan severe, bisa beberapa detik) TIDAK menahan loop
    dashboard utama yang harus tetap jalan tiap 1 detik."""
    global last_export_ms, last_export_ok
    elapsed, export_bytes, cpu_ms = export_to_collector(report_line, host, port, groups)
    if elapsed is not None:
        last_export_ms = elapsed * 1000
        last_export_ok = True
    else:
        last_export_ok = False
    if csv_path:
        write_csv_row(csv_path, profile_label, algo_label, total, snapshot, lat_snapshot,
                      last_export_ms if last_export_ok else None, last_export_ok, export_bytes, cpu_ms)
    export_in_progress.clear()


def render_dashboard(collector_host, collector_port, mode="pqc", csv_path=None, profile_label="unlabeled", duration=None):
    groups = GROUPS_BY_MODE[mode]
    last_exported_total = 0   # dipakai utk deteksi "ada paket baru sejak export terakhir?"
    start_time = time.time()
    while True:
        if duration is not None and (time.time() - start_time) >= duration:
            if export_in_progress.is_set():
                # PENTING: ada export (thread daemon) yang masih jalan --
                # kalau langsung return di sini, thread itu bisa dibunuh
                # paksa SEBELUM sempat nulis baris CSV-nya (walau datanya
                # sendiri sudah terkirim ke collector). Tunggu dulu max 10
                # detik biar export terakhir ini sempat selesai & tercatat.
                print(f"\n[sink_agent] durasi {duration}s tercapai, menunggu export terakhir selesai...")
                export_in_progress.wait(timeout=10)
            print(f"[sink_agent] keluar otomatis.")
            return
        time.sleep(1)
        with lock:
            snapshot = {sw: dict(v) for sw, v in stats.items()}
            lat_snapshot = list(e2e_latencies_ms)
            total = total_packets

        # Export ke collector HANYA kalau ada paket baru sejak export
        # terakhir, DAN tidak ada export lain yang masih berjalan (biar
        # thread nggak numpuk kalau export sedang lambat). Dijalankan di
        # thread terpisah supaya loop 1 detik ini TIDAK ikut ketahan.
        if total > 0 and total != last_exported_total and not export_in_progress.is_set():
            report_line = build_report_line(snapshot, lat_snapshot, total)
            export_in_progress.set()
            last_exported_total = total
            threading.Thread(
                target=_do_export_async,
                args=(report_line, collector_host, collector_port, groups, csv_path, profile_label, mode, total, snapshot, lat_snapshot),
                daemon=True,
            ).start()

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

        print(f"\n--- Export ke Telemetry Collector ({collector_host}:{collector_port}), mode={mode} ---")
        if last_export_ok is None:
            print("Belum ada percobaan export (menunggu paket pertama)")
        elif last_export_ok:
            print(f"Sukses, waktu kirim (handshake+transfer): {last_export_ms:.2f} ms")
        else:
            print(f"GAGAL -- {last_export_error}")

        print("\n(Ctrl+C untuk berhenti)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector-host", default="127.0.0.1")
    parser.add_argument("--collector-port", type=int, default=7001)
    parser.add_argument("--mode", choices=["pqc", "classical"], default="pqc",
                         help="HARUS sama dengan mode collector.py yang lagi jalan")
    parser.add_argument("--csv", default=None, help="path CSV utk log hasil (Fase 7 harness)")
    parser.add_argument("--profile-label", default="unlabeled", help="label profil jaringan, ditulis ke tiap baris CSV")
    parser.add_argument("--duration", type=float, default=None, help="keluar otomatis setelah N detik (dipakai harness.py)")
    args = parser.parse_args()

    sniffer = AsyncSniffer(iface="eth0", prn=handle_packet, store=False,
                            filter="ether proto 0x1212")
    sniffer.start()
    try:
        render_dashboard(args.collector_host, args.collector_port, mode=args.mode,
                          csv_path=args.csv, profile_label=args.profile_label,
                          duration=args.duration)
    except KeyboardInterrupt:
        print("\nBerhenti.")
    finally:
        sniffer.stop()


if __name__ == "__main__":
    main()