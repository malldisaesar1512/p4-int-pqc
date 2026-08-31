#!/usr/bin/env python3
"""
Jalankan di host h1 (dalam Mininet CLI: `h1 python3 send_int_test.py`).
Cukup kirim paket IPv4 biasa ke h2 — logika penyisipan INT sepenuhnya
terjadi di switch (s1), host tidak perlu tahu apa-apa soal INT.

Payload menyertakan waktu kirim (8 byte, double, wall-clock h1) di posisi
akhir, dipakai sink_agent.py di h2 untuk menghitung latency end-to-end
menggunakan SATU jam saja (h1), bukan timestamp antar-switch BMv2 yang
tidak sinkron satu sama lain.
"""
import sys
import time
import struct
from scapy.all import IP, UDP, Ether, sendp, get_if_hwaddr, get_if_list

def get_iface():
    for i in get_if_list():
        if "eth0" in i:
            return i
    return get_if_list()[0]

def main():
    iface = get_iface()
    dst_ip = sys.argv[1] if len(sys.argv) > 1 else "10.0.2.2"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    interval = float(sys.argv[3]) if len(sys.argv) > 3 else 0.2

    print(f"[send_int_test] mengirim {n} paket ke {dst_ip} lewat {iface}")
    for i in range(n):
        payload = b"int-test-payload" + struct.pack("!d", time.time())
        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / \
              IP(dst=dst_ip) / UDP(sport=12345, dport=54321) / payload
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(interval)
    print("[send_int_test] selesai. Cek receive_int_test.py / sink_agent.py di h2.")

if __name__ == "__main__":
    main()