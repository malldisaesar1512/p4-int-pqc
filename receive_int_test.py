#!/usr/bin/env python3
"""
Jalankan di host h2 (dalam Mininet CLI: `h2 python3 receive_int_test.py`),
SEBELUM menjalankan send_int_test.py di h1.

Mendefinisikan struktur INT custom (shim + header + metadata stack) sebagai
layer Scapy sendiri, karena scapy tidak mengenalinya secara bawaan.
Struktur ini HARUS persis sama dengan yang didefinisikan di int_source.p4.
"""
from scapy.all import Packet, bind_layers, BitField, ByteField, ShortField, IntField, Ether, IP, sniff

TYPE_INT = 0x1212

class INTShim(Packet):
    name = "INTShim"
    fields_desc = [
        ByteField("int_type", 1),
        ByteField("rsvd", 0),
        ByteField("len", 0),   # dalam word 4-byte, termasuk shim+header+metadata stack
        ByteField("dscp", 0),
    ]

class INTHeader(Packet):
    name = "INTHeader"
    fields_desc = [
        ByteField("ver_flags", 0),
        ByteField("ins_cnt", 3),
        ByteField("max_hop_cnt", 8),
        ByteField("total_hop_cnt", 0),
        ShortField("instruction_mask", 0),
        ShortField("rsvd", 0),
    ]

class INTMetadata(Packet):
    name = "INTMetadata"
    fields_desc = [
        IntField("switch_id", 0),
        IntField("ingress_timestamp", 0),
        IntField("queue_depth", 0),
    ]

bind_layers(Ether, INTShim, type=TYPE_INT)
bind_layers(INTShim, INTHeader)
# metadata stack & IPv4 di-parse manual di handle_packet (jumlahnya dinamis,
# bind_layers scapy tidak nyaman dipakai untuk stack dgn panjang variabel)


def handle_packet(pkt):
    if not pkt.haslayer(INTShim):
        return
    shim = pkt.getlayer(INTShim)
    hdr = pkt.getlayer(INTHeader)
    if hdr is None:
        return

    print("\n=== Paket INT diterima ===")
    print(f"  shim.len          : {shim.len} word (=> {shim.len*4} byte total section)")
    print(f"  header.total_hop  : {hdr.total_hop_cnt}")

    # payload mentah setelah INTHeader = stack metadata (12 byte/entri) + sisanya IPv4
    raw = bytes(hdr.payload)
    n_meta = hdr.total_hop_cnt
    print(f"  jumlah metadata entri terbaca : {n_meta}")

    offset = 0
    for i in range(n_meta):
        chunk = raw[offset:offset+12]
        if len(chunk) < 12:
            print(f"  [!] entri ke-{i} terpotong, cek kembali panjang paket")
            break
        m = INTMetadata(chunk)
        print(f"  hop[{i}] switch_id={m.switch_id}  ts={m.ingress_timestamp}  queue_depth={m.queue_depth}")
        offset += 12

    ip_layer = pkt.getlayer(IP)
    if ip_layer:
        print(f"  IPv4 asli: {ip_layer.src} -> {ip_layer.dst}")
    print("===========================\n")


def main():
    print("[receive_int_test] menunggu paket INT di h2 ... (Ctrl+C utk berhenti)")
    sniff(iface="eth0", prn=handle_packet, store=False)

if __name__ == "__main__":
    main()
