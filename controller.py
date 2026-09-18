#!/usr/bin/env python3
"""
FASE 4: Controller P4Runtime sederhana (BELUM PQC).

Konek ke ketiga switch (s1, s2, s3) lewat gRPC/P4Runtime, lalu secara
periodik meng-update entry `mac_key_table` di SEMUA switch dengan nilai
key yang sama (rotasi kunci sederhana), sambil Mininet tetap berjalan.

Kenapa ini fase penting sebelum PQC: nanti di Fase 5, fungsi push_mac_key()
di sini bakal diganti supaya kunci baru dikirim lewat kanal PQC-TLS
(ML-KEM/ML-DSA), BUKAN langsung lewat P4Runtime seperti sekarang. Tapi
struktur "controller yang hidup terus dan mengelola kunci" itu sama persis.

CATATAN JUJUR: gue nggak bisa compile/run-test script ini di sandbox gue
(nggak ada BMv2/p4runtime_lib di sini). Ada satu risiko teknis yang paling
mungkin bikin ini gagal di percobaan pertama: P4Runtime punya mekanisme
"mastership arbitration" -- run_exercise.py yang udah konek duluan waktu
`make run` mungkin masih pegang status "master" dengan election_id
tertentu, dan kalau controller ini connect dengan election_id yang SAMA
atau LEBIH RENDAH, tulisan (WriteTableEntry) bisa ditolak server dengan
error PERMISSION_DENIED. Makanya di bawah ini gue pakai election_id
berbasis waktu sekarang (hampir pasti lebih tinggi dari punya
run_exercise.py yang biasanya pakai angka kecil tetap). Kalau tetap kena
error itu, kabari gue, kita naikkan lagi election_id-nya.
"""

import argparse
import os
import random
import sys
import time

# p4runtime_lib ada di utils/ milik repo p4lang/tutorials (dipakai juga
# oleh run_exercise.py secara internal)
UTILS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'utils')
sys.path.append(UTILS_PATH)

import p4runtime_lib.bmv2          # noqa: E402
import p4runtime_lib.helper        # noqa: E402
from p4runtime_lib.switch import ShutdownAllSwitchConnections  # noqa: E402

SWITCHES = [
    {"name": "s1", "addr": "127.0.0.1:50051", "device_id": 0},
    {"name": "s2", "addr": "127.0.0.1:50052", "device_id": 1},
    {"name": "s3", "addr": "127.0.0.1:50053", "device_id": 2},
]

P4INFO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "build", "int_source.p4.p4info.txtpb")


def connect_all(p4info_helper):
    conns = []
    for sw in SWITCHES:
        conn = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=sw["name"],
            address=sw["addr"],
            device_id=sw["device_id"],
        )
        conn.MasterArbitrationUpdate()
        conns.append((sw["name"], conn))
        print(f"[controller] terhubung & jadi master di {sw['name']} ({sw['addr']})")
    return conns


def push_mac_key(p4info_helper, conn, key_value):
    entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.mac_key_table",
        default_action=True,
        action_name="MyIngress.set_mac_key",
        action_params={"key": key_value},
    )
    conn.WriteTableEntry(entry, update_type="modify")


def main(rotate_interval):
    if not os.path.exists(P4INFO_PATH):
        print(f"[controller] ERROR: p4info tidak ketemu di {P4INFO_PATH}")
        print("             pastikan sudah 'make build' / 'make run' minimal sekali dulu.")
        sys.exit(1)

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(P4INFO_PATH)
    conns = connect_all(p4info_helper)

    try:
        while True:
            new_key = random.getrandbits(32)
            print(f"\n[controller] rotasi mac_key -> {hex(new_key)}  (jam {time.strftime('%H:%M:%S')})")
            for name, conn in conns:
                try:
                    push_mac_key(p4info_helper, conn, new_key)
                    print(f"  - {name}: key ter-update")
                except Exception as e:
                    print(f"  - {name}: GAGAL update -> {e}")
            time.sleep(rotate_interval)
    except KeyboardInterrupt:
        print("\n[controller] dihentikan oleh user.")
    finally:
        ShutdownAllSwitchConnections()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=int, default=15, help="detik antar rotasi key (default 15)")
    args = parser.parse_args()
    main(args.interval)