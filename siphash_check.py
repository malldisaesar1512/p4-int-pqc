#!/usr/bin/env python3
"""
Validasi SipHash-2-4 di int_source.p4 TANPA perlu compile P4/jalanin BMv2.

Yang diuji:
  1. Implementasi referensi (di file ini) cocok dgn test vector RESMI SipHash
     (key 00..0f, pesan 00..0e -> 0xa129ca6149be45e5) dan dgn pustaka pihak
     ketiga (pip install siphash).
  2. Teks kode P4 SESUNGGUHNYA (blok SIPHASH-BEGIN..END di int_source.p4),
     setelah diproses preprocessor `cpp`, diterjemahkan baris-per-baris ke
     Python dgn aritmetika 64-bit wrap, lalu hasilnya dibandingkan dgn
     referensi utk banyak (key, f0, f1, f2) acak + kasus tepi.

BATASAN JUJUR: ini membuktikan LOGIKA & urutan operasi di kode P4 benar,
BUKAN bahwa p4c berhasil compile. Compile tetap harus dicoba di mesin
yang punya p4c (`make build`).

Pakai:  python3 siphash_check.py [path/int_source.p4]
Juga bisa di-import: p4_mac(key128, switch_id, ts, qd) -> tag 32-bit,
berguna utk verifikasi MAC di sisi host (sink_agent).
"""
import random
import re
import struct
import subprocess
import sys

M64 = (1 << 64) - 1


# ---------------- referensi independen (standar, byte-oriented) ----------------
def _rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & M64


def siphash24(key16: bytes, msg: bytes) -> int:
    k0, k1 = struct.unpack("<QQ", key16)
    v0 = k0 ^ 0x736f6d6570736575
    v1 = k1 ^ 0x646f72616e646f6d
    v2 = k0 ^ 0x6c7967656e657261
    v3 = k1 ^ 0x7465646279746573

    def rnd():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & M64; v1 = _rotl(v1, 13); v1 ^= v0; v0 = _rotl(v0, 32)
        v2 = (v2 + v3) & M64; v3 = _rotl(v3, 16); v3 ^= v2
        v0 = (v0 + v3) & M64; v3 = _rotl(v3, 21); v3 ^= v0
        v2 = (v2 + v1) & M64; v1 = _rotl(v1, 17); v1 ^= v2; v2 = _rotl(v2, 32)

    n = len(msg)
    for i in range(0, n - n % 8, 8):
        m = struct.unpack("<Q", msg[i:i + 8])[0]
        v3 ^= m; rnd(); rnd(); v0 ^= m
    last = msg[n - n % 8:] + b"\x00" * (8 - n % 8)
    b = struct.unpack("<Q", last)[0] | ((n & 0xff) << 56)
    v3 ^= b; rnd(); rnd(); v0 ^= b
    v2 ^= 0xff
    for _ in range(4):
        rnd()
    return (v0 ^ v1 ^ v2 ^ v3) & M64


def p4_mac(key128: int, f0: int, f1: int, f2: int) -> int:
    """MAC 32-bit persis spt di switch P4: kunci = (k1<<64)|k0, pesan = LE32(f0)||LE32(f1)||LE32(f2)."""
    key16 = struct.pack("<QQ", key128 & M64, key128 >> 64)
    return siphash24(key16, struct.pack("<III", f0, f1, f2)) & 0xFFFFFFFF


# ---------------- penerjemah kode P4 -> Python ----------------
class U(int):
    """Bilangan 64-bit tak bertanda dgn wrap-around, meniru bit<64> di P4."""
    def __new__(cls, v=0):
        return int.__new__(cls, int(v) & M64)
    def __add__(s, o): return U(int(s) + int(o))
    __radd__ = __add__
    def __xor__(s, o): return U(int(s) ^ int(o))
    __rxor__ = __xor__
    def __or__(s, o): return U(int(s) | int(o))
    __ror__ = __or__
    def __and__(s, o): return U(int(s) & int(o))
    __rand__ = __and__
    def __lshift__(s, n): return U(int(s) << int(n))
    def __rshift__(s, n): return U(int(s) >> int(n))


def extract_p4_block(path):
    txt = open(path).read()
    m = re.search(r"// SIPHASH-BEGIN(.*?)// SIPHASH-END", txt, re.S)
    if not m:
        sys.exit("Penanda SIPHASH-BEGIN/END tidak ketemu di " + path)
    return m.group(1)


def expand_with_cpp(block):
    block = re.sub(r"//[^\n]*", "", block)          # buang komentar //
    out = subprocess.run(["cpp", "-P", "-undef", "-nostdinc"], input=block,
                         capture_output=True, text=True, check=True).stdout
    return out


def build_python_mac(path):
    code = expand_with_cpp(extract_p4_block(path))
    consts = dict(re.findall(r"const\s+bit<64>\s+(\w+)\s*=\s*64w(0x[0-9a-fA-F]+)\s*;", code))
    body = re.search(r"apply\s*\{(.*)\}\s*\}", code, re.S).group(1)

    t = body
    t = re.sub(r"64w(0x[0-9a-fA-F]+)", r"U(\1)", t)                 # literal 64w0x..
    t = re.sub(r"bit<\d+>\s+(\w+)\s*=", r"\1 =", t)                  # deklarasi+inisialisasi
    t = re.sub(r"\(bit<64>\)(\w+)", r"U(\1)", t)                     # cast ke 64-bit
    t = re.sub(r"\(bit<32>\)\(", "T32(", t)                           # cast ke 32-bit
    t = re.sub(r"(\w+)\[(\d+):(\d+)\]", r"SL(\1,\2,\3)", t)          # slice
    lines = [l.strip() for l in t.replace(";", "\n").splitlines() if l.strip()]

    def SL(x, hi, lo):
        return U((int(x) >> lo) & ((1 << (hi - lo + 1)) - 1))

    def T32(x):
        return int(x) & 0xFFFFFFFF

    def mac(key128, f0, f1, f2):
        env = {"U": U, "SL": SL, "T32": T32, "key": key128, "f0": f0, "f1": f1, "f2": f2}
        for k, v in consts.items():
            env[k] = U(int(v, 16))
        for ln in lines:
            exec(ln, env)
        return env["tag"]

    return mac, len(lines)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "int_source.p4"
    rng = random.Random(1234)

    # 1) referensi vs test vector resmi
    key = bytes(range(16))
    official = siphash24(key, bytes(range(15)))
    assert official == 0xa129ca6149be45e5, hex(official)
    print(f"[1] referensi cocok dgn test vector resmi SipHash-2-4: {official:#018x}")

    # 1b) referensi vs pustaka pihak ketiga (kalau terpasang)
    try:
        import siphash as lib
        for _ in range(500):
            k = rng.randbytes(16); m = rng.randbytes(rng.randint(0, 40))
            assert siphash24(k, m) == lib.SipHash_2_4(k, m).hash()
        print("[1b] referensi cocok dgn pustaka `siphash` utk 500 kasus acak")
    except ImportError:
        print("[1b] pustaka `siphash` tidak terpasang, dilewati (pip install siphash)")

    # 2) kode P4 sungguhan vs referensi
    mac, nstmt = build_python_mac(path)
    cases = [(0, 0, 0, 0), ((1 << 128) - 1,) + (0xFFFFFFFF,) * 3,
             (0x000102030405060708090a0b0c0d0e0f, 1, 2, 3)]
    cases += [(rng.getrandbits(128), rng.getrandbits(32), rng.getrandbits(32), rng.getrandbits(32))
              for _ in range(5000)]
    bad = 0
    for k, a, b, c in cases:
        if mac(k, a, b, c) != p4_mac(k, a, b, c):
            bad += 1
    print(f"[2] kode P4 ({nstmt} pernyataan hasil cpp) vs referensi: "
          f"{len(cases) - bad}/{len(cases)} cocok")
    if bad:
        sys.exit("GAGAL: ada ketidakcocokan")

    k = 0x000102030405060708090a0b0c0d0e0f
    print(f"\nContoh vektor utk dokumentasi/verifikasi di host:\n"
          f"  key=0x{k:032x}  switch_id=1 ts=100 qd=5  ->  tag32=0x{p4_mac(k,1,100,5):08x}")
    print("\nSEMUA OK.")


if __name__ == "__main__":
    main()