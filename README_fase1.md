# Fase 1 — INT dasar tanpa crypto

## Yang gue yakin bener
- `int_source.p4` — ditulis manual sesuai spesifikasi bahasa P4_16/v1model, bukan hasil compile-test (nggak ada `p4c`/BMv2 di environment gue). Logikanya (parser, push_front untuk stack, egress action) sudah gue cek ulang manual sesuai semantik P4_16, tapi **wajib lo compile & jalanin sendiri** dan kabari kalau ada error compile.
- `send_int_test.py` / `receive_int_test.py` — murni Python + scapy biasa, tidak tergantung tooling P4 apapun, harusnya jalan langsung.

## Yang PERLU lo sesuaikan (gue nggak bisa verifikasi dari sini)
- `s1/s2/s3-runtime.json` — gue tulis berdasarkan pola umum yang dipakai p4lang/tutorials, TAPI nama field JSON persisnya (`table`, `match`, `action_params`, dst.) bisa beda tergantung versi repo tutorials lo. **Buka file runtime.json yang SUDAH JALAN di exercise `basic` lo, dan samakan formatnya** — isi entry yang gue kasih tetap sama (switch_id per switch, forwarding rule, khusus s1 ada entry `int_source`), tinggal transplant ke skema JSON yang bener.
- Alamat IP/MAC (`10.0.1.1`, `10.0.2.2`, dst.) itu asumsi umum dari tutorial dasar P4 — ganti sesuai topologi asli lo.
- Nomor port (`port: 1`, `port: 2`) juga asumsi — sesuaikan sama urutan link di topologi lo yang sebenarnya.

## Cara test
1. Compile: `p4c-bm2-ss --p4v 16 int_source.p4 -o build/int_source.json` (atau lewat Makefile yang udah ada di exercise `basic`, tinggal ganti nama file .p4-nya).
2. Jalankan Mininet dengan runtime.json yang sudah lo sesuaikan.
3. Di Mininet CLI:
   ```
   mininet> h2 python3 receive_int_test.py &
   mininet> h1 python3 send_int_test.py
   ```
4. **Kriteria sukses Fase 1**: di terminal h2 muncul 3 baris `hop[i] switch_id=...` dengan switch_id **1, 2, 3** (urutan boleh terbalik tergantung push_front — itu normal, cek isinya lengkap, bukan urutannya dulu) dan `shim.len` konsisten dengan jumlah hop.

## Kalau macet
Kirim pesan error compile atau output yang aneh dari receive_int_test.py, gue bantu debug bareng — termasuk kalau perlu revisi skema runtime.json setelah lo kasih tau format asli yang dipakai exercise `basic` lo.
