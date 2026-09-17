/* -*- P4_16 -*- */
/*
 * FASE 1 + FASE 2: INT dengan CRC32 placeholder MAC per-hop.
 * Fase 1: metadata INT (switch_id, timestamp, queue depth) disisipkan di
 * switch sumber dan ditambahkan (append) oleh setiap switch transit.
 * Fase 2 (baru): tiap entri metadata sekarang juga bawa field `mac`
 * (CRC32 atas field lain + shared key). Switch penerima memverifikasi MAC
 * milik entri SEBELUM menambahkan entrinya sendiri -- kalau tidak valid,
 * paket di-drop. Shared key masih SAMA di semua switch (placeholder);
 * nanti di fase PQC baru didistribusikan/dirotasi lewat kanal terenkripsi.
 *
 * Topologi asumsi: h1 -- s1 -- s2 -- s3 -- h2 (linear).
 * Satu file .p4 ini dipakai untuk KETIGA switch; identitas switch_id dan
 * apakah switch tsb menjadi "sumber INT" dikonfigurasi lewat table entries
 * runtime yang berbeda per switch (lihat s1/s2/s3-runtime.json), bukan lewat
 * compile-time constant. Ini meniru cara kontroler nyata mengonfigurasi
 * banyak switch dari satu P4 program yang sama.
 */

#include <core.p4>
#include <v1model.p4>

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_INT  = 0x1212;   // EtherType custom penanda "frame ini bawa INT"
const bit<8>  MAX_HOPS  = 8;

/*************************************************************************
*********************** H E A D E R S  **********************************
*************************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// Shim header: penanda awal section INT + panjang total section (dalam word 4-byte)
header int_shim_t {
    bit<8> int_type;   // 1 = INT-MD (disederhanakan, cukup 1 nilai utk riset ini)
    bit<8> rsvd;
    bit<8> len;        // panjang total shim+header+metadata stack, dalam satuan 4-byte word
    bit<8> dscp;       // dicadangkan, tidak dipakai di Fase 1
}

// Header INT utama (disederhanakan supaya byte-aligned; bukan copy persis
// bit-per-bit dari spek P4.org INT, tapi fungsinya setara utk riset ini)
header int_header_t {
    bit<8>  ver_flags;
    bit<8>  ins_cnt;         // jumlah field per hop yang disisipkan (tetap = 3)
    bit<8>  max_hop_cnt;
    bit<8>  total_hop_cnt;   // di-increment setiap hop
    bit<16> instruction_mask;
    bit<16> rsvd;
}

// Satu entri metadata per hop: 4 field x 4 byte = 16 byte
// (field ke-4, `mac`, adalah CRC32 placeholder yang dihitung dari 3 field
// lain + shared key -- akan diganti algoritma yang lebih kuat di fase lanjut)
header int_metadata_t {
    bit<32> switch_id;
    bit<32> ingress_timestamp;
    bit<32> queue_depth;
    bit<32> mac;
}

struct metadata {
    bit<32> switch_id;     // diisi oleh switch_id_table (per switch, via runtime entry)
    bit<32> mac_key;       // shared secret placeholder (sama di semua switch utk Fase 2)
    bit<8>  mac_valid;     // hasil verifikasi MAC hop sebelumnya (1=valid, 0=invalid)
    bit<8>  int_hop_count; // dipakai parser utk tahu berapa banyak metadata yang SUDAH ada
    bit<8>  int_hop_idx;
}

struct headers {
    ethernet_t                  ethernet;
    int_shim_t                  int_shim;
    int_header_t                int_header;
    int_metadata_t[MAX_HOPS]    int_meta;
    ipv4_t                      ipv4;
}

/*************************************************************************
*********************** P A R S E R  *************************************
*************************************************************************/

parser MyParser(packet_in packet,
                 out headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_INT:  parse_int_shim;
            default:   accept;
        }
    }

    state parse_int_shim {
        packet.extract(hdr.int_shim);
        transition parse_int_header;
    }

    state parse_int_header {
        packet.extract(hdr.int_header);
        // total_hop_cnt SUDAH menyimpan langsung jumlah metadata entri yang
        // ada di stack (di-increment tiap hop nambah metadata di egress).
        // Nggak perlu dihitung ulang dari shim.len (itu butuh pembagian
        // runtime yang nggak didukung BMv2 -- makanya versi sebelumnya error).
        meta.int_hop_count = hdr.int_header.total_hop_cnt;
        meta.int_hop_idx = 0;
        transition select(meta.int_hop_count) {
            0:       parse_ipv4;
            default: parse_int_meta;
        }
    }

    state parse_int_meta {
        packet.extract(hdr.int_meta.next);
        meta.int_hop_idx = meta.int_hop_idx + 1;
        transition select(meta.int_hop_idx == meta.int_hop_count) {
            true:    parse_ipv4;
            default: parse_int_meta;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M   V E R I F I C A T I O N   ***************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }  // diabaikan utk Fase 1, sama seperti pola umum di tutorial dasar P4
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control MyIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_switch_id(bit<32> sw_id) {
        meta.switch_id = sw_id;
    }

    // Diisi via runtime entry berbeda di tiap switch (s1/s2/s3-runtime.json)
    table switch_id_table {
        actions = { set_switch_id; NoAction; }
        default_action = NoAction();
        size = 1;
    }

    action set_mac_key(bit<32> key) {
        meta.mac_key = key;
    }

    // Fase 2: SATU shared key yang SAMA di semua switch (placeholder).
    // Nanti di fase PQC, kunci ini yang bakal didistribusikan/rotasi lewat
    // kanal PQC-TLS dari controller, bukan hardcode sama di semua switch.
    table mac_key_table {
        actions = { set_mac_key; NoAction; }
        default_action = NoAction();
        size = 1;
    }

    // Verifikasi MAC milik entri metadata TERBARU (int_meta[0]), yaitu yang
    // ditambahkan oleh switch SEBELUMNYA di jalur ini. Dipanggil di ingress,
    // sebelum switch ini menambahkan entrinya sendiri di egress.
    action verify_prev_hop_mac() {
        bit<32> computed_mac;
        hash(computed_mac, HashAlgorithm.crc32, (bit<32>)0,
             { hdr.int_meta[0].switch_id,
               hdr.int_meta[0].ingress_timestamp,
               hdr.int_meta[0].queue_depth,
               meta.mac_key },
             (bit<32>)0xFFFFFFFF);
        if (computed_mac == hdr.int_meta[0].mac) {
            meta.mac_valid = 1;
        } else {
            meta.mac_valid = 0;
        }
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        switch_id_table.apply();
        mac_key_table.apply();

        // Hanya verifikasi kalau paket ini SUDAH bawa minimal 1 metadata
        // entri dari switch sebelumnya (switch sumber yg pertama kali
        // menerima dari host tidak punya apa-apa utk diverifikasi).
        if (hdr.int_header.isValid() && hdr.int_header.total_hop_cnt > 0) {
            verify_prev_hop_mac();
            if (meta.mac_valid == 0) {
                drop();
                exit;   // hentikan pemrosesan, jangan lanjut ke forwarding
            }
        }

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *********************
*************************************************************************/

control MyEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Dipanggil HANYA oleh switch yang jadi titik sumber INT (mis. s1, port
    // menghadap h1). Menyalakan shim+header, EtherType diubah jadi TYPE_INT.
    action init_int_header() {
        hdr.int_shim.setValid();
        hdr.int_header.setValid();
        hdr.int_shim.int_type = 1;
        hdr.int_shim.rsvd     = 0;
        hdr.int_shim.len      = 3;   // shim(1 word) + header(2 word); metadata ditambah setelah ini
        hdr.int_shim.dscp     = 0;
        hdr.int_header.ver_flags       = 0;
        hdr.int_header.ins_cnt         = 4;
        hdr.int_header.max_hop_cnt     = MAX_HOPS;
        hdr.int_header.total_hop_cnt   = 0;
        hdr.int_header.instruction_mask = 0;
        hdr.int_header.rsvd            = 0;
        hdr.ethernet.etherType = TYPE_INT;
    }

    // Diisi via runtime entry HANYA pada switch sumber (match: ingress_port
    // yang menghadap host pengirim). Switch lain tidak punya entry ini
    // sehingga default_action (NoAction) yang jalan.
    table int_source {
        key = { standard_metadata.ingress_port: exact; }
        actions = { init_int_header; NoAction; }
        default_action = NoAction();
        size = 8;
    }

    // Menambahkan SATU entri metadata baru di depan stack (push_front),
    // termasuk menghitung CRC32 sebagai MAC placeholder atas field metadata
    // + shared key. Dipanggil oleh SEMUA switch (sumber maupun transit)
    // selama header INT sudah valid di titik ini pada pipeline egress.
    action add_int_metadata() {
        hdr.int_meta.push_front(1);
        hdr.int_meta[0].setValid();
        hdr.int_meta[0].switch_id          = meta.switch_id;
        hdr.int_meta[0].ingress_timestamp  = (bit<32>) standard_metadata.egress_global_timestamp;
        hdr.int_meta[0].queue_depth        = (bit<32>) standard_metadata.deq_qdepth;
        hash(hdr.int_meta[0].mac, HashAlgorithm.crc32, (bit<32>)0,
             { hdr.int_meta[0].switch_id,
               hdr.int_meta[0].ingress_timestamp,
               hdr.int_meta[0].queue_depth,
               meta.mac_key },
             (bit<32>)0xFFFFFFFF);
        hdr.int_shim.len       = hdr.int_shim.len + 4;   // 16 byte = 4 word/entri sekarang
        hdr.int_header.total_hop_cnt = hdr.int_header.total_hop_cnt + 1;
    }

    apply {
        if (hdr.ipv4.isValid() && !hdr.int_shim.isValid()) {
            int_source.apply();   // hanya "nyala" di switch sumber
        }
        if (hdr.int_header.isValid()) {
            add_int_metadata();   // jalan di switch sumber (lanjutan) & semua transit
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   ****************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen,
              hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset,
              hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *********************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.int_shim);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_meta);   // stack: emit semua entri yang valid, sesuai urutan
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  **************************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
