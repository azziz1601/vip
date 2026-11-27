# Diff Summary — `xray-lite-rs` (`v1.0.0`, Optimasi 1-vCPU & Low-RAM VPS)

Ringkasan 9 optimasi performa CPU, RAM, dan stabilitas jangka panjang untuk VPS 1-vCPU / 2 GB RAM pada `xray-lite-rs` (versi `Cargo.toml` tetap `1.0.0`, **0 dependency baru**).

## Ringkasan 9 Optimasi yang Diterapkan

| # | File | Optimasi | Dampak Utama |
|---|---|---|---|
| 1 | `src/address.rs` | In-memory DNS cache TTL 60 detik (`OnceLock<RwLock<HashMap<...>>>`, maks 1024 entri) pada `resolve_domain_cached()` | Memangkas blocking thread `getaddrinfo` & syscall DNS berulang saat browsing/gaming ke domain yang sama |
| 2 | `src/transport/websocket.rs` | `BufReader` 16 KB untuk `wire_r` + zero-copy 10-byte headroom framing (`write_ws_header_before`) di `write_task` | Mengurangi 3–4 syscall `read()` per frame WS menjadi 1x dan menghilangkan alokasi `Vec` per chunk downlink |
| 3 | `src/stats.rs` | `AccessLogger` non-blocking via `mpsc::sync_channel(2048)` + 1 background thread `BufWriter` 8 KB (flush tiap 250ms) | Mencegah disk I/O `/var/log/xray/access.log` memblokir worker Tokio saat koneksi ramai |
| 4 | `src/stats.rs` | Fast-path `AtomicBool` (`has_rules`) di `DynamicBlocklist::is_blocked()` | Menghindari `RwLock::read()` pada setiap koneksi masuk ketika tidak ada rule `xray api sib` aktif |
| 5 | `src/protocol/vmess.rs` | Ganti `OsRng` → `rand::thread_rng()` di `ChunkCodec::write_chunk` | Menghilangkan syscall `getrandom()` per chunk saat `GlobalPadding` aktif |
| 6 | `src/protocol/vmess.rs` | In-place AEAD (`AeadInPlace`) + reusable `read_buf`/`write_buf`/`scratch_buf` + `BufReader` 16 KB di `ChunkCodec` | **0 alokasi heap per chunk** pada jalur baca/tulis VMess (sebelumnya 3–5 alokasi per chunk) |
| 7 | `src/protocol/mux.rs` | `BufReader` 16 KB untuk `client_r`, buffer metadata reusable (`read_mux_frame_with_buf`), dan single-alloc `encode_udp_keep_frame` | Mengurangi syscall & alokasi heap per paket game online XUDP/Mux.Cool |
| 8 | `src/protocol/vless.rs`, `vmess.rs`, `trojan.rs`, `mux.rs` | Perkecil buffer UDP `recv_buf` dari `65535`/`65507` byte → `8192` byte | Menghemat ~8x RAM per sesi UDP aktif (aman untuk seluruh paket MTU internet 1500B & jumbo UDP) |
| 9 | `src/config.rs`, `outbound.rs`, `protocol/mod.rs`, `lib.rs`, `vless.rs`, `trojan.rs`, `vmess.rs` | Enforcing `policy.levels["0"].connIdle` (default 300s) pada TCP relay VLESS, Trojan, dan VMess via `AtomicBool` idle watchdog | Memutus otomatis koneksi TCP idle/zombie agar FD & RAM tidak menumpuk berjam-jam |
