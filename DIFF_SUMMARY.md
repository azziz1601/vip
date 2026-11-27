# Diff Summary — `vip` (Integrasi `ws-rs` + Tuning Stabilitas Nginx/HAProxy)

| File | Perubahan |
|---|---|
| `ws-rs/` | Implementasi ulang `/usr/bin/ws` berbasis Rust (static `musl`, 0 cek lisensi `.ipvps`, 2 dependency `tokio` + `socket2`, drop-in `tun.conf` & `ws.service`, runtime 1-vCPU). |
| `.github/workflows/build-ws.yml` | Workflow GitHub Actions untuk `cargo test` + build & rilis otomatis `ws-linux-amd64` dan `ws-linux-arm64` static `musl` saat push tag `v*`. |
| `setup.sh`, `install.sh`, `zevpn.sh` | Unduh otomatis `ws-linux-amd64`/`ws-linux-arm64` dari GitHub Releases `azziz1601/vip` (fallback ke `limit/ws` jika rilis belum tersedia). |
| `update.sh` | Menambah `migrate_ws_rs()` otomatis saat update + blok 2a tuning stabilitas Nginx & HAProxy. |
| `limit/nginx.conf` | Menambah `worker_shutdown_timeout 10s;` dan menaikkan `worker_connections 1024` → `4096`. |
| `limit/xray.conf` | Mengubah `client_header_timeout` & `keepalive_timeout` dari `86400000m` → `360s`. |
| `limit/haproxy.cfg` | Menghapus `option httplog` dan keyword `check` pada backend lokal `127.0.0.1` (menghilangkan false-down & broadcast `EMERG`). |
