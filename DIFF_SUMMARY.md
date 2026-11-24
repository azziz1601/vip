# Diff Summary — `vip-main` (Fix Update Menu No-Cache + Fix Host Link VLESS + Multi-Transport)

Ringkasan perbaikan terbaru pada `azziz1601/vip` (seluruh installer, updater, menu, dan config tersinkronisasi penuh):

## Perbaikan Terbaru
- **`update.sh`, `menu/utility`, `setup.sh`, `install.sh`, `zevpn.sh`**:
  - Mengunduh `update.sh`, `menu.zip`, `xray.conf`, `haproxy.cfg`, dan `config.json` ke path `/tmp` bersih dengan `-O` + header `Cache-Control: no-cache` + query `?t=$(date +%s)` agar tidak pernah tertimpa `menu.zip.1` / `update.sh.1` ataupun terkena cache CDN GitHub `raw.githubusercontent.com`.
- **`menu/addvless` & `menu/trialvless`**:
  - Menambahkan `&host=${domain}&sni=${domain}` pada `vlesslink1` (WS TLS), `&host=${domain}&security=none` pada `vlesslink2` (WS Non-TLS), dan `&host=${domain}` pada `vlesslink3` (gRPC) agar field Host tidak lagi kosong saat di-import ke aplikasi client.
- **Sinkronisasi Penuh Multi-Transport, UDPGW Rust `v1.2.0` & Xray-Lite `v1.0.0`**:
  - `limit/config.json` (13 inbound), `limit/xray.conf`, `limit/haproxy.cfg`, `limit/menu.zip` (WS, HTTPUpgrade, XHTTP, gRPC; tanpa Shadowsocks), serta auto-install & auto-migrasi `badvpn-udpgw-rs v1.2.0` dan `xray-lite-rs v1.0.0` pada `setup.sh`, `install.sh`, `zevpn.sh`, dan `update.sh`.
