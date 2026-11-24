# Diff Summary — `vip-main` (Multi-Transport, Pemisah Garis & Seragamkan Return to Menu)

Ringkasan lengkap pembaruan tersinkronisasi pada `azziz1601/vip`:

## Pembaruan Terbaru
- **Seragamkan navigasi kembali ke menu (`limit/menu.zip`)**:
  - Menambahkan `read -n 1 -s -r -p "Press [ Enter ] to back on menu"` + `menu` pada seluruh skrip akun & monitoring (`addws`, `trialws`, `addvless`, `trialvless`, `addtr`, `trialtr`, `addssh`, `trial`, `cekws`, `cekvless`, `cektr`, `cekssh`, `change-vmess-qouta`, `change-vless-qouta`, `change-trojan-qouta`, `ganti-ip-vmess`, `ganti-ip-vless`, `ganti-ip-trojan`, `lock-vm`, `unlock-vm`, serta `ceklim`).
- **Tampilan output multi-transport**:
  - Pemisah garis `◇━━━━━━━━━━━━━━━━━◇` di antara `HTTPUpgrade TLS` / `HTTPUpgrade NTLS` dan `XHTTP TLS` / `XHTTP NTLS` di terminal (serta pemisah di notifikasi Telegram), plus perbaikan `&host=${domain}` pada link VLESS.
- **Sinkronisasi penuh infrastruktur & biner Rust**:
  - `setup.sh`, `install.sh`, `zevpn.sh`, `update.sh` (unduh no-cache `/tmp`, `xray-lite-rs v1.0.0`, `badvpn-udpgw-rs v1.2.0`, `xray.service` `ExecReload`), `limit/config.json` (13 inbound), `limit/xray.conf`, dan `limit/haproxy.cfg` tanpa Shadowsocks.
