# Diff Summary — `vip` (Final Release: HAProxy SSH-SSL/BMOVE Fix + Safe `update.sh` + Go TUI `v1.1.0` + `ws-rs v1.1.0`)

| File | Perubahan |
|---|---|
| `limit/haproxy.cfg` | Menambah `sshssl_backend` (`127.0.0.1:143` Dropbear) untuk `SSH-2.0` & default TLS (agar akun SSH ber-password tetap konek walau `sshd` key-only), menempatkan `BMOVE`/`CONNECT` → `ws_ssh_backend` (`127.0.0.1:10015`, `ws-rs`) sebelum `is_http2`, dan menjaga seluruh rute V2Ray tetap utuh. |
| `update.sh` | **Dijamin 0 sentuhan** ke `/etc/xray/config.json` dan seluruh DB akun (`/etc/vmess`, `/etc/vless`, `/etc/trojan`, `/etc/ssh`), sinkronisasi `sshssl_backend` + rollback jika `haproxy -c` gagal, perbaikan `ExecReload=/bin/kill -HUP $MAINPID`, guard non-TTY, dan pembersihan proses `menu` orphan. |
| `setup.sh` | Skrip instalasi tunggal dengan escape `\$MAINPID` pada `xray.service`, SlowDNS HTTP Custom (UDP 53 + `NOTRACK`), `ws-rs`, `vip-menu`, dan cron log 6 jam. |
| `vip-menu/` & `ws-rs/` | Go TUI `v1.1.0` menyeluruh (bebas `go vet` error, rollback instan ke `menu-legacy`) dan `ws-rs v1.1.0` (dukungan `BMOVE`, `CONNECT`, `[split]`). |
