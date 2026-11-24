# Diff Summary — `vip-main` (Sinkronisasi Penuh Multi-Transport, UDPGW Rust `v1.2.0` & Xray-Lite `v1.0.0`)

Ringkasan lengkap seluruh perubahan tersinkronisasi pada `azziz1601/vip` antara installer (`setup.sh`, `install.sh`, `zevpn.sh`), updater (`update.sh`), menu CLI (`limit/menu.zip`), dan konfigurasi (`config.json`, `xray.conf`, `haproxy.cfg`).

## Ringkasan File yang Berubah

| File | Ringkasan Perubahan |
|---|---|
| `setup.sh`, `install.sh`, `zevpn.sh` | Auto-install `badvpn-udpgw-rs v1.2.0` (`amd64`/`arm64`, idempoten), auto-install `xray-lite-rs v1.0.0` (`amd64`/`arm64`, fallback aman ke Xray-core), perbaikan `[Unit]` + `ExecReload=/bin/kill -HUP $MAINPID` pada `xray.service`, dan penghapusan sisa direktori/DB Shadowsocks. |
| `update.sh` | Auto-migrasi `badvpn-udpgw-rs v1.2.0` (skip jika sudah Rust), auto-migrasi `xray-lite-rs v1.0.0` (skip jika sudah `xray-lite`, backup binary lama ke `xray.go.bak`), pembersihan 7 skrip Shadowsocks lama, sinkronisasi `xray.service` (`[Unit]` + `ExecReload`), serta `sync_multi_transport_configs()` untuk upgrade otomatis `xray.conf`, `haproxy.cfg`, dan `config.json` (mengkloning akun eksisting ke inbound HTTPUpgrade & XHTTP setelah lolos `nginx -t`, `haproxy -c`, dan `xray -t`). |
| `limit/config.json` | 13 inbound bersih (tanpa Shadowsocks): `api` (`:10000`), WS (`:10001-10003`), gRPC (`:10005-10007`), HTTPUpgrade (`:10009-10011` `/upvless`, `/upvmess`, `/uptrojan`), dan XHTTP (`:10016-10018` `/vless-xhttp`, `/vmess-xhttp`, `/trojan-xhttp`). |
| `limit/xray.conf` | Route Nginx unbuffered (`proxy_buffering off; proxy_request_buffering off`) untuk HTTPUpgrade (`/up*`) di `:1010` dan XHTTP (`/*-xhttp`) di `:1010` (HTTP/1.1 Non-TLS) & `:1013` (HTTP/2 TLS), tanpa `/ss-ws` & `/ss-grpc`. |
| `limit/haproxy.cfg` | Penambahan ACL `is_xhttp` (`path_beg -i /vless-xhttp /vmess-xhttp /trojan-xhttp`) pada frontend HTTP (`80`) & HTTPS (`443`). |
| `limit/menu.zip` | Penghapusan total menu & 7 skrip Shadowsocks, penghitung akun unik (`sort -u`) di `menu/menu`, serta sinkronisasi 4 transport (`WS`, `HTTPUpgrade`, `XHTTP`, `gRPC`) pada `addws`/`trialws`, `addvless`/`trialvless`, `addtr`/`trialtr`, dan `unlock-vm`/`unlock-vl`/`unlock-tr`. |
