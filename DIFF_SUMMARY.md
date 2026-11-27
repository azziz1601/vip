# Diff Summary — `vip` (Anti-Orphan `menu` Guard + Safe `limit-ip` + SlowDNS + `ws-rs`)

| File | Perubahan |
|---|---|
| `limit/menu.zip` (`menu/menu` & sub-menu `while true`) | Menambah `trap 'exit 0' HUP TERM PIPE`, guard `[[ -t 0 ]] \|\| exit 0`, dan `read ... \|\| exit 0` agar sesi menu otomatis berhenti saat SSH putus (mencegah proses `menu` orphan & lonjakan Load Average). |
| `limit/limit-ip` | Mode **notify-only** (tanpa hapus akun/restart Xray/kosongkan log, pencocokan eksak `email: <user>`, cooldown alert 10 menit). |
| `limit/nginx.conf` & `limit/xray.conf` | `map $http_cf_connecting_ip $client_real_ip` (IP asli Cloudflare + PROXY protocol direct) + tuning stabilitas (`worker_shutdown_timeout 10s`, `worker_connections 4096`, timeout `360s`). |
| `update.sh` | Tidak menyentuh `/etc/xray/config.json`; sinkronisasi otomatis menu, `limit-ip`, `ws-rs`, `zevpn-limit`, `udpgw-rs`, `xray-lite-rs`, SlowDNS, Nginx/HAProxy, & cron log 6 jam. |
| `setup.sh`, `ws-rs/`, `zevpn-limit/` | Instalasi tunggal `setup.sh`, integrasi SlowDNS HTTP Custom (UDP 53 + `NOTRACK` + NS/Pub Key di akun SSH), `ws-rs` static `musl`, dan `zevpn-limit` `reload` (`SIGHUP`) + `.trim_start()`. |
