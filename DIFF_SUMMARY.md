# Diff Summary — `vip` (Safe `limit-ip` + `CF-Connecting-IP` Real IP + `zevpn-limit` Fix)

| File | Perubahan |
|---|---|
| `limit/limit-ip` | Diubah ke mode **notify-only** (tidak lagi menghapus akun dari `config.json`/`.db`, tidak merestart Xray, dan tidak mengosongkan `access.log`), memperbaiki pencocokan eksak `email: <user>`, hitungan `0` saat kosong, serta cooldown alert Telegram 10 menit. |
| `limit/nginx.conf` & `limit/xray.conf` | Menambah `map $http_cf_connecting_ip $client_real_ip` agar trafik Cloudflare mencatat IP asli user dari `CF-Connecting-IP` (bukan IP edge Cloudflare `104.x`/`172.x`) dan trafik direct tetap memakai `$remote_addr` dari PROXY protocol. |
| `zevpn-limit/src/config.rs` | Menambah `.trim_start()` saat mendeteksi baris `},{` pada `remove_user_from_xray_config()`. |
| `update.sh` | Otomatis memperbarui `/usr/bin/limit-ip` dan menyinkronkan `$client_real_ip` Nginx tanpa pernah menyentuh `/etc/xray/config.json`. |
