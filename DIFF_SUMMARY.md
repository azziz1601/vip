# Diff Summary — `vip` (Integrasi SlowDNS HTTP Custom + Output NS & Pub Key di SSH)

| File | Perubahan |
|---|---|
| `limit/slowdns-linux-amd64.tar.gz` | **Ditambahkan** — paket SlowDNS static `amd64` khusus HTTP Custom (6 mode DNS + `NOTRACK` UDP 53). |
| `setup.sh` | Mengganti `ssh_slow()` agar mengekstrak & memasang SlowDNS ke `/root/slowdns` pada `<IP_VPS>:53` → `127.0.0.1:143` (Dropbear), menyimpan NS ke `/etc/xray/dns`, symlink `/etc/slowdns/server.pub`, dan menghapus rule NAT `53 → 5300` di `rc.local`. |
| `limit/ipserver` | Menghapus rule NAT `PREROUTING 53 → 5300` agar SlowDNS berjalan langsung di UDP 53 dengan `NOTRACK`. |
| `update.sh` | Menambah `sync_slowdns()` untuk memasang/menyinkronkan SlowDNS, `/etc/slowdns/server.pub`, dan `/etc/xray/dns` secara otomatis saat update. |
| `limit/menu.zip` (`menu/addssh`, `menu/trial`, `menu/user-ssh`) | Menampilkan **Name Server (`NS`)**, **Pub Key (`PUB`)**, dan **Port DNS (`53`)** di terminal, file `/var/www/html/ssh-<user>.txt`, serta notifikasi Telegram setiap kali membuat akun SSH/Trial SSH. |
