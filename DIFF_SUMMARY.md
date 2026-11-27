# Diff Summary — `vip` (Go TUI `vip-menu v1.1.0` Menyeluruh + Layout Klasik)

| File | Perubahan |
|---|---|
| `vip-menu/internal/accounts/accounts.go` | **Baru** — Implementasi 100% native Go CRUD untuk **SSH (+ SlowDNS NS & Pub Key)**, **VMess**, **VLESS**, dan **Trojan** (Buat, Trial 1-klik, Perpanjang, Hapus, Cek Login eksak, Lihat Detail/Link, Hapus Expired `xp`, Clear Cache & Log, validasi `xray -t` + atomic write + `systemctl reload xray` `SIGHUP` + notifikasi Telegram) + unit test di `accounts_test.go`. |
| `vip-menu/internal/tui/model.go` | Merombak tampilan agar mengikuti struktur **menu klasik** (banner merah `.::. ZE-VPN STORE TUNNEL .::.`, kotak System OS/Core/RAM/Uptime/Domain/IP/ISP, kotak jumlah akun, grid status 8 service, grid menu 2 kolom `[1]-[0]`, dan kotak Bandwidth `vnstat`), lengkap dengan form input native Go, pemilih akun native, dan tampilan hasil yang bisa langsung disalin. |
| `vip-menu/internal/sysinfo/sysinfo.go` | Menambah jumlah CPU core (`runtime.NumCPU()`) dan ringkasan bandwidth harian/bulanan dari `vnstat --oneline`. |
| Rollback | Tetap 100% aman: menu Bash klasik tersimpan di `/usr/local/sbin/menu-legacy`, rollback instan lewat opsi `[0]` di dashboard atau `menu-rollback` (`menu-tui` untuk kembali ke Go TUI). |
