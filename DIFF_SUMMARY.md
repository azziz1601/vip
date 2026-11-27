# Diff Summary — `vip` (Go TUI `vip-menu` + Instant Rollback)

| File | Perubahan |
|---|---|
| `vip-menu/` | Panel TUI modern berbasis **Go (`Bubble Tea` + `Lip Gloss`)** sebagai 1 binary static tunggal (`vip-menu`): dashboard live (Domain, IP, OS, Uptime, Load, RAM, status 8 service, jumlah akun SSH/VMess/VLESS/Trojan), navigasi panah + pintasan `1–9`, Service Control (`reload` SIGHUP Xray, Nginx, HAProxy, WS, SlowDNS), info SlowDNS, anti-orphan TTY/SIGHUP guard, dan proteksi anti-nested menu (`VIP_MENU_NESTED=1`). |
| `.github/workflows/build-menu.yml` | Workflow GitHub Actions (`go mod tidy`, `go vet`, `go test`, build static `CGO_ENABLED=0` `amd64` & `arm64`, + GitHub Release otomatis saat push tag `v*`). |
| `setup.sh` & `update.sh` | Menyimpan menu Bash klasik di `/usr/local/sbin/menu-legacy`, memasang `/usr/local/bin/vip-menu`, membuat perintah `menu-rollback` & `menu-tui`, serta menghormati opt-out `/etc/xray/.use-legacy-menu` agar rollback tidak pernah tertimpa saat update. |
