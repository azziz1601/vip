# ws-rs

Pengganti drop-in berbasis Rust untuk binary `/usr/bin/ws` (`ws-epro`) pada skrip VPS `vip`. Menghasilkan binary tunggal **static `musl`** (`x86_64-unknown-linux-musl` & `aarch64-unknown-linux-musl`) tanpa ketergantungan library OS, tanpa DRM/cek `.ipvps`, dan dioptimalkan untuk VPS 1-vCPU.

## Fitur Utama
- **Drop-in compatible** dengan `ws.service` (`ExecStart=/usr/bin/ws -f /usr/bin/tun.conf`) dan format YAML `tun.conf` (`verbose`, `listen`, `target_host`, `target_port`, `listen_port`).
- **HTTP/1.1 101 Upgrade Bridge**: kompatibel dengan Nginx `proxy_pass`, HAProxy, HTTP Injector, HTTP Custom, NetMod, DarkTunnel, dan client SSH-WS / OpenVPN-WS (termasuk dukungan `Sec-WebSocket-Accept` RFC 6455, early-data pasca `\r\n\r\n`, serta fallback raw TCP).
- **Ringan untuk 1-vCPU**: otomatis memilih Tokio `current_thread` di VPS 1-vCPU, hanya 2 dependency (`tokio` + `socket2`), `TCP_NODELAY`, TCP keepalive, batas koneksi global (`4096`), dan idle watchdog (300 detik).

## Build Lokal (Target `amd64` Static `musl`)
```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install -y musl-tools
CC_x86_64_unknown_linux_musl=musl-gcc RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build --release --target x86_64-unknown-linux-musl
# Output: target/x86_64-unknown-linux-musl/release/ws
```

## Pemakaian di VPS
```bash
ws -f /usr/bin/tun.conf
ws --version
```
