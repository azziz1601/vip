# xray-lite-rs

High-performance, low-memory Rust server compatible with standard **Xray-core `config.json`**, tailored for production VPN VPS behind **Nginx / HAProxy** (or standalone TLS).

## Supported Protocols & Transports

- **Protocols (TCP + UDP):**
  - **VLESS** (`version 0`, TCP & UDP)
  - **VMess AEAD** (`alterId: 0`, `aes-128-gcm` / `chacha20-poly1305`, `Shake128` chunk masking + `GlobalPadding`, anti-replay cache, TCP & UDP)
  - **Trojan** (`SHA-224` password hash, TCP & UDP, optional `fallbacks`)
- **Transports:**
  - **TLS** (`rustls` + ALPN `h2`/`http/1.1`) & **Non-TLS**
  - **TCP** (raw), **WebSocket (`ws`)** with Xray `?ed=2048` `Sec-WebSocket-Protocol` early data, **HTTPUpgrade**, and **gRPC** (Xray Gun mode over HTTP/2)
  - **TCP & Unix Domain Socket** listeners + **PROXY Protocol v1/v2** (`acceptProxyProtocol: true`)
- **Hot-Reload Users (`SIGHUP`):**
  - Reload `clients` from `config.json` via `systemctl reload xray-lite` (`kill -HUP <pid>`) without dropping active connections. Invalid JSON is safely rejected while keeping the previous active user list.
- **VPS-Optimized Runtime:**
  - Automatically selects Tokio `current_thread` runtime on 1-vCPU VPS (zero work-stealing overhead) and `multi_thread` on multi-core servers.

## Usage

```bash
# Test config syntax & validation
./xray-lite -t -c /etc/xray/config.json

# Run server (drop-in compatible with `xray run -c ...`)
./xray-lite run -c /etc/xray/config.json

# Hot-reload user list without disconnecting active clients
sudo systemctl reload xray-lite
```

## Build via GitHub Actions

Push this repository to GitHub to automatically run `cargo test` and build statically linked Linux binaries (`amd64` & `arm64`) ready to download from the **Actions** tab (or push a `v*` tag to publish a GitHub Release).
