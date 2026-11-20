#!/bin/bash
set -euo pipefail

GITHUB_REPO="${GITHUB_REPO:-azziz1601/vip}"
VERSION="${VERSION:-latest}"
RAW_REPO="https://raw.githubusercontent.com/${GITHUB_REPO}/main/"

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  ASSET="zevpn-limit-linux-amd64" ;;
    aarch64) ASSET="zevpn-limit-linux-arm64" ;;
    *)
        echo "Arsitektur tidak didukung: $ARCH"
        exit 1
        ;;
esac

if [ "$VERSION" = "latest" ]; then
    BIN_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/${ASSET}"
else
    BIN_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${ASSET}"
fi

# Nonaktifkan 4 service bash lama jika masih ada
for svc in limitvmess limitvless limittrojan limitshadowsocks; do
    systemctl disable --now "$svc" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${svc}.service"
done
rm -f /etc/xray/limit.vmess /etc/xray/limit.vless /etc/xray/limit.trojan /etc/xray/limit.shadowsocks

# Unduh binary Rust statis secara atomik agar aman saat update service yang sedang berjalan
TMP_BIN="/usr/local/bin/zevpn-limit.tmp.$$"
curl -fsSL "$BIN_URL" -o "$TMP_BIN"
chmod +x "$TMP_BIN"
mv -f "$TMP_BIN" /usr/local/bin/zevpn-limit

# Pasang/perbarui systemd service tunggal
curl -fsSL "${RAW_REPO}limit/zevpn-limit.service" -o /etc/systemd/system/zevpn-limit.service

systemctl daemon-reload
systemctl enable zevpn-limit >/dev/null 2>&1 || true
systemctl restart zevpn-limit
