### INSTALL SCRIPT 
<pre><code>apt install -y && apt update -y && apt upgrade -y && apt install -y lolcat wget curl jq && gem install lolcat && wget -q https://raw.githubusercontent.com/azziz1601/vip/main/setup.sh && chmod +x setup.sh && ./setup.sh
</code></pre>

### INSTALL SCRIPT (SCREEN)
<pre><code>apt install -y && apt install curl jq wget screen build-essential -y && apt update -y && apt upgrade -y && apt install -y lolcat wget curl jq && gem install lolcat && wget -q https://raw.githubusercontent.com/azziz1601/vip/main/setup.sh && chmod +x setup.sh && screen -S install ./setup.sh
</code></pre>

### LINK UPDATE 
```bash
wget -q https://raw.githubusercontent.com/azziz1601/vip/main/update.sh && chmod +x update.sh && ./update.sh
```

### RUST QUOTA DAEMON (`zevpn-limit`)
Keempat service bash lama (`limitvmess`, `limitvless`, `limittrojan`, `limitshadowsocks`) kini digabung menjadi satu daemon Rust statis di folder `zevpn-limit/` yang otomatis dikompilasi oleh GitHub Actions (`.github/workflows/build-limit.yml`) untuk `amd64` dan `arm64`.

1. Setelah push ke GitHub, buat tag rilis pertama agar binary muncul di **GitHub Releases**:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```
2. Saat `setup.sh` / `limit/limit.sh` dijalankan di VPS, skrip otomatis mengunduh binary terbaru dari:
   `https://github.com/azziz1601/vip/releases/latest/download/zevpn-limit-linux-<arch>`
   (jika nama repo GitHub berbeda, ubah `GITHUB_REPO` di `limit/limit.sh` dan `REPO` di `setup.sh`).

### TESTED ON OS 
- UBUNTU 20.04 / 24.04
- DEBIAN 10 / 12

### FITUR TAMBAHAN
- Tambah Swap 1GiB
- Pemasangan yang dinamis
- Tuning profile pada server
- Penambahan fail2ban
- Auto block sebagian ads indo by default
- Auto clear log per 3 menit
- Auto delete expired
- User Details Akun
- Unified Rust Xray Quota Limit Daemon (`zevpn-limit`)

### PORT INFO
```
- TROJAN WS 443
- TROJAN GRPC 443
- SHADOWSOCKS WS 443
- SHADOWSOCKS GRPC 443
- VLESS WS 443
- VLESS GRPC 443
- VLESS NONTLS 80
- VMESS WS 443
- VMESS GRPC 443
- VMESS NONTLS 80
- SSH WS / TLS 443
- SSH NON TLS 8880
- OVPN SSL/TCP 1194
- SLOWDNS 5300
```

### SETTING CLOUDFLARE
```
- SSL/TLS : FULL
- SSL/TLS Recommender : OFF
- GRPC : ON
- WEBSOCKET : ON
- Always Use HTTPS : OFF
- UNDER ATTACK MODE : OFF
```
