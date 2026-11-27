#!/bin/bash
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
red() { echo -e "\\033[32;1m${*}\\033[0m"; }
GITHUB_REPO="${GITHUB_REPO:-azziz1601/vip}"
if [[ -z "${VIP_REF:-}" ]]; then
    VIP_REF=$(curl -fsSL -H "Accept: application/vnd.github.sha" "https://api.github.com/repos/${GITHUB_REPO}/commits/main" 2>/dev/null || true)
fi
[[ -z "$VIP_REF" || ${#VIP_REF} -lt 7 ]] && VIP_REF="main"
RAW_REPO="https://raw.githubusercontent.com/${GITHUB_REPO}/${VIP_REF}/"
clear
fun_bar() {
    CMD[0]="$1"
    CMD[1]="$2"
    (
        [[ -e $HOME/fim ]] && rm $HOME/fim
        ${CMD[0]} -y >/dev/null 2>&1
        ${CMD[1]} -y >/dev/null 2>&1
        touch $HOME/fim
    ) >/dev/null 2>&1 &
    tput civis
    echo -ne "  \033[0;33mPlease Wait Loading \033[1;37m- \033[0;33m["
    while true; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "\033[0;32m#"
            sleep 0.1s
        done
        [[ -e $HOME/fim ]] && rm $HOME/fim && break
        echo -e "\033[0;33m]"
        sleep 1s
        tput cuu1
        tput dl1
        echo -ne "  \033[0;33mPlease Wait Loading \033[1;37m- \033[0;33m["
    done
    echo -e "\033[0;33m]\033[1;37m -\033[1;32m OK !\033[1;37m"
    tput cnorm
}
update_udpgw_rust() {
    # Lewati otomatis jika UDPGW versi Rust sudah terpasang
    if [[ -x /usr/local/kyt/udp-mini ]] && /usr/local/kyt/udp-mini --version 2>&1 | grep -q "badvpn-udpgw-rs"; then
        return 0
    fi

    local udpgw_url=""
    case "$(uname -m)" in
        x86_64|amd64)
            udpgw_url="https://github.com/azziz1601/badvpn-udpgw-rs/releases/download/v1.2.0/badvpn-udpgw-linux-amd64"
            ;;
        aarch64|arm64)
            udpgw_url="https://github.com/azziz1601/badvpn-udpgw-rs/releases/download/v1.2.0/badvpn-udpgw-linux-arm64"
            ;;
        *)
            return 0
            ;;
    esac

    mkdir -p /usr/local/kyt
    if (curl -fsSL "$udpgw_url" -o /tmp/udp-mini.new || wget -q -O /tmp/udp-mini.new "$udpgw_url"); then
        chmod +x /tmp/udp-mini.new
        if /tmp/udp-mini.new --version 2>&1 | grep -q "badvpn-udpgw-rs"; then
            systemctl stop udp-mini-1 udp-mini-2 udp-mini-3 >/dev/null 2>&1
            mv -f /tmp/udp-mini.new /usr/local/kyt/udp-mini
            systemctl daemon-reload >/dev/null 2>&1
            systemctl restart udp-mini-1 udp-mini-2 udp-mini-3 >/dev/null 2>&1
        else
            rm -f /tmp/udp-mini.new
        fi
    else
        rm -f /tmp/udp-mini.new
    fi
}
update_xray_lite_rust() {
    # Lewati otomatis jika xray-lite-rs sudah terpasang
    if [[ -x /usr/local/bin/xray ]] && /usr/local/bin/xray --version 2>&1 | grep -q "xray-lite"; then
        return 0
    fi

    local xray_url=""
    case "$(uname -m)" in
        x86_64|amd64)
            xray_url="https://github.com/azziz1601/xray-lite-rs/releases/download/v1.0.0/xray-lite-linux-amd64"
            ;;
        aarch64|arm64)
            xray_url="https://github.com/azziz1601/xray-lite-rs/releases/download/v1.0.0/xray-lite-linux-arm64"
            ;;
        *)
            return 0
            ;;
    esac

    if (curl -fsSL "$xray_url" -o /tmp/xray-lite.new || wget -q -O /tmp/xray-lite.new "$xray_url"); then
        chmod +x /tmp/xray-lite.new
        if /tmp/xray-lite.new --version 2>&1 | grep -q "xray-lite"; then
            systemctl stop xray >/dev/null 2>&1
            [[ -f /usr/local/bin/xray ]] && cp -f /usr/local/bin/xray /usr/local/bin/xray.go.bak
            mv -f /tmp/xray-lite.new /usr/local/bin/xray
            systemctl daemon-reload >/dev/null 2>&1
            systemctl restart xray >/dev/null 2>&1
        else
            rm -f /tmp/xray-lite.new
        fi
    else
        rm -f /tmp/xray-lite.new
    fi
}
sync_multi_transport_configs() {
    local domain
    domain=$(cat /etc/xray/domain 2>/dev/null || echo "localhost")

    # 1. Upgrade /etc/nginx/conf.d/xray.conf jika belum punya /upvmess atau /vmess-xhttp
    if [[ -f /etc/nginx/conf.d/xray.conf ]] && ! grep -q "/vmess-xhttp" /etc/nginx/conf.d/xray.conf; then
        cp -f /etc/nginx/conf.d/xray.conf /etc/nginx/conf.d/xray.conf.bak
        if curl -fsSL -H "Cache-Control: no-cache" "${RAW_REPO}limit/xray.conf?t=$(date +%s)" -o /tmp/xray.conf.new; then
            sed -i "s/xxx/${domain}/g" /tmp/xray.conf.new
            mv -f /tmp/xray.conf.new /etc/nginx/conf.d/xray.conf
            if nginx -t >/dev/null 2>&1; then
                systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1
            else
                mv -f /etc/nginx/conf.d/xray.conf.bak /etc/nginx/conf.d/xray.conf
            fi
        fi
        rm -f /tmp/xray.conf.new
    fi

    # 2. Upgrade /etc/haproxy/haproxy.cfg jika belum punya ACL is_xhttp
    if [[ -f /etc/haproxy/haproxy.cfg ]] && ! grep -q "is_xhttp" /etc/haproxy/haproxy.cfg; then
        cp -f /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak
        if curl -fsSL -H "Cache-Control: no-cache" "${RAW_REPO}limit/haproxy.cfg?t=$(date +%s)" -o /tmp/haproxy.cfg.new; then
            mv -f /tmp/haproxy.cfg.new /etc/haproxy/haproxy.cfg
            if haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1; then
                systemctl reload haproxy >/dev/null 2>&1 || systemctl restart haproxy >/dev/null 2>&1
            else
                mv -f /etc/haproxy/haproxy.cfg.bak /etc/haproxy/haproxy.cfg
            fi
        fi
        rm -f /tmp/haproxy.cfg.new
    fi

    # 2a. Tuning stabilitas Nginx & HAProxy (hindari worker timeout & broadcast grpc_backend DOWN)
    local nginx_changed=0
    if [[ -f /etc/nginx/nginx.conf ]]; then
        if ! grep -q "worker_shutdown_timeout" /etc/nginx/nginx.conf; then
            sed -i '/^worker_processes/a worker_shutdown_timeout 10s;' /etc/nginx/nginx.conf
            nginx_changed=1
        fi
        if grep -q "worker_connections 1024;" /etc/nginx/nginx.conf; then
            sed -i 's/worker_connections 1024;/worker_connections 4096;/g' /etc/nginx/nginx.conf
            nginx_changed=1
        fi
    fi
    if [[ -f /etc/nginx/conf.d/xray.conf ]] && grep -q "86400000m" /etc/nginx/conf.d/xray.conf; then
        sed -i 's/86400000m/360s/g' /etc/nginx/conf.d/xray.conf
        nginx_changed=1
    fi
    if [[ "$nginx_changed" -eq 1 ]] && nginx -t >/dev/null 2>&1; then
        systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1
    fi
    if [[ -f /etc/haproxy/haproxy.cfg ]] && grep -qE 'server (dropbear_server|ws_server|grpc_server) 127\.0\.0\.1:[0-9]+ check' /etc/haproxy/haproxy.cfg; then
        cp -f /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak
        sed -i -E 's/(server (dropbear_server|ws_server|grpc_server) 127\.0\.0\.1:[0-9]+) check/\1/g' /etc/haproxy/haproxy.cfg
        sed -i '/^[[:space:]]*option httplog$/d' /etc/haproxy/haproxy.cfg
        if haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1; then
            systemctl reload haproxy >/dev/null 2>&1 || systemctl restart haproxy >/dev/null 2>&1
        else
            mv -f /etc/haproxy/haproxy.cfg.bak /etc/haproxy/haproxy.cfg
        fi
    fi

    # 2b. Pastikan xray.service punya [Unit] dan ExecReload=SIGHUP untuk hot-reload xray-lite-rs
    if [[ -f /etc/systemd/system/xray.service ]]; then
        if ! grep -q "^\[Unit\]" /etc/systemd/system/xray.service; then
            sed -i '1i [Unit]' /etc/systemd/system/xray.service
        fi
        if ! grep -q "ExecReload=" /etc/systemd/system/xray.service; then
            sed -i '/^ExecStart=/a ExecReload=/bin/kill -HUP $MAINPID' /etc/systemd/system/xray.service
            systemctl daemon-reload >/dev/null 2>&1
        fi
    fi

    # 3. Sinkronkan /etc/xray/config.json: tambahkan inbound HTTPUpgrade & XHTTP + klon user eksisting
    if [[ -f /etc/xray/config.json ]] && ! grep -q "#vmessxhttp" /etc/xray/config.json; then
        cp -f /etc/xray/config.json /etc/xray/config.json.bak
        if curl -fsSL -H "Cache-Control: no-cache" "${RAW_REPO}limit/config.json?t=$(date +%s)" -o /tmp/xray-config.base.json; then
            # Klon seluruh user eksisting dari config lama ke semua transport baru
            awk '/^#& /{h=$0; getline; print h "\n" $0}' /etc/xray/config.json.bak | sort -u > /tmp/vless.users.tmp
            awk '/^### /{h=$0; getline; print h "\n" $0}' /etc/xray/config.json.bak | sort -u > /tmp/vmess.users.tmp
            awk '/^#! /{h=$0; getline; print h "\n" $0}' /etc/xray/config.json.bak | sort -u > /tmp/trojan.users.tmp

            python3 - <<'PYMERGE' 2>/dev/null || true
from pathlib import Path
base = Path("/tmp/xray-config.base.json").read_text()
def extract_blocks(path, prefix):
    lines = Path(path).read_text().splitlines()
    seen, out = set(), []
    i = 0
    while i + 1 < len(lines):
        if lines[i].startswith(prefix + " ") and lines[i+1].lstrip().startswith("},{"):
            key = lines[i].split()[1]
            if key not in seen:
                seen.add(key)
                out.append(lines[i] + "\n" + lines[i+1])
            i += 2
        else:
            i += 1
    return "\n".join(out)

for prefix, markers in [
    ("#&", ["#vless", "#vlessgrpc", "#vlesshu", "#vlessxhttp"]),
    ("###", ["#vmess", "#vmessgrpc", "#vmesshu", "#vmessxhttp"]),
    ("#!", ["#trojanws", "#trojangrpc", "#trojanhu", "#trojanxhttp"]),
]:
    blk = extract_blocks("/etc/xray/config.json.bak", prefix)
    if blk:
        for mk in markers:
            base = base.replace(mk + "\n", mk + "\n" + blk + "\n", 1)
Path("/tmp/xray-config.merged.json").write_text(base)
PYMERGE

            if [[ -s /tmp/xray-config.merged.json ]] && /usr/local/bin/xray -t -config /tmp/xray-config.merged.json >/dev/null 2>&1; then
                mv -f /tmp/xray-config.merged.json /etc/xray/config.json
                systemctl restart xray >/dev/null 2>&1
            fi
        fi
        rm -f /tmp/xray-config.base.json /tmp/xray-config.merged.json /tmp/vless.users.tmp /tmp/vmess.users.tmp /tmp/trojan.users.tmp
    fi
}
res1() {
    local ts
    ts=$(date +%s)
    rm -rf /tmp/vip-menu-upd /tmp/vip-menu-upd.zip
    mkdir -p /tmp/vip-menu-upd
    if curl -fsSL -H "Cache-Control: no-cache" "${RAW_REPO}limit/menu.zip?t=${ts}" -o /tmp/vip-menu-upd.zip || wget -q --no-cache -O /tmp/vip-menu-upd.zip "${RAW_REPO}limit/menu.zip?t=${ts}"; then
        unzip -o -q /tmp/vip-menu-upd.zip -d /tmp/vip-menu-upd
        chmod +x /tmp/vip-menu-upd/menu/*
        mv -f /tmp/vip-menu-upd/menu/* /usr/local/sbin/
        rm -f /usr/local/sbin/{addss,cekss,delss,m-ssws,renewss,trialss,user-ss}
    fi
    rm -rf /tmp/vip-menu-upd /tmp/vip-menu-upd.zip

    # Migrasi / perbarui daemon Rust zevpn-limit otomatis dari GitHub Releases
    curl -fsSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" "${RAW_REPO}limit/limit.sh?t=$(date +%s)" -o /tmp/zevpn-limit-update.sh
    chmod +x /tmp/zevpn-limit-update.sh
    GITHUB_REPO="$GITHUB_REPO" bash /tmp/zevpn-limit-update.sh
    rm -f /tmp/zevpn-limit-update.sh

    # Migrasi otomatis ke UDPGW Rust v1.2.0 (skip jika sudah terpasang)
    update_udpgw_rust

    # Migrasi otomatis ke xray-lite-rs v1.0.0 (skip jika sudah terpasang)
    update_xray_lite_rust

    # Sinkronisasi multi-transport (WS, gRPC, HTTPUpgrade, XHTTP) + migrasi akun lama
    sync_multi_transport_configs

    rm -rf update.sh /tmp/update.sh
}
netfilter-persistent
clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " \e[1;97;101m          UPDATE SCRIPT    \e[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
echo -e "  \033[1;91m update script, zevpn-limit, udpgw-rs & xray-lite\033[1;37m"
fun_bar 'res1'
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
read -n 1 -s -r -p "Press [ Enter ] to back on menu"
menu

###########- COLOR CODE -##############
