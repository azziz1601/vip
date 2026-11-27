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
migrate_ws_rs() {
    # Sudah memakai ws-rs? Skip agar update cepat & idempotent
    if [[ -x /usr/bin/ws ]] && /usr/bin/ws --version 2>&1 | grep -q "ws-rs"; then
        return 0
    fi

    local arch ws_url
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)  ws_url="https://github.com/${GITHUB_REPO}/releases/latest/download/ws-linux-amd64" ;;
        aarch64|arm64) ws_url="https://github.com/${GITHUB_REPO}/releases/latest/download/ws-linux-arm64" ;;
        *) return 0 ;;
    esac

    if (curl -fsSL "$ws_url" -o /tmp/ws.new || wget -q -O /tmp/ws.new "$ws_url"); then
        chmod +x /tmp/ws.new
        if /tmp/ws.new --version 2>&1 | grep -q "ws-rs"; then
            systemctl stop ws >/dev/null 2>&1
            mv -f /tmp/ws.new /usr/bin/ws
            chmod +x /usr/bin/ws
            systemctl restart ws >/dev/null 2>&1
        else
            rm -f /tmp/ws.new
        fi
    else
        rm -f /tmp/ws.new
    fi
}
sync_slowdns() {
    mkdir -p /etc/slowdns /etc/xray
    # Jika /root/slowdns/server.pub sudah ada, pastikan symlink & /etc/xray/dns tersinkron
    if [[ -s /root/slowdns/server.pub ]]; then
        ln -sf /root/slowdns/server.pub /etc/slowdns/server.pub
    fi
    if [[ ! -s /etc/xray/dns ]] && [[ -f /root/slowdns/slowdns.env ]]; then
        local env_dom
        env_dom=$(grep -E '^SLOWDNS_DOMAIN=' /root/slowdns/slowdns.env | head -n1 | cut -d= -f2- | tr -d '"'"'"'')
        if [[ -n "$env_dom" ]]; then
            echo "$env_dom" >/etc/xray/dns
        fi
    fi

    # Jika SlowDNS belum terpasang sama sekali di /root/slowdns, pasang otomatis
    if [[ ! -x /root/slowdns/slowdns ]]; then
        local dom ns_dom my_ip
        dom=$(cat /etc/xray/domain 2>/dev/null || echo "")
        ns_dom=$(cat /etc/xray/dns 2>/dev/null || echo "")
        if [[ -z "$ns_dom" && -n "$dom" ]]; then
            ns_dom="ns.${dom}"
            echo "$ns_dom" >/etc/xray/dns
        fi
        if [[ -n "$ns_dom" ]]; then
            mkdir -p /root/slowdns
            my_ip=$(cat /root/.myip 2>/dev/null || curl -sS ipv4.icanhazip.com 2>/dev/null || echo "auto")
            iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true
            if curl -fsSL -H "Cache-Control: no-cache" "${RAW_REPO}limit/slowdns-linux-amd64.tar.gz?t=$(date +%s)" -o /tmp/slowdns.tar.gz; then
                tar -xzf /tmp/slowdns.tar.gz -C /root/slowdns
                chmod +x /root/slowdns/slowdns /root/slowdns/install.sh
                printf '%s\n%s\n%s\n%s\n' "$my_ip" "53" "$ns_dom" "127.0.0.1:143" | bash /root/slowdns/install.sh install >/dev/null 2>&1 || true
                if [[ -s /root/slowdns/server.pub ]]; then
                    ln -sf /root/slowdns/server.pub /etc/slowdns/server.pub
                fi
            fi
            rm -f /tmp/slowdns.tar.gz
        fi
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

    # 2a1. Sinkronkan PROXY protocol (real IP) di HAProxy & Nginx secara berpasangan + perbaiki cron log
    if [[ -f /etc/haproxy/haproxy.cfg ]] && [[ -f /etc/nginx/conf.d/xray.conf ]] && ! grep -q "send-proxy" /etc/haproxy/haproxy.cfg; then
        cp -f /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak.pp
        cp -f /etc/nginx/conf.d/xray.conf /etc/nginx/conf.d/xray.conf.bak.pp
        if curl -fsSL -H "Cache-Control: no-cache" "${RAW_REPO}limit/haproxy.cfg?t=$(date +%s)" -o /tmp/haproxy.cfg.pp && \
           curl -fsSL -H "Cache-Control: no-cache" "${RAW_REPO}limit/xray.conf?t=$(date +%s)" -o /tmp/xray.conf.pp; then
            sed -i "s/xxx/${domain}/g" /tmp/xray.conf.pp
            mv -f /tmp/xray.conf.pp /etc/nginx/conf.d/xray.conf
            mv -f /tmp/haproxy.cfg.pp /etc/haproxy/haproxy.cfg
            if nginx -t >/dev/null 2>&1 && haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1; then
                systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1
                systemctl reload haproxy >/dev/null 2>&1 || systemctl restart haproxy >/dev/null 2>&1
            else
                mv -f /etc/nginx/conf.d/xray.conf.bak.pp /etc/nginx/conf.d/xray.conf
                mv -f /etc/haproxy/haproxy.cfg.bak.pp /etc/haproxy/haproxy.cfg
            fi
        fi
        rm -f /tmp/haproxy.cfg.pp /tmp/xray.conf.pp
    fi
    if [[ -f /etc/cron.d/log.nginx ]] && grep -q "\*/1 " /etc/cron.d/log.nginx; then
        echo "0 */6 * * * root [ -f /var/log/nginx/access.log ] && truncate -s 0 /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    fi
    if [[ -f /etc/cron.d/log.xray ]] && grep -q "\*/1 " /etc/cron.d/log.xray; then
        echo "0 */6 * * * root [ -f /var/log/xray/access.log ] && truncate -s 0 /var/log/xray/access.log" >/etc/cron.d/log.xray
    fi

    # 2a2. Pastikan izin log Xray dimiliki www-data agar xray.service bisa menulis access/error log
    if [[ -d /var/log/xray ]]; then
        touch /var/log/xray/access.log /var/log/xray/error.log 2>/dev/null || true
        chown -R www-data:www-data /var/log/xray 2>/dev/null || true
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

    # 2c. Perbarui /usr/bin/limit-ip ke versi aman (notify-only, tanpa hapus akun)
    if curl -fsSL -H "Cache-Control: no-cache" "${RAW_REPO}limit/limit-ip?t=$(date +%s)" -o /tmp/limit-ip.new; then
        chmod +x /tmp/limit-ip.new
        mv -f /tmp/limit-ip.new /usr/bin/limit-ip
        for svc in vmip vlip trip; do
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                systemctl restart "$svc" >/dev/null 2>&1 || true
            fi
        done
    fi
    rm -f /tmp/limit-ip.new

    # 2d. Sinkronkan map $client_real_ip (CF-Connecting-IP + real IP direct) pada Nginx
    if [[ -f /etc/nginx/nginx.conf ]] && ! grep -q "client_real_ip" /etc/nginx/nginx.conf; then
        cp -f /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.cf
        cp -f /etc/nginx/conf.d/xray.conf /etc/nginx/conf.d/xray.conf.bak.cf 2>/dev/null || true
        if curl -fsSL -H "Cache-Control: no-cache" "${RAW_REPO}limit/nginx.conf?t=$(date +%s)" -o /tmp/nginx.conf.cf && \
           curl -fsSL -H "Cache-Control: no-cache" "${RAW_REPO}limit/xray.conf?t=$(date +%s)" -o /tmp/xray.conf.cf; then
            sed -i "s/xxx/${domain}/g" /tmp/xray.conf.cf
            mv -f /tmp/nginx.conf.cf /etc/nginx/nginx.conf
            mv -f /tmp/xray.conf.cf /etc/nginx/conf.d/xray.conf
            if nginx -t >/dev/null 2>&1; then
                systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1
            else
                mv -f /etc/nginx/nginx.conf.bak.cf /etc/nginx/nginx.conf
                [[ -f /etc/nginx/conf.d/xray.conf.bak.cf ]] && mv -f /etc/nginx/conf.d/xray.conf.bak.cf /etc/nginx/conf.d/xray.conf
            fi
        fi
        rm -f /tmp/nginx.conf.cf /tmp/xray.conf.cf
    fi

    # Catatan: /etc/xray/config.json sengaja tidak disentuh saat update demi keamanan data akun.
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

    # Migrasi otomatis /usr/bin/ws ke ws-rs dari GitHub Releases (skip jika sudah terpasang)
    migrate_ws_rs

    # Pasang / sinkronkan SlowDNS (NS & Pub Key)
    sync_slowdns

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
echo -e "  \033[1;91m update script, zevpn-limit, udpgw-rs, ws-rs & xray-lite\033[1;37m"
fun_bar 'res1'
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
read -n 1 -s -r -p "Press [ Enter ] to back on menu"
menu

###########- COLOR CODE -##############
