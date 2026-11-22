#!/bin/bash
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
red() { echo -e "\\033[32;1m${*}\\033[0m"; }
GITHUB_REPO="${GITHUB_REPO:-azziz1601/vip}"
RAW_REPO="https://raw.githubusercontent.com/${GITHUB_REPO}/main/"
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
res1() {
    wget -q "${RAW_REPO}limit/menu.zip"
    unzip -o -q menu.zip
    chmod +x menu/*
    mv -f menu/* /usr/local/sbin
    rm -f /usr/local/sbin/{addss,cekss,delss,m-ssws,renewss,trialss,user-ss}
    rm -rf menu menu.zip

    # Migrasi / perbarui daemon Rust zevpn-limit otomatis dari GitHub Releases
    curl -fsSL "${RAW_REPO}limit/limit.sh" -o /tmp/zevpn-limit-update.sh
    chmod +x /tmp/zevpn-limit-update.sh
    GITHUB_REPO="$GITHUB_REPO" bash /tmp/zevpn-limit-update.sh
    rm -f /tmp/zevpn-limit-update.sh

    # Migrasi otomatis ke UDPGW Rust v1.2.0 (skip jika sudah terpasang)
    update_udpgw_rust

    rm -rf update.sh
}
netfilter-persistent
clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " \e[1;97;101m          UPDATE SCRIPT    \e[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
echo -e "  \033[1;91m update script, zevpn-limit & udpgw-rs\033[1;37m"
fun_bar 'res1'
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
read -n 1 -s -r -p "Press [ Enter ] to back on menu"
menu

###########- COLOR CODE -##############
