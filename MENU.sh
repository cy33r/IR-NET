#!/bin/bash
# MENU.SH - ADVANCED UBUNTU MANAGEMENT SCRIPT
# FULL VERSION - ALL FUNCTIONS INCLUDED

LRM=$'\u200E'
RLM=$'\u200F'

# --- Added helpers for Stubby hardening ---
_ensure_stubby_listen() {
    local conf="/etc/stubby/stubby.yml"
    [ -f "$conf" ] || return 0
    if ! grep -qE '^\s*listen_addresses:\s*\[? *127\.0\.0\.1' "$conf"; then
        sed -i '1ilisten_addresses:\n  - 127.0.0.1\n  - ::1\n' "$conf"
    fi
}

_replace_stubby_upstreams_safely() {
    local conf="/etc/stubby/stubby.yml"
    local block="$1" 
    [ -f "$conf" ] || return 1
    awk -v RS= -v ORS="\n\n" -v newblock="$block" '
    /^upstream_recursive_servers:/ {
        print "upstream_recursive_servers:\n" newblock;
        next
    }
    { print }
    ' "$conf" > "${conf}.tmp" && mv "${conf}.tmp" "$conf"
}

# CHECK FOR ROOT USER
if [ "$(id -u)" -ne 0 ]; then
  echo "THIS SCRIPT MUST BE RUN AS ROOT."
  echo "PLEASE USE COMMAND 'sudo bash MENU.sh'."
  exit 1
fi

# --- START: THEME-AWARE DYNAMIC COLOR PALETTE ---
CONFIG_DIR="/etc/irnet" 
THEME_CONF_FILE="${CONFIG_DIR}/theme.conf"

apply_theme() {
    local theme="CYAN" 
    if [ -f "$THEME_CONF_FILE" ]; then
        theme=$(cat "$THEME_CONF_FILE")
    fi

    case "${theme^^}" in
        "MAGENTA")
            C_RESET=$'\e[0m'; C_RED=$'\e[0;31m'; C_GREEN=$'\e[0;32m'; C_YELLOW=$'\e[0;33m'; C_BLUE=$'\e[0;34m'; C_MAGENTA=$'\e[0;35m'; C_CYAN=$'\e[0;36m'; C_WHITE=$'\e[0;37m'
            B_BLUE=$'\e[1;35m'; B_MAGENTA=$'\e[1;35m'; B_CYAN=$'\e[1;35m'; B_YELLOW=$'\e[1;33m'
            R=$'\e[0;31m'; G=$'\e[0;32m'; Y=$'\e[0;33m'; B=$'\e[0;34m'; C=$'\e[0;36m'; W=$'\e[1;37m'; D=$'\e[0;90m'; N=$'\e[0m'; P=$'\e[1;35m'
            ;;
        "YELLOW")
            C_RESET=$'\e[0m'; C_RED=$'\e[0;31m'; C_GREEN=$'\e[0;32m'; C_YELLOW=$'\e[0;33m'; C_BLUE=$'\e[0;34m'; C_MAGENTA=$'\e[0;35m'; C_CYAN=$'\e[0;36m'; C_WHITE=$'\e[0;37m'
            B_BLUE=$'\e[1;33m'; B_MAGENTA=$'\e[1;33m'; B_CYAN=$'\e[1;33m'; B_YELLOW=$'\e[1;33m'
            R=$'\e[0;31m'; G=$'\e[0;32m'; Y=$'\e[0;33m'; B=$'\e[0;34m'; C=$'\e[0;36m'; W=$'\e[1;37m'; D=$'\e[0;90m'; N=$'\e[0m'; P=$'\e[1;35m'
            ;;
        "FOREST")
            C_RESET=$'\e[0m'; C_RED=$'\e[0;31m'; C_GREEN=$'\e[0;32m'; C_YELLOW=$'\e[0;33m'; C_BLUE=$'\e[0;32m'; C_MAGENTA=$'\e[0;35m'; C_CYAN=$'\e[0;36m'; C_WHITE=$'\e[0;37m'
            B_BLUE=$'\e[1;32m'; B_MAGENTA=$'\e[1;35m'; B_CYAN=$'\e[1;32m'; B_YELLOW=$'\e[1;33m'
            R=$'\e[0;31m'; G=$'\e[0;32m'; Y=$'\e[0;33m'; B=$'\e[0;32m'; C=$'\e[0;36m'; W=$'\e[1;37m'; D=$'\e[0;90m'; N=$'\e[0m'; P=$'\e[1;35m'
            ;;
        "MATRIX")
            C_RESET=$'\e[0m'; C_RED=$'\e[1;31m'; C_GREEN=$'\e[1;32m'; C_YELLOW=$'\e[1;33m'; C_BLUE=$'\e[1;32m'; C_MAGENTA=$'\e[1;32m'; C_CYAN=$'\e[1;32m'; C_WHITE=$'\e[1;37m'
            B_BLUE=$'\e[1;32m'; B_MAGENTA=$'\e[1;32m'; B_CYAN=$'\e[1;32m'; B_YELLOW=$'\e[1;33m'
            R=$'\e[1;31m'; G=$'\e[1;32m'; Y=$'\e[1;33m'; B=$'\e[1;32m'; C=$'\e[1;32m'; W=$'\e[1;37m'; D=$'\e[0;90m'; N=$'\e[0m'; P=$'\e[1;35m'
            ;;
        *) # Default to CYAN
            C_RESET=$'\e[0m'; C_RED=$'\e[0;31m'; C_GREEN=$'\e[0;32m'; C_YELLOW=$'\e[0;33m'; C_BLUE=$'\e[0;34m'; C_MAGENTA=$'\e[0;35m'; C_CYAN=$'\e[0;36m'; C_WHITE=$'\e[0;37m'
            B_BLUE=$'\e[1;34m'; B_MAGENTA=$'\e[1;35m'; B_CYAN=$'\e[1;36m'; B_YELLOW=$'\e[1;33m'
            R=$'\e[0;31m'; G=$'\e[0;32m'; Y=$'\e[0;33m'; B=$'\e[0;34m'; C=$'\e[0;36m'; W=$'\e[1;37m'; D=$'\e[0;90m'; N=$'\e[0m'; P=$'\e[1;35m'
            ;;
    esac
}

# #############################################################################
# --- START OF CORE FRAMEWORK ---
# #############################################################################

readonly LOG_FILE="/var/log/network_optimizer.log"
readonly BACKUP_DIR="/var/backups/network_optimizer"
readonly CONFIG_DIR="/etc/irnet" 
readonly TARGET_DNS=("9.9.9.9" "149.112.112.112")
readonly MIN_MTU=576
readonly MAX_MTU=9000

declare -g SYSTEM_CPU_CORES
declare -g SYSTEM_TOTAL_RAM
declare -g SYSTEM_OPTIMAL_BACKLOG
declare -g SYSTEM_OPTIMAL_MEM
declare -g PRIMARY_INTERFACE

log_message() {
    local level="$1"
    local message="$2"
    local timestamp color
    printf -v timestamp '%(%Y-%m-%d %H:%M:%S)T' -1
    case "$level" in
        INFO|اطلاعات) color="$C_BLUE"; level="INFO" ;;
        WARNING|هشدار) color="$C_YELLOW"; level="WARNING" ;;
        ERROR|خطا) color="$C_RED"; level="ERROR" ;;
        SUCCESS|موفقیت) color="$C_GREEN"; level="SUCCESS" ;;
        *) color="$C_RESET" ;;
    esac

    local upper_message="${message^^}"
    local log_line="[$timestamp] [$level] $upper_message"
    printf "%s%s%s\n" "$color" "$log_line" "$C_RESET" | tee -a "$LOG_FILE"
}

create_backup() {
    local file_path="$1"
    if [ ! -f "$file_path" ]; then
        log_message "INFO" "FILE $file_path NOT FOUND FOR BACKUP; SKIPPED."
        return 1
    fi
    local backup_name
    printf -v backup_name '%s.bak.%(%s)T' "$(basename "$file_path")" -1
    if cp -f "$file_path" "$BACKUP_DIR/$backup_name" 2>/dev/null; then
        log_message "SUCCESS" "BACKUP OF $file_path CREATED AT $BACKUP_DIR/$backup_name."
        echo "$BACKUP_DIR/$backup_name"
        return 0
    else
        log_message "ERROR" "BACKUP FAILED FOR $file_path."
        return 1
    fi
}

restore_backup() {
    local original_file="$1"
    local backup_file="$2"
    if cp -f "$backup_file" "$original_file" 2>/dev/null; then
        log_message "SUCCESS" "FILE $original_file RESTORED FROM BACKUP."
        return 0
    else
        log_message "ERROR" "FAILED TO RESTORE FROM BACKUP."
        return 1
    fi
}

check_service_status() {
    local service_name="$1"
    if systemctl is-active --quiet "$service_name"; then
        log_message "SUCCESS" "SERVICE $service_name IS ACTIVE AND RUNNING."
    else
        log_message "ERROR" "SERVICE $service_name FAILED TO RUN. PLEASE CHECK MANUALLY: SYSTEMCTL STATUS $service_name"
    fi
}

handle_interrupt() {
    log_message "WARNING" "SCRIPT INTERRUPTED. CLEANING UP..."
    stty sane 
    local pids
    pids=$(jobs -p 2>/dev/null)
    if [[ -n "$pids" ]]; then
        echo "$pids" | xargs -r kill -TERM 2>/dev/null || true
        sleep 1
        echo "$pids" | xargs -r kill -KILL 2>/dev/null || true
    fi
    rm -f /tmp/setup_*.sh /tmp/dns_test_$$_* /tmp/conn_test_$$_* /tmp/mirror_speeds_$$ 2>/dev/null
    exit 130
}

init_environment() {
    export LC_ALL=C
    export LANG=C
    export DEBIAN_FRONTEND=noninteractive
    export APT_LISTCHANGES_FRONTEND=none

    mkdir -p "$BACKUP_DIR" "$(dirname "$LOG_FILE")" "$CONFIG_DIR" 2>/dev/null
    chmod 700 "$BACKUP_DIR" "$CONFIG_DIR" 2>/dev/null
    : >> "$LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null

    trap 'handle_interrupt' INT TERM

    PRIMARY_INTERFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
}

check_ipv6_status() {
    if sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q "1"; then
        echo "DISABLED"
    else
        echo "ENABLED"
    fi
}

check_ping_status() {
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        if iptables -C ufw-before-input -p icmp --icmp-type echo-request -j DROP &>/dev/null || \
           iptables -C INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null || \
           ip6tables -C ufw6-before-input -p icmpv6 --icmpv6-type echo-request -j DROP &>/dev/null || \
           ip6tables -C INPUT -p icmpv6 --icmpv6-type echo-request -j DROP &>/dev/null; then
            echo "BLOCKED"
        else
            echo "ALLOWED"
        fi
    else
        echo "ALLOWED"
    fi
}

check_internet_connection() {
    local test_ips=("8.8.8.8" "1.1.1.1" "9.9.9.9")
    local pids=()
    local success=0
    for ip in "${test_ips[@]}"; do
        timeout 3 ping -c1 -W2 "$ip" &>/dev/null &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            success=1
            break
        fi
    done
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    return $((1 - success))
}

wait_for_dpkg_lock() {
    local max_wait=300
    local waited=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        if [[ "$waited" -ge "$max_wait" ]]; then
            log_message "ERROR" "TIMEOUT WAITING FOR PACKAGE MANAGER."
            log_message "ERROR" "PLEASE MANUALLY KILL THE APT/DPKG PROCESS AND TRY AGAIN."
            return 1
        fi
        if [[ $((waited % 30)) -eq 0 ]]; then
            log_message "WARNING" "PACKAGE MANAGER IS LOCKED. WAITING... (${waited}S/${max_wait}S)"
        fi
        sleep 5
        waited=$((waited + 5))
    done
    return 0
}

reset_environment() {
    log_message "INFO" "RESETTING ENVIRONMENT AFTER PACKAGE INSTALLATION..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get clean 2>/dev/null || true
        rm -f /var/lib/dpkg/lock* /var/lib/apt/lists/lock /var/cache/apt/archives/lock 2>/dev/null || true
    fi
    reset 2>/dev/null || true
    stty sane 2>/dev/null || true
    hash -r 2>/dev/null || true
    [[ -f /etc/environment ]] && source /etc/environment 2>/dev/null || true
    [[ -f ~/.bashrc ]] && source ~/.bashrc 2>/dev/null || true
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
    
    sleep 3
    log_message "SUCCESS" "ENVIRONMENT RESET COMPLETED."
    return 0
}

install_dependencies() {
    log_message "INFO" "CHECKING AND INSTALLING REQUIRED DEPENDENCIES..."
    if ! check_internet_connection; then
        log_message "ERROR" "NO INTERNET CONNECTION AVAILABLE."
        return 1
    fi

    local deps=("curl" "wget" "socat" "ethtool" "net-tools" "dnsutils" "mtr-tiny" "iperf3" "jq" "bc" "lsb-release" "netcat-openbsd" "nmap" "fping" "uuid-runtime" "iptables-persistent" "python3" "python3-pip" "fail2ban" "chkrootkit" "unzip" "rkhunter" "lynis" "htop" "btop" "ncdu" "iftop" "git" "certbot" "xtables-addons-common" "geoip-database" "gnupg" "whois" "ipset")
    local missing_deps=()

    for dep in "${deps[@]}"; do
        local cmd_name="$dep"
        [[ "$dep" == "dnsutils" ]] && cmd_name="dig"
        [[ "$dep" == "net-tools" ]] && cmd_name="ifconfig"
        [[ "$dep" == "mtr-tiny" ]] && cmd_name="mtr"
        [[ "$dep" == "netcat-openbsd" ]] && cmd_name="nc"
        [[ "$dep" == "uuid-runtime" ]] && cmd_name="uuidgen"
        [[ "$dep" == "iptables-persistent" ]] && cmd_name="netfilter-persistent"
        [[ "$dep" == "xtables-addons-common" ]] && cmd_name="xtables-addons-info"

        if ! command -v "$cmd_name" &>/dev/null; then
            if [[ "$dep" == "netcat-openbsd" ]] && (command -v "ncat" >/dev/null || command -v "netcat" >/dev/null); then
                continue
            fi
            missing_deps+=("$dep")
        fi
    done

    if [[ "${#missing_deps[@]}" -gt 0 ]]; then
        log_message "WARNING" "INSTALLING MISSING DEPENDENCIES: ${missing_deps[*]}"
        if ! wait_for_dpkg_lock; then
            log_message "ERROR" "COULD NOT ACQUIRE PACKAGE LOCK."
            return 1
        fi

        apt-get update -qq

        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" "${missing_deps[@]}"; then
            log_message "ERROR" "FAILED TO INSTALL SOME DEPENDENCIES. PLEASE TRY INSTALLING THEM MANUALLY."
            return 1
        else
            log_message "SUCCESS" "DEPENDENCIES INSTALLED SUCCESSFULLY."
            if ! reset_environment; then
                return 1
            fi
        fi
    else
        log_message "INFO" "ALL DEPENDENCIES ARE ALREADY INSTALLED."
    fi
    return 0
}

fix_etc_hosts() {
    local host_path="${1:-/etc/hosts}"
    local hostname_cached
    log_message "INFO" "STARTING TO FIX THE HOSTS FILE..."
    hostname_cached=$(hostname 2>/dev/null || echo "localhost")
    local backup_path
    if ! backup_path=$(create_backup "$host_path"); then
        log_message "ERROR" "FAILED TO CREATE BACKUP OF HOSTS FILE."
        return 1
    fi
    if lsattr "$host_path" 2>/dev/null | grep -q 'i'; then
        log_message "WARNING" "FILE $host_path IS IMMUTABLE. ATTEMPTING TO MAKE IT MUTABLE..."
        if ! chattr -i "$host_path" 2>/dev/null; then
            log_message "ERROR" "FAILED TO REMOVE IMMUTABLE ATTRIBUTE."
            return 1
        fi
    fi
    if [[ ! -w "$host_path" ]]; then
        log_message "ERROR" "CANNOT WRITE TO $host_path. CHECK PERMISSIONS."
        return 1
    fi
    if ! grep -q "$hostname_cached" "$host_path" 2>/dev/null; then
        local hostname_entry="127.0.1.1 $hostname_cached"
        if printf '%s\n' "$hostname_entry" >> "$host_path"; then
            log_message "SUCCESS" "HOSTNAME ENTRY ADDED TO HOSTS FILE."
        else
            log_message "ERROR" "FAILED TO ADD HOSTNAME ENTRY."
            restore_backup "$host_path" "$backup_path"
            return 1
        fi
    else
        log_message "INFO" "HOSTNAME ENTRY ALREADY PRESENT."
    fi
    return 0
}

_verify_dns_settings() {
    local expected_dns1="$1"
    local expected_dns2="$2"
    log_message "INFO" "VERIFYING DNS SETTINGS..."
    sleep 1

    local override_file="/etc/systemd/resolved.conf.d/99-irnet-dns.conf"
    local active_dns=""
    if [ -r "$override_file" ]; then
        active_dns="$(awk -F'=' '/^(DNS|FallbackDNS)=/{
            for(i=2;i<=NF;i++){print $i}
        }' "$override_file" | tr ' ' '\n' | sed '/^$/d' \
          | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | awk '!seen[$0]++' | xargs)"
    fi

    if [ -z "$active_dns" ]; then
        if command -v resolvectl &>/dev/null; then
            active_dns+="$(resolvectl status 2>/dev/null | awk -F': ' '
                BEGIN{in_global=0}
                /^Global$/ {in_global=1; next}
                /^Link/ {in_global=0}
                in_global && /^ *DNS Servers:/ {print $2; exit}
            ' )"
            active_dns+=" "
            if [ -n "$PRIMARY_INTERFACE" ]; then
                active_dns+="$(resolvectl dns "$PRIMARY_INTERFACE" 2>/dev/null | awk -F': ' 'NF>1{print $2}')"
            fi
        fi
        if [ -z "$(echo "$active_dns" | tr -d '[:space:]')" ]; then
            active_dns+=" $(grep -E '^\s*nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | xargs)"
        fi
        active_dns=$( echo "$active_dns" | tr ' ' '\n' \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
            | awk '!seen[$0]++' | xargs )
    fi

    echo -e "\n${B_CYAN}--- DNS VERIFICATION RESULT ---${N}"
    echo -e "${C_WHITE}EXPECTED DNS:${N} ${G}${expected_dns1}${N}${expected_dns2:+ " AND ${G}${expected_dns2}${N}"}"
    echo -e "${C_WHITE}ACTIVE DNS:${N} ${Y}${active_dns:-«NONE»}${N}"

    local ok1=false ok2=true
    [[ " $active_dns " == *" $expected_dns1 "* ]] && ok1=true
    if [ -n "$expected_dns2" ]; then
        ok2=false
        [[ " $active_dns " == *" $expected_dns2 "* ]] && ok2=true
    fi

    if $ok1 && $ok2; then
        log_message "SUCCESS" "DNS VERIFICATION PASSED."
        return 0
    else
        log_message "ERROR" "DNS VERIFICATION FAILED."
        return 1
    fi
}

apply_dns_persistent() {
    local dns1="$1" dns2="$2"
    [ -z "$dns1" ] && { log_message "ERROR" "DNS ADDRESS CANNOT BE EMPTY."; return 1; }

    if systemctl is-active --quiet systemd-resolved; then
        log_message "INFO" "SYSTEMD-RESOLVED DETECTED. APPLYING DNS SECURELY..."
        local override_dir="/etc/systemd/resolved.conf.d"
        local override_file="${override_dir}/99-irnet-dns.conf"
        
        mkdir -p "$override_dir"
        
        tee "$override_file" > /dev/null <<EOF
# Settings applied by IR-NET Script
[Resolve]
DNS=${dns1}${dns2:+ ${dns2}}
FallbackDNS=
Domains=~.
EOF
        
        systemctl restart systemd-resolved
        if [ -L /etc/resolv.conf ]; then
            target="$(readlink -f /etc/resolv.conf)"
            if [[ "$target" != "/run/systemd/resolve/stub-resolv.conf" && "$target" != "/run/systemd/resolve/resolv.conf" ]]; then
                ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
            fi
        else
            ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
        fi
        log_message "SUCCESS" "DNS APPLIED SUCCESSFULLY. SYSTEMD-RESOLVED RESTARTED."
        
    else
        log_message "INFO" "FALLING BACK TO /etc/resolv.conf METHOD..."
        local resolv_conf="/etc/resolv.conf"
        create_backup "$resolv_conf"
        chattr -i "$resolv_conf" 2>/dev/null || true
        {
          echo "# MANAGED BY MENU.SH"
          echo "nameserver ${dns1}"
          [ -n "$dns2" ] && echo "nameserver ${dns2}"
        } > "$resolv_conf"
        chattr +i "$resolv_conf" 2>/dev/null || true
        log_message "SUCCESS" "DNS APPLIED TO $resolv_conf (LOCKED)."
    fi

    _verify_dns_settings "$dns1" "$dns2"
}

is_valid_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$ || "$ip" =~ ^(([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])) || "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# --- BANNER (UPDATED WITH NEW TEAM NAMES) ---
show_banner() {
    local border title_line line1 line2 line3

    # Total Width: 64 Characters
    # Layout: | (Left: 36 chars) | (Right: 25 chars) |

    border="${B_CYAN}+--------------------------------------------------------------+${C_RESET}"

    # Title Line
    title_line="${B_CYAN}|${C_WHITE}  ADVANCED UBUNTU LINUX MANAGEMENT AND OPTIMIZATION PRO       ${B_CYAN}|${C_RESET}"
    
    # Row 1: AMIR ALI
    # Left: " CREATED BY: AMIR ALI" (21 chars) + 15 spaces = 36
    # Right: " TELEGRAM: T.ME/CY3ER" (21 chars) + 4 spaces = 25
    line1="${B_CYAN}|${C_YELLOW} CREATED BY: ${C_WHITE}AMIR ALI               ${B_CYAN}|${C_YELLOW} TELEGRAM: ${C_WHITE}T.ME/CY3ER    ${B_CYAN}|${C_RESET}"

    # Row 2: NIMA
    # Left: " COLLABORATOR: NIMA" (19 chars) + 17 spaces = 36
    # Right: " TELEGRAM: T.ME/# _4L" (21 chars) + 4 spaces = 25
    line2="${B_CYAN}|${C_YELLOW} COLLABORATOR: ${C_WHITE}NIMA                 ${B_CYAN}|${C_YELLOW} TELEGRAM: ${C_WHITE}T.ME/# _4L    ${B_CYAN}|${C_RESET}"

    # Row 3: MOBIN
    # Left: " COLLABORATOR: MOBIN" (20 chars) + 16 spaces = 36
    # Right: " TELEGRAM: T.ME/#" (17 chars) + 8 spaces = 25
    line3="${B_CYAN}|${C_YELLOW} COLLABORATOR: ${C_WHITE}MOBIN                ${B_CYAN}|${C_YELLOW} TELEGRAM: ${C_WHITE}T.ME/#        ${B_CYAN}|${C_RESET}"

    # Print All
    echo -e "$border"
    echo -e "$title_line"
    echo -e "$border"
    echo -e "$line1"
    echo -e "$line2"
    echo -e "$line3"
    echo -e "$border"
    echo ""
}

# --- SYSTEM STATUS ---
show_enhanced_system_status() {
    local ipv4_file="/tmp/ip4_$$"
    local ipv6_file="/tmp/ip6_$$"
    local isp_file="/tmp/isp_$$"
    
    (
        local services=("https://ipv4.icanhazip.com" "https://api.ipify.org" "https://ifconfig.me")
        local ip="N/A"
        for service in "${services[@]}"; do
            ip=$(curl -s --max-time 1 --ipv4 "$service" | xargs)
            if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "$ip" > "$ipv4_file"
                return
            fi
        done
        echo "N/A" > "$ipv4_file"
    ) &

    (
        local services=("https://ipv6.icanhazip.com" "https://api64.ipify.org")
        local ip="N/A"
        for service in "${services[@]}"; do
            ip=$(curl -s --max-time 1 --ipv6 "$service" | xargs)
            if [[ "$ip" =~ ^([0-9a-fA-F:]+:+)+[0-9a-fA-F]+$ ]]; then
                echo "$ip" > "$ipv6_file"
                return
            fi
        done
        echo "N/A" > "$ipv6_file"
    ) &

    (
        local prov
        prov=$(curl -fs --max-time 1 http://ip-api.com/line?fields=isp 2>/dev/null | tr -d '\n')
        [ -z "$prov" ] && prov="N/A"
        echo "$prov" > "$isp_file"
    ) &

    wait

    local public_ipv4=$(cat "$ipv4_file" 2>/dev/null || echo "N/A")
    local public_ipv6=$(cat "$ipv6_file" 2>/dev/null || echo "N/A")
    local provider=$(cat "$isp_file" 2>/dev/null || echo "N/A")
    
    rm -f "$ipv4_file" "$ipv6_file" "$isp_file"

    get_visual_length() {
        local clean_string
        clean_string=$(echo -e "$1" | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' | tr -d "$LRM$RLM")
        echo "${#clean_string}"
    }

    local cpu_model cpu_cores cpu_usage mem_total mem_used mem_percent load_avg uptime_str ubuntu_version
    cpu_model=$(lscpu | awk -F: '/^Model name/ {print $2}' | xargs)
    cpu_model_upper="${cpu_model^^}"
    cpu_cores=$(nproc)
    cpu_usage=$(top -bn1 | awk -F',' '/Cpu\(s\)/{gsub(/ /,""); print $1}' | awk -F: '{print $2+0}' 2>/dev/null || echo "0")
    mem_total=$(free -h | awk '/^Mem:/{print $2}')
    mem_used=$(free -h | awk '/^Mem:/{print $3}')
    mem_total_disp="$(printf '%s' "$mem_total" | sed 's/Mi/MI/g; s/Gi/GI/g; s/Ki/KI/g; s/MiB/MIB/g; s/GiB/GIB/g; s/KiB/KIB/g')"
    mem_used_disp="$(printf '%s' "$mem_used" | sed 's/Mi/MI/g; s/Gi/GI/g; s/Ki/KI/g; s/MiB/MIB/g; s/GiB/GIB/g; s/KiB/KIB/g')"
    mem_percent=$(free | awk '/^Mem:/{printf "%.0f", ($3/$2)*100.0}')
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs | cut -d, -f1)
    uptime_str=$(uptime -p 2>/dev/null | sed 's/^up //')
    uptime_upper="${uptime_str^^}"
    ubuntu_version=$(lsb_release -sr 2>/dev/null || echo 'N/A')
    
    local ipv6_status_val ping_status_val provider_upper current_mirror_host_upper private_ips dns_servers
    ipv6_status_val=$(check_ipv6_status)
    ping_status_val=$(check_ping_status)
    
    provider_upper="${provider^^}"
    current_mirror_host=$(awk -F/ '/^deb /{print $3; exit}' /etc/apt/sources.list 2>/dev/null)
    current_mirror_host_upper="${current_mirror_host^^}"
    private_ips=$(ip -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -E '^(10\.)|(172\.(1[6-9]|2[0-9]|3[0-1])\.)|(192\.168\.)' | tr '\n' ' ' | xargs); [ -z "$private_ips" ] && private_ips="N/A"
    
    local override_file="/etc/systemd/resolved.conf.d/99-irnet-dns.conf"
    if [ -r "$override_file" ]; then dns_servers=$(awk -F'=' '/^(DNS|FallbackDNS)=/{for(i=2;i<=NF;i++)print $i}' "$override_file" | xargs); else dns_servers=$(awk "/^nameserver/{print \$2}" /etc/resolv.conf | xargs); [ -z "$dns_servers" ] && dns_servers="N/A"; fi

    local ipv6_display="$ipv6_status_val"; [[ "$ipv6_status_val" == "ENABLED" ]] && ipv6_display="${G}${ipv6_display}${N}" || ipv6_display="${R}${ipv6_display}${N}"
    local ping_display="$ping_status_val"; [[ "$ping_status_val" == "ALLOWED" ]] && ping_display="${G}${ping_display}${N}" || ping_display="${R}${ping_display}${N}"
    local private_ips_display="$(echo "$private_ips" | sed 's/ / '"$LRM"'/g')"
    local public_ipv4_display="$LRM$public_ipv4"
    local public_ipv6_display="$LRM$public_ipv6"
    local dns_servers_display="$(echo "$dns_servers" | sed 's/ / '"$LRM"'/g')"

    local labels=( "CPU" "PERFORMANCE" "MEMORY" "UPTIME" "LOAD AVERAGE" "IPV6 STATUS" "PING" "ACTIVE DNS" "PROVIDER" "MIRROR" "UBUNTU VERSION" "PRIVATE IP(S)" "PUBLIC IPV4" "PUBLIC IPV6" )
    local values=(
        "${C_WHITE}${cpu_model_upper}${N} ${D}(${cpu_cores} CORES)${N}"
        "${G}${cpu_usage%%%}${N}"
        "${C_WHITE}${mem_used_disp}${N}/${D}${mem_total_disp}${N} (${Y}${mem_percent%%%}${N}%)"
        "${C_WHITE}${uptime_upper}${N}"
        "${C_WHITE}${load_avg}${N}"
        "$ipv6_display"
        "$ping_display"
        "$dns_servers_display"
        "$provider_upper"
        "$current_mirror_host_upper"
        "${C_WHITE}${ubuntu_version}${N}"
        "${G}${private_ips_display}${N}"
        "${G}${public_ipv4_display}${N}"
        "${G}${public_ipv6_display}${N}"
    )

    local max_label_len=0
    for label in "${labels[@]}"; do
        (( ${#label} > max_label_len )) && max_label_len=${#label}
    done

    local terminal_width; terminal_width=$(tput cols 2>/dev/null || echo 80)
    local max_value_width=$(( terminal_width - max_label_len - 7 )); [[ $max_value_width -lt 20 ]] && max_value_width=20

    printf "${B_CYAN}+%s+\n" "$(printf -- '-%.0s' $(seq 1 $((max_label_len + max_value_width + 5)) ))"
    for i in "${!labels[@]}"; do
        local label="${labels[$i]}"; local value="${values[$i]}"
        local clean_value; clean_value=$(echo -e "$value" | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' | tr -d "$LRM$RLM")

        if (( ${#clean_value} > max_value_width )); then
            local value_part; value_part=$(echo -e "${value}" | cut -c 1-$((max_value_width - 3)))
            value="${value_part}...${N}"
        fi

        local visual_value_len; visual_value_len=$(get_visual_length "$value")

        printf "${B_CYAN}|${C_YELLOW} %s" "$label"
        printf "%*s" "$((max_label_len - ${#label}))" ""
        printf " ${B_CYAN}|${C_WHITE} %s" "$value"

        local padding=$(( max_value_width - visual_value_len )); [[ $padding -lt 0 ]] && padding=0
        printf "%*s" "$padding" ""
        printf " ${B_CYAN}|\n"
    done
    printf "${B_CYAN}+%s+\n${C_RESET}" "$(printf -- '-%.0s' $(seq 1 $((max_label_len + max_value_width + 5)) ))"
}


# --- PROGRESS BAR FUNCTION ---
progress_bar() {
    local msg="$1"
    local total_time="$2"
    local width=30
    local delay
    
    # Calculate delay
    if command -v bc &>/dev/null; then
        delay=$(echo "scale=3; $total_time/100" | bc -l)
    else
        delay="0.02"
    fi

    # Hide Cursor
    tput civis
    
    for ((i=0; i<=100; i++)); do
        local filled=$((i*width/100))
        local empty=$((width-filled))
        
        # Color Logic
        local color="$C_YELLOW"
        if [ $i -gt 70 ]; then color="$C_GREEN"; fi
        
        # Print Bar
        printf "\r${C_CYAN}%-30s ${C_RESET}[" "$msg"
        printf "${color}"
        printf "%${filled}s" | tr ' ' '█'
        printf "${C_WHITE}"
        printf "%${empty}s" | tr ' ' '░'
        printf "${C_RESET}] ${color}%3d%%${C_RESET} " "$i"
        
        sleep "$delay"
    done
    
    # Finished Message
    printf "\n${B_GREEN}✅ LOADED SUCCESSFULLY.${C_RESET}\n"
    
    # Restore Cursor
    tput cnorm
}

# --- MENU 1 FUNCTIONS (VPN PANELS) ---

manage_txui_panel() {
    while true; do
        clear
        log_message "INFO" "--- TX-UI PANEL MANAGEMENT ---"
        echo -e "${B_CYAN}--- INSTALL / UPDATE TX-UI PANEL ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "1" "ONLINE INSTALLATION"
        printf "  ${C_YELLOW}%2d)${B_CYAN}  %s\n" "2" "OFFLINE INSTALLATION (FROM /ROOT)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                log_message "INFO" "STARTING ONLINE INSTALLATION..."
                bash <(curl -Ls https://raw.githubusercontent.com/AghayeCoder/tx-ui/master/install.sh)
                log_message "SUCCESS" "ONLINE INSTALLATION SCRIPT EXECUTED."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                # --- ARCHITECTURE DETECTION ---
                ARCH=$(uname -m)
                case "${ARCH}" in
                    x86_64 | x64 | amd64) XUI_ARCH="amd64" ;;
                    i*86 | x86) XUI_ARCH="386" ;;
                    armv8* | armv8 | arm64 | aarch64) XUI_ARCH="arm64" ;;
                    armv7* | armv7) XUI_ARCH="armv7" ;;
                    armv6* | armv6) XUI_ARCH="armv6" ;;
                    armv5* | armv5) XUI_ARCH="armv5" ;;
                    s390x) echo 's390x' ;;
                    *) XUI_ARCH="amd64" ;;
                esac

                local filename="x-ui-linux-${XUI_ARCH}.tar.gz"
                local file_path="/root/${filename}"

                if [ -f "$file_path" ]; then
                    log_message "INFO" "LOCAL FILE FOUND: ${filename}. STARTING INSTALLATION..."
                    
                    cd /root/
                    rm -rf x-ui/ /usr/local/x-ui/ /usr/bin/x-ui
                    
                    if tar zxvf "$filename"; then
                        chmod +x x-ui/x-ui x-ui/bin/xray-linux-* x-ui/x-ui.sh
                        cp x-ui/x-ui.sh /usr/bin/x-ui
                        cp -f x-ui/x-ui.service /etc/systemd/system/
                        mv x-ui/ /usr/local/
                        systemctl daemon-reload
                        systemctl enable x-ui
                        systemctl restart x-ui
                        
                        log_message "SUCCESS" "PANEL INSTALLED SUCCESSFULLY FROM LOCAL FILE."
                        echo -e "\n${G}X-UI STARTED. TYPE 'x-ui' TO MANAGE.${N}"
                    else
                        log_message "ERROR" "FAILED TO EXTRACT TAR FILE."
                    fi
                else
                    log_message "ERROR" "FILE NOT FOUND: ${file_path}"
                    echo -e "\n${C_RED}ERROR: PLEASE UPLOAD '${filename}' TO /root/ FIRST.${C_RESET}"
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                return
                ;;
            *)
                echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

manage_3xui_panel() {
    while true; do
        clear
        log_message "INFO" "--- 3X-UI PANEL MANAGEMENT ---"
        echo -e "${B_CYAN}--- INSTALL / UPDATE 3X-UI PANEL ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "1" "ONLINE INSTALLATION"
        printf "  ${C_YELLOW}%2d)${B_CYAN}  %s\n" "2" "OFFLINE INSTALLATION (FROM /ROOT)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                log_message "INFO" "STARTING ONLINE INSTALLATION..."
                bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
                log_message "SUCCESS" "ONLINE INSTALLATION SCRIPT EXECUTED."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                # --- ARCHITECTURE DETECTION ---
                ARCH=$(uname -m)
                case "${ARCH}" in
                    x86_64 | x64 | amd64) XUI_ARCH="amd64" ;;
                    i*86 | x86) XUI_ARCH="386" ;;
                    armv8* | armv8 | arm64 | aarch64) XUI_ARCH="arm64" ;;
                    armv7* | armv7) XUI_ARCH="armv7" ;;
                    armv6* | armv6) XUI_ARCH="armv6" ;;
                    armv5* | armv5) XUI_ARCH="armv5" ;;
                    s390x) echo 's390x' ;;
                    *) XUI_ARCH="amd64" ;;
                esac

                local filename="x-ui-linux-${XUI_ARCH}.tar.gz"
                local file_path="/root/${filename}"

                if [ -f "$file_path" ]; then
                    log_message "INFO" "LOCAL FILE FOUND: ${filename}. STARTING INSTALLATION..."
                    
                    cd /root/
                    rm -rf x-ui/ /usr/local/x-ui/ /usr/bin/x-ui
                    
                    if tar zxvf "$filename"; then
                        chmod +x x-ui/x-ui x-ui/bin/xray-linux-* x-ui/x-ui.sh
                        cp x-ui/x-ui.sh /usr/bin/x-ui
                        cp -f x-ui/x-ui.service /etc/systemd/system/
                        mv x-ui/ /usr/local/
                        systemctl daemon-reload
                        systemctl enable x-ui
                        systemctl restart x-ui
                        
                        log_message "SUCCESS" "PANEL INSTALLED SUCCESSFULLY FROM LOCAL FILE."
                        echo -e "\n${G}X-UI STARTED. TYPE 'x-ui' TO MANAGE.${N}"
                    else
                        log_message "ERROR" "FAILED TO EXTRACT TAR FILE."
                    fi
                else
                    log_message "ERROR" "FILE NOT FOUND: ${file_path}"
                    echo -e "\n${C_RED}ERROR: PLEASE UPLOAD '${filename}' TO /root/ FIRST.${C_RESET}"
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                return
                ;;
            *)
                echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

manage_vpn_panels() {
    while true; do
        clear
        echo -e "${B_CYAN}--- INSTALL AND MANAGE PANELS ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "1" "INSTALL / UPDATE TX-UI PANEL"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "2" "INSTALL / UPDATE 3X-UI PANEL"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK TO MAIN MENU"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1) manage_txui_panel ;;
            2) manage_3xui_panel ;;
            3) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
}

# --- MENU 2 FUNCTIONS (NETWORK OPTIMIZATION) ---

gather_system_info() {
    log_message "INFO" "GATHERING SYSTEM INFORMATION..."
    local cpu_cores total_ram
    cpu_cores=$(nproc 2>/dev/null | head -1)
    cpu_cores=$(printf '%s' "$cpu_cores" | tr -cd '0-9')
    if [[ -z "$cpu_cores" ]] || ! [[ "$cpu_cores" =~ ^[0-9]+$ ]] || [[ "$cpu_cores" -eq 0 ]]; then
        log_message "WARNING" "CPU CORE DETECTION FAILED. USING FALLBACK VALUE."
        cpu_cores=1
    fi
    total_ram=$(awk '/MemTotal:/ {print int($2/1024); exit}' /proc/meminfo 2>/dev/null | head -1)
    total_ram=$(printf '%s' "$total_ram" | tr -cd '0-9')
    if [[ -z "$total_ram" ]] || ! [[ "$total_ram" =~ ^[0-9]+$ ]] || [[ "$total_ram" -eq 0 ]]; then
        log_message "WARNING" "RAM DETECTION FAILED. USING FALLBACK VALUE."
        total_ram=1024
    fi
    log_message "INFO" "SYSTEM INFORMATION:"
    log_message "INFO" "CPU CORES: $cpu_cores"
    log_message "INFO" "TOTAL RAM: ${total_ram}MB"
    local optimal_backlog optimal_mem
    optimal_backlog=$((50000 * cpu_cores))
    optimal_mem=$((total_ram * 1024 / 4))
    SYSTEM_CPU_CORES=$cpu_cores
    SYSTEM_TOTAL_RAM=$total_ram
    SYSTEM_OPTIMAL_BACKLOG=$optimal_backlog
    SYSTEM_OPTIMAL_MEM=$optimal_mem
    return 0
}

optimize_network() {
    local interface="$1"
    if [[ -z "$interface" ]]; then
        log_message "ERROR" "NO INTERFACE SPECIFIED."
        return 1
    fi
    log_message "INFO" "OPTIMIZING NETWORK INTERFACE $interface..."
    if [[ -z "$SYSTEM_OPTIMAL_BACKLOG" ]]; then
        gather_system_info
    fi
    local max_mem=$SYSTEM_OPTIMAL_MEM
    if [[ "$max_mem" -gt 16777216 ]]; then
        max_mem=16777216
    fi
    log_message "INFO" "CONFIGURING NIC OFFLOAD SETTINGS..."
    {
        ethtool -K "$interface" tso on gso on gro on 2>/dev/null
        ethtool -G "$interface" rx 4096 tx 4096 2>/dev/null
    } || true
    if ethtool -k "$interface" 2>/dev/null | grep -q "rx-udp-gro-forwarding"; then
        log_message "INFO" "ENABLING UDP GRO FORWARDING..."
        ethtool -K "$interface" rx-udp-gro-forwarding on rx-gro-list off 2>/dev/null || true
    fi

    local custom_conf="/etc/sysctl.d/98-custom-optimizer.conf"
    if [ -f "$custom_conf" ]; then
        log_message "WARNING" "CONFLICTING SYSCTL FILE DETECTED: 98-custom-optimizer.conf"
        printf "\n%b" "${C_RED}**WARNING:** A CUSTOM OPTIMIZATION FILE WAS FOUND. CONTINUING MAY OVERWRITE ITS SETTINGS. PROCEED? (Y/N): ${C_RESET}"
        read -e -r choice
        if [[ ! "$choice" =~ ^[yY]$ ]]; then
            log_message "INFO" "OPTIMIZATION CANCELED BY USER TO AVOID CONFLICT."
            return 1
        fi
    fi
    
    local sysctl_conf="/etc/sysctl.d/99-network-optimizer.conf"
    log_message "INFO" "CREATING NETWORK OPTIMIZATION CONFIGURATION..."
    create_backup "$sysctl_conf"
    
    local current_time
    printf -v current_time '%(%Y-%m-%d %H:%M:%S)T' -1
    cat > "$sysctl_conf" << EOF
# NETWORK OPTIMIZATIONS ADDED ON $current_time
net.core.netdev_max_backlog = $SYSTEM_OPTIMAL_BACKLOG
net.core.rmem_max = $max_mem
net.core.wmem_max = $max_mem
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.default_qdisc = fq
net.ipv4.tcp_rmem = 4096 87380 $max_mem
net.ipv4.tcp_wmem = 4096 65536 $max_mem
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_max_syn_backlog = $SYSTEM_OPTIMAL_BACKLOG
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
EOF
    if sysctl -p "$sysctl_conf" &>/dev/null; then
        log_message "SUCCESS" "NETWORK OPTIMIZATIONS APPLIED SUCCESSFULLY."
    else
        log_message "ERROR" "FAILED TO APPLY NETWORK OPTIMIZATIONS."
        return 1
    fi
    local current_cc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [[ "$current_cc" == "bbr" ]]; then
        log_message "SUCCESS" "TCP BBR CONGESTION CONTROL ENABLED."
    else
        log_message "WARNING" "TCP BBR NOT AVAILABLE. FALLING BACK TO CUBIC."
        sysctl -w net.ipv4.tcp_congestion_control=cubic &>/dev/null
    fi
    if ip link set dev "$interface" txqueuelen 10000 2>/dev/null; then
        log_message "SUCCESS" "INCREASED TX QUEUE LENGTH FOR $interface."
    else
        log_message "WARNING" "FAILED TO SET TX QUEUE LENGTH."
    fi
    return 0
}

find_best_mtu() {
    local interface="$1"
    local target_ip="8.8.8.8"
    if [[ -z "$interface" ]]; then
        log_message "ERROR" "NO INTERFACE SPECIFIED FOR MTU OPTIMIZATION."
        return 1
    fi
    log_message "INFO" "STARTING MTU OPTIMIZATION FOR INTERFACE $interface..."
    local current_mtu
    if ! current_mtu=$(cat "/sys/class/net/$interface/mtu" 2>/dev/null); then
        current_mtu=$(ip link show "$interface" 2>/dev/null | sed -n 's/.*mtu \([0-9]*\).*/\1/p')
    fi
    if [[ -z "$current_mtu" ]] || [[ ! "$current_mtu" =~ ^[0-9]+$ ]]; then
        log_message "ERROR" "COULD NOT DETERMINE CURRENT MTU FOR $interface."
        return 1
    fi
    log_message "INFO" "CURRENT MTU: $current_mtu"
    if ! ip addr show "$interface" 2>/dev/null | grep -q "inet "; then
        log_message "ERROR" "INTERFACE $interface IS NOT CONFIGURED WITH AN IP ADDRESS."
        return 1
    fi
    log_message "INFO" "TESTING BASIC CONNECTIVITY..."
    if ! ping -c 1 -W 3 "$target_ip" &>/dev/null; then
        log_message "ERROR" "NO INTERNET CONNECTIVITY. CANNOT PERFORM MTU OPTIMIZATION."
        return 1
    fi
    test_mtu_size() {
        local size="$1"
        local payload_size=$((size - 28))
        if [[ "$payload_size" -lt 0 ]]; then return 1; fi
        local attempts=0; local success=0
        while [[ "$attempts" -lt 3 ]] && [[ "$success" -eq 0 ]]; do
            if ping -M do -s "$payload_size" -c 1 -W 2 -i 0.2 "$target_ip" &>/dev/null; then
                success=1; break
            fi
            ((attempts++)); sleep 0.1
        done
        return $((1 - success))
    }
    local optimal_mtu="$current_mtu"
    local found_working=0
    log_message "INFO" "TESTING COMMON MTU SIZES..."
    local common_mtus=(1500 1492 1480 1472 1468 1460 1450 1440 1430 1420 1400 1380 1360 1340 1300 1280 1200 1024)
    for size in "${common_mtus[@]}"; do
        if [[ "$size" -le "$current_mtu" ]]; then
            printf "  TESTING MTU %d... " "$size"
            if test_mtu_size "$size"; then
                printf "${G}✓${N}\n"
                optimal_mtu="$size"; found_working=1; break
            else
                printf "${R}✗${N}\n"
            fi
        fi
    done
    if [[ "$found_working" -eq 0 ]]; then
        log_message "INFO" "COMMON MTUS FAILED. PERFORMING BINARY SEARCH..."
        local min_mtu=576; local max_mtu="$current_mtu"; local test_mtu
        while [[ "$min_mtu" -le "$max_mtu" ]]; do
            test_mtu=$(( (min_mtu + max_mtu) / 2 ))
            printf "  TESTING MTU %d... " "$test_mtu"
            if test_mtu_size "$test_mtu"; then
                printf "${G}✓${N}\n"
                optimal_mtu="$test_mtu"; min_mtu=$((test_mtu + 1)); found_working=1
            else
                printf "${R}✗${N}\n"
                max_mtu=$((test_mtu - 1))
            fi
        done
    fi
    if [[ "$found_working" -eq 1 ]]; then
        if [[ "$optimal_mtu" -ne "$current_mtu" ]]; then
            log_message "INFO" "APPLYING OPTIMAL MTU: $optimal_mtu"
            if ip link set "$interface" mtu "$optimal_mtu" 2>/dev/null; then
                log_message "SUCCESS" "MTU SUCCESSFULLY SET TO $optimal_mtu."
                log_message "INFO" "MAKING MTU SETTING PERSISTENT ACROSS REBOOTS..."
                cat > "$CONFIG_DIR/mtu.conf" << EOF
# OPTIMAL MTU CONFIGURATION SAVED BY SCRIPT
INTERFACE=$interface
OPTIMAL_MTU=$optimal_mtu
EOF
                cat > /etc/systemd/system/irnet-mtu-persistent.service << EOF
[Unit]
Description=Persistent MTU Setter by IRNET Script
After=network.target
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "source \"$CONFIG_DIR/mtu.conf\" && /sbin/ip link set dev \\\$INTERFACE mtu \\\$OPTIMAL_MTU"

[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload
                systemctl enable --now irnet-mtu-persistent.service
                check_service_status "irnet-mtu-persistent.service"
            else
                log_message "ERROR" "FAILED TO SET MTU TO $optimal_mtu."
                return 1
            fi
        else
            log_message "INFO" "CURRENT MTU ($current_mtu) IS ALREADY OPTIMAL."
        fi
    else
        log_message "WARNING" "COULD NOT FIND WORKING MTU. KEEPING CURRENT MTU: $current_mtu."
    fi
    return 0
}

restore_defaults() {
    log_message "INFO" "RESTORING ORIGINAL SETTINGS..."
    local choice
    while true; do
        read -p "ARE YOU SURE YOU WANT TO RESTORE DEFAULT SETTINGS? (Y/N): " -n 1 -r choice
        echo
        case "$choice" in
            [Yy]*)
                break
                ;;
            [Nn]*)
                log_message "INFO" "RESTORE OPERATION CANCELED."
                return 0
                ;;
            *)
                printf "\n%b" "${C_RED}PLEASE ANSWER WITH Y OR N.${C_RESET}\n"
                ;;
        esac
    done

    log_message "INFO" "REMOVING ALL PERSISTENT SERVICES CREATED BY THIS SCRIPT..."
    systemctl disable --now irnet-mtu-persistent.service &>/dev/null
    rm -f /etc/systemd/system/irnet-mtu-persistent.service
    rm -f "$CONFIG_DIR/mtu.conf"

    systemctl disable --now irnet-tc-persistent.service &>/dev/null
    rm -f /etc/systemd/system/irnet-tc-persistent.service
    rm -f "$CONFIG_DIR/tc.conf"
    systemctl daemon-reload

    local sysctl_backup hosts_backup resolv_backup
    sysctl_backup=$(find "$BACKUP_DIR" -name "99-network-optimizer.conf.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    hosts_backup=$(find "$BACKUP_DIR" -name "hosts.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    resolv_backup=$(find "$BACKUP_DIR" -name "resolv.conf.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    if [[ -f "$sysctl_backup" ]]; then
        if cp -f "$sysctl_backup" "/etc/sysctl.d/99-network-optimizer.conf" 2>/dev/null; then
            sysctl -p "/etc/sysctl.d/99-network-optimizer.conf" &>/dev/null
            log_message "SUCCESS" "RESTORED SYSCTL SETTINGS."
        else
            log_message "ERROR" "FAILED TO RESTORE SYSCTL SETTINGS."
        fi
    else
        log_message "WARNING" "NO SYSCTL BACKUP FOUND. REMOVING OPTIMIZATION FILE..."
        rm -f "/etc/sysctl.d/99-network-optimizer.conf"
        sysctl --system &>/dev/null
        log_message "INFO" "RESET TO SYSTEM DEFAULTS."
    fi
    if [[ -f "$hosts_backup" ]]; then
        if cp -f "$hosts_backup" "/etc/hosts" 2>/dev/null; then
            log_message "SUCCESS" "RESTORED HOSTS FILE."
        else
            log_message "ERROR" "FAILED TO RESTORE HOSTS FILE."
        fi
    else
        log_message "WARNING" "NO HOSTS BACKUP FOUND."
    fi
    if [[ -f "$resolv_backup" ]]; then
        if cp -f "$resolv_backup" "/etc/resolv.conf" 2>/dev/null; then
            log_message "SUCCESS" "RESTORED DNS SETTINGS."
        else
            log_message "ERROR" "FAILED TO RESTORE DNS SETTINGS."
        fi
    else
        log_message "WARNING" "NO DNS BACKUP FOUND."
    fi
    log_message "SUCCESS" "ORIGINAL SETTINGS RESTORED SUCCESSFULLY."
    log_message "INFO" "A SYSTEM REBOOT IS RECOMMENDED FOR CHANGES TO TAKE FULL EFFECT."
    
    local reboot_choice
    while true; do
        read -p "DO YOU WANT TO REBOOT THE SYSTEM? (Y/N): " -n 1 -r reboot_choice
        echo
        case "$reboot_choice" in
            [Yy]*)
                log_message "INFO" "REBOOTING SYSTEM NOW..."
                systemctl reboot
                break
                ;;
            [Nn]*)
                break
                ;;
            *)
                printf "\n%b" "${C_RED}PLEASE ANSWER WITH Y OR N.${C_RESET}\n"
                ;;
        esac
    done
    return 0
}

intelligent_optimize() {
    log_message "INFO" "STARTING INTELLIGENT NETWORK OPTIMIZATION..."
    
    if ! install_dependencies; then
        log_message "ERROR" "FAILED TO INSTALL REQUIRED DEPENDENCIES. ABORTING."
        return 1
    fi
    
    if ! check_internet_connection; then
        log_message "ERROR" "NO INTERNET CONNECTION AVAILABLE. CANNOT APPLY OPTIMIZATIONS."
        return 1
    fi
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        log_message "ERROR" "COULD NOT DETECT PRIMARY NETWORK INTERFACE."
        return 1
    fi

    log_message "INFO" "APPLYING OPTIMIZATIONS TO INTERFACE $PRIMARY_INTERFACE..."
    if ! fix_etc_hosts; then log_message "ERROR" "FAILED TO OPTIMIZE HOSTS FILE."; return 1; fi
    
    if ! apply_dns_persistent "${TARGET_DNS[0]}" "${TARGET_DNS[1]}"; then 
        log_message "ERROR" "FAILED TO OPTIMIZE DNS SETTINGS."; 
        return 1; 
    fi

    if ! gather_system_info; then log_message "ERROR" "FAILED TO GATHER SYSTEM INFORMATION."; return 1; fi
    if ! optimize_network "$PRIMARY_INTERFACE"; then log_message "ERROR" "FAILED TO APPLY NETWORK OPTIMIZATIONS."; return 1; fi
    if ! find_best_mtu "$PRIMARY_INTERFACE"; then log_message "ERROR" "FAILED TO OPTIMIZE MTU."; return 1; fi
    
    log_message "SUCCESS" "ALL OPTIMIZATIONS COMPLETED SUCCESSFULLY."
    log_message "INFO" "A SYSTEM REBOOT IS RECOMMENDED FOR CHANGES TO TAKE FULL EFFECT."
    
    local choice
    while true; do
        read -p "DO YOU WANT TO REBOOT THE SYSTEM? (Y/N): " -n 1 -r choice
        echo
        case "$choice" in
            [Yy]*)
                log_message "INFO" "REBOOTING SYSTEM NOW..."
                systemctl reboot
                break
                ;;
            [Nn]*)
                break
                ;;
            *)
                printf "\n%b" "${C_RED}PLEASE ANSWER WITH Y OR N.${C_RESET}\n"
                ;;
        esac
    done
    return 0
}

run_as_bbr_optimization() {
    init_environment
    while true; do
        clear
        echo -e "${B_CYAN}--- NETWORK BASE OPTIMIZATION MENU ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "APPLY INTELLIGENT OPTIMIZATION (RECOMMENDED)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "RESTORE DEFAULT SETTINGS"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK TO MAIN MENU"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION (1-3): ${C_RESET}"
        read -e -r choice

        case "$choice" in
            1)
                intelligent_optimize
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                restore_defaults
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                log_message "INFO" "RETURNING TO THE MAIN MENU."
                return
                ;;
            *)
                printf "\n%sINVALID OPTION. PLEASE ENTER A NUMBER FROM 1 TO 3.%s\n" "$C_RED" "$C_RESET"
                sleep 2
                ;;
        esac
    done
}

remove_tcp_optimizers() {
    log_message "INFO" "REMOVING TCP OPTIMIZER CONFIGS..."
    rm -f /etc/sysctl.d/99-custom-optimizer.conf
    sysctl --system &>/dev/null
    log_message "SUCCESS" "TCP OPTIMIZER CONFIG REMOVED."
}

apply_bbr_plus() {
    remove_tcp_optimizers
    log_message "INFO" "APPLYING BBR PLUS OPTIMIZATION PROFILE..."
    cat > /etc/sysctl.d/99-custom-optimizer.conf << EOF
# BBR PLUS PROFILE BY IRNET
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=1800
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_max_syn_backlog=10240
net.ipv4.tcp_max_tw_buckets=2000000
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_notsent_lowat=16384
EOF
    sysctl -p /etc/sysctl.d/99-custom-optimizer.conf &>/dev/null
    log_message "SUCCESS" "BBR PLUS PROFILE APPLIED SUCCESSFULLY."
}

apply_bbr_v2() {
    remove_tcp_optimizers
    log_message "INFO" "APPLYING BBRV2 OPTIMIZATION PROFILE..."
    cat > /etc/sysctl.d/99-custom-optimizer.conf << EOF
# BBRV2 PROFILE BY IRNET
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_ecn=1
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_keepalive_intvl=20
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_max_tw_buckets=2000000
net.ipv4.tcp_notsent_lowat=16384
net.ipv4.tcp_retries2=10
net.ipv4.tcp_sack=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_window_scaling=1
EOF
    sysctl -p /etc/sysctl.d/99-custom-optimizer.conf &>/dev/null
    log_message "SUCCESS" "BBRV2 PROFILE APPLIED SUCCESSFULLY."
}

apply_hybla_plus() {
    if ! modprobe tcp_hybla; then
        log_message "ERROR" "TCP HYBLA MODULE NOT AVAILABLE IN THIS KERNEL."
        return
    fi
    remove_tcp_optimizers
    log_message "INFO" "APPLYING HYBLA PLUS OPTIMIZATION PROFILE..."
    cat > /etc/sysctl.d/99-custom-optimizer.conf << EOF
# HYBLA PLUS PROFILE BY IRNET
net.core.default_qdisc=fq_codel
net.ipv4.tcp_congestion_control=hybla
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=1800
net.ipv4.tcp_low_latency=1
EOF
    sysctl -p /etc/sysctl.d/99-custom-optimizer.conf &>/dev/null
    log_message "SUCCESS" "HYBLA PLUS PROFILE APPLIED SUCCESSFULLY."
}

apply_cubic_unstable() {
    remove_tcp_optimizers
    log_message "INFO" "APPLYING CUBIC PROFILE FOR UNSTABLE NETWORKS..."
    cat > /etc/sysctl.d/99-custom-optimizer.conf << EOF
# CUBIC FOR UNSTABLE NETWORKS PROFILE BY IRNET
net.core.default_qdisc=codel
net.ipv4.tcp_congestion_control=cubic
net.ipv4.ip_local_port_range = 32768 32818
EOF
    sysctl -p /etc/sysctl.d/99-custom-optimizer.conf &>/dev/null
    log_message "SUCCESS" "CUBIC (UNSTABLE NETWORK) PROFILE APPLIED SUCCESSFULLY."
}

manage_tcp_optimizers() {
    while true; do
        clear
        echo -e "${B_CYAN}--- MANAGE TCP OPTIMIZERS ---${C_RESET}\n"
        
        local current_qdisc
        current_qdisc=$(sysctl -n net.core.default_qdisc)
        local current_tcp_algo
        current_tcp_algo=$(sysctl -n net.ipv4.tcp_congestion_control)
        local active_profile_name="${C_YELLOW}UNKNOWN${N}"

        local custom_conf="/etc/sysctl.d/99-custom-optimizer.conf"
        local intelligent_conf="/etc/sysctl.d/99-network-optimizer.conf"
        
        if [ -f "$custom_conf" ]; then
            if grep -q "# BBR PLUS PROFILE" "$custom_conf"; then
                active_profile_name="${G}BBR PLUS${N}"
            elif grep -q "# BBRV2 PROFILE" "$custom_conf"; then
                active_profile_name="${G}BBRV2${N}"
            elif grep -q "# HYBLA PLUS PROFILE" "$custom_conf"; then
                active_profile_name="${G}HYBLA PLUS${N}"
            elif grep -q "# CUBIC FOR UNSTABLE" "$custom_conf"; then
                active_profile_name="${G}CUBIC (UNSTABLE NETWORK)${N}"
            else
                active_profile_name="${Y}CUSTOM FILE${N}"
            fi
        elif [ -f "$intelligent_conf" ]; then
             active_profile_name="${C_CYAN}INTELLIGENT OPTIMIZER${N}"
        else
            active_profile_name="${C_WHITE}KERNEL DEFAULT${N}"
        fi
        
        echo -e "  ${C_WHITE}ACTIVE TCP ALGORITHM:${C_RESET} ${B_GREEN}${current_tcp_algo^^}${N}"
        echo -e "  ${C_WHITE}ACTIVE QDISC:${C_RESET} ${B_GREEN}${current_qdisc^^}${N}"
        echo -e "  ${C_WHITE}DETECTED PROFILE:${C_RESET} ${active_profile_name}\n"

        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "INSTALL BBR PLUS OPTIMIZER"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "INSTALL BBRV2 OPTIMIZER"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "INSTALL HYBLA PLUS OPTIMIZER"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "INSTALL CUBIC OPTIMIZER (FOR UNSTABLE NETWORKS)"
        printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "5" "REMOVE ALL OPTIMIZERS (REVERT TO KERNEL DEFAULT)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "6" "BACK"
        echo -e "${B_BLUE}-----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"
        read -e -r choice

        case $choice in
            1) apply_bbr_plus ;;
            2) apply_bbr_v2 ;;
            3) apply_hybla_plus ;;
            4) apply_cubic_unstable ;;
            5) remove_tcp_optimizers; log_message "INFO" "OPTIMIZER CONFIG REMOVED." ;;
            6) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
    done
}

manage_custom_sysctl() {
    local conf_file="/etc/sysctl.d/98-custom-optimizer.conf"
    while true; do
        clear
        echo -e "${B_CYAN}--- CUSTOM SYSCTL OPTIMIZER ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "APPLY CUSTOM SETTINGS"
        printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "2" "REMOVE CUSTOM SETTINGS"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"
        read -e -r choice
        case $choice in
            1)
                log_message "INFO" "APPLYING CUSTOM SYSCTL SETTINGS..."
                
                local intelligent_conf="/etc/sysctl.d/99-network-optimizer.conf"
                if [ -f "$intelligent_conf" ]; then
                    log_message "WARNING" "CONFLICTING SYSCTL FILE DETECTED: 99-network-optimizer.conf"
                    printf "\n%b" "${C_RED}**WARNING:** INTELLIGENT OPTIMIZATION FILE FOUND. APPLYING THIS CUSTOM PROFILE MAY OVERWRITE SOME SETTINGS. PROCEED? (Y/N): ${C_RESET}"
                    read -e -r conflict_choice
                    if [[ ! "$conflict_choice" =~ ^[yY]$ ]]; then
                        log_message "INFO" "OPTIMIZATION CANCELED BY USER TO AVOID CONFLICT."
                        break
                    fi
                fi

                create_backup "$conf_file"
                tee "$conf_file" > /dev/null <<'EOF'
# CUSTOM SYSCTL SETTINGS BY IRNET
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.core.rmem_default=16777216
net.core.wmem_default=16777216
net.core.netdev_max_backlog=30000
net.core.somaxconn=32768
net.ipv4.tcp_rmem=8192 131072 134217728
net.ipv4.tcp_wmem=8192 131072 134217728
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=3
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_max_tw_buckets=2000000
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_ecn=2
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_mtu_probing=2
net.ipv4.ip_forward=1
net.ipv4.ip_default_ttl=64
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.netfilter.nf_conntrack_max=1048576
vm.swappiness=10
fs.file-max=2097152
fs.nr_open=2097152
net.core.default_qdisc=fq_codel
EOF
                sysctl -p "$conf_file"
                log_message "SUCCESS" "CUSTOM SYSCTL SETTINGS APPLIED SUCCESSFULLY."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                if [ -f "$conf_file" ]; then
                    rm -f "$conf_file"
                    sysctl --system &>/dev/null
                    log_message "SUCCESS" "CUSTOM SYSCTL SETTINGS FILE REMOVED."
                else
                    log_message "INFO" "CUSTOM SETTINGS FILE NOT FOUND."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
}

manage_tc_qleen_mtu() {
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        log_message "ERROR" "PRIMARY NETWORK INTERFACE NOT FOUND."
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi
    
    local TC_CONFIG_FILE="$CONFIG_DIR/tc.conf"
    local TC_SERVICE_FILE="/etc/systemd/system/irnet-tc-persistent.service"

    while true; do
        clear
        echo -e "${B_CYAN}--- CUSTOM QLEEN & MTU OPTIMIZER ---${C_RESET}"
        echo -e "${C_YELLOW}NOTE: SELECTING ANY PROFILE BELOW WILL SET MTU TO A FIXED VALUE OF 1380.${N}"
        echo -e "DETECTED INTERFACE: ${B_YELLOW}${PRIMARY_INTERFACE}${N}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "APPLY CAKE PROFILE (TXQUEUELEN 500, MTU 1380)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "APPLY FQ_CODEL PROFILE (TXQUEUELEN 1500, MTU 1380)"
        printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "3" "REMOVE TC SETTINGS AND REVERT TO DEFAULT"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "BACK"
        echo -e "${B_BLUE}-----------------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"
        read -e -r choice
        
        case $choice in
            1|2)
                local profile_name qdisc txq mtu
                if [ "$choice" -eq 1 ]; then
                    profile_name="CAKE"
                    qdisc="cake"
                    txq="500"
                    mtu="1380"
                else
                    profile_name="FQ_CODEL"
                    qdisc="fq_codel"
                    txq="1500"
                    mtu="1380"
                fi

                log_message "INFO" "APPLYING $profile_name PROFILE TO $PRIMARY_INTERFACE..."
                tc qdisc del dev "$PRIMARY_INTERFACE" root 2>/dev/null
                tc qdisc add dev "$PRIMARY_INTERFACE" root "$qdisc"
                ip link set dev "$PRIMARY_INTERFACE" txqueuelen "$txq"
                ip link set dev "$PRIMARY_INTERFACE" mtu "$mtu"
                log_message "SUCCESS" "$profile_name PROFILE APPLIED SUCCESSFULLY."

                log_message "INFO" "MAKING TC PROFILE PERSISTENT..."
                echo "TC_PROFILE=${profile_name}" > "$TC_CONFIG_FILE"
                echo "INTERFACE=${PRIMARY_INTERFACE}" >> "$TC_CONFIG_FILE"
                
                cat > "$TC_SERVICE_FILE" << EOF
[Unit]
Description=Persistent TC Profile by IRNET Script ($profile_name)
After=network.target
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "source \"$TC_CONFIG_FILE\" && tc qdisc del dev \\\$INTERFACE root 2>/dev/null; if [ \\\"\\\$TC_PROFILE\\\" = \\\"CAKE\\\" ]; then tc qdisc add dev \\\$INTERFACE root cake; ip link set dev \\\$INTERFACE txqueuelen 500; ip link set dev \\\$INTERFACE mtu 1380; elif [ \\\"\\\$TC_PROFILE\\\" = \\\"FQ_CODEL\\\" ]; then tc qdisc add dev \\\$INTERFACE root fq_codel; ip link set dev \\\$INTERFACE txqueuelen 1500; ip link set dev \\\$INTERFACE mtu 1380; fi"

[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload
                systemctl enable --now irnet-tc-persistent.service
                check_service_status "irnet-tc-persistent.service"

                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                log_message "INFO" "REMOVING TC QDISC FROM $PRIMARY_INTERFACE..."
                tc qdisc del dev "$PRIMARY_INTERFACE" root 2>/dev/null
                
                log_message "INFO" "REMOVING PERSISTENT TC SERVICE..."
                systemctl disable --now irnet-tc-persistent.service &>/dev/null
                rm -f "$TC_SERVICE_FILE"
                rm -f "$TC_CONFIG_FILE"
                systemctl daemon-reload

                log_message "SUCCESS" "TC SETTINGS AND ITS PERSISTENT SERVICE REMOVED."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            4) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
}

show_current_dns_smart() {
    local uniq_list=()
    mapfile -t uniq_list < <(_dns_collect_unique)

    echo -e "${B_BLUE}--- ACTIVE SYSTEM DNS ---${C_RESET}"
    if [ ${#uniq_list[@]} -eq 0 ]; then
        echo -e "${C_YELLOW}NO ACTIVE DNS FOUND.${C_RESET}"
    else
        echo -e "${C_WHITE}CURRENT SYSTEM DNS SERVERS:${C_RESET}"
        for ip in "${uniq_list[@]}"; do
            echo -e "  • ${C_CYAN}${ip}${C_RESET}"
        done
    fi
    echo
}

manage_sanction_dns() {
    clear
    echo -e "${B_CYAN}--- DOMESTIC ANTI-SANCTION DNS ---${C_RESET}\n"

    local -a providers=("SHECAN" "RADAR" "ELECTRO" "BEGZAR" "DNS PRO" "403" "GOOGLE" "CLOUDFLARE" "RESET TO DEFAULT")
    local -A dns_servers=(
        ["SHECAN"]="178.22.122.100 185.51.200.2"
        ["RADAR"]="10.202.10.10 10.202.10.11"
        ["ELECTRO"]="78.157.42.100 78.157.42.101"
        ["BEGZAR"]="185.55.226.26 185.55.225.25"
        ["DNS PRO"]="87.107.110.109 87.107.110.110"
        ["403"]="10.202.10.202 10.202.10.102"
        ["GOOGLE"]="8.8.8.8 8.8.4.4"
        ["CLOUDFLARE"]="1.1.1.1 1.0.0.1"
        ["RESET TO DEFAULT"]=""
    )

    show_current_dns_smart
    
    echo -e "${B_CYAN}AVAILABLE DNS PROVIDERS:${C_RESET}"
    for i in "${!providers[@]}"; do
        local name="${providers[$i]}"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %-17s ${C_CYAN}%s${C_RESET}\n" $((i + 1)) "$name" "${dns_servers[$name]}"
    done
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "0" "BACK"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    
    printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"
    read -e -r choice

    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -gt "${#providers[@]}" ]; then
        log_message "ERROR" "INVALID SELECTION."; sleep 2; return
    fi
    [ "$choice" -eq 0 ] && return

    local provider="${providers[$((choice - 1))]}"
    local dns_list="${dns_servers[$provider]}"
    local dns1 dns2
    read -r dns1 dns2 <<< "$dns_list"
    apply_dns_persistent "$dns1" "$dns2"
    
    log_message "INFO" "OPERATION COMPLETED. CHECKING NEW DNS SETTINGS..."
    sleep 2; clear; show_current_dns_smart
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

_dns_collect_unique() {
    local override_file="/etc/systemd/resolved.conf.d/99-irnet-dns.conf"
    if [ -r "$override_file" ]; then
        awk -F'=' '/^(DNS|FallbackDNS)=/{
            for(i=2;i<=NF;i++){print $i}
        }' "$override_file" | tr ' ' '\n' | sed '/^$/d' \
          | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|^[0-9a-fA-F:]+$' \
          | awk '!seen[$0]++'
        return
    fi
    local collected=""
    if command -v resolvectl >/dev/null 2>&1; then
        collected+=" $(resolvectl status 2>/dev/null | awk -F': ' '
            BEGIN{in_global=0}
            /^Global$/ {in_global=1; next}
            /^Link/ {in_global=0}
            in_global && /^ *DNS Servers:/ {print $2; exit}
        ')"
        if [ -n "$PRIMARY_INTERFACE" ]; then
            collected+=" $(resolvectl dns "$PRIMARY_INTERFACE" 2>/dev/null | awk -F': ' 'NF>1{print $2}')"
        else
            collected+=" $(resolvectl dns 2>/dev/null | awk -F': ' 'NF>1{for(i=2;i<=NF;i++)print $i}')"
        fi
    fi
    if [ -r /etc/resolv.conf ]; then
        collected+=" $(awk "/^nameserver/{print \$2}" /etc/resolv.conf)"
    fi
    if command -v nmcli >/dev/null 2>&1; then
        collected+=" $(nmcli -t -f IP4.DNS,IP6.DNS connection show 2>/dev/null | tr ':,' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    fi
    echo "$collected" | tr ' ' '\n' \
      | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|^[0-9a-fA-F:]+$' \
      | awk '!seen[$0]++'
}

_dns_set_persistent_interactive() {
    echo -e "${B_MAGENTA}ENTER DNS IPS SEPARATED BY SPACE (EXAMPLE: 1.1.1.1 8.8.8.8):${N}"
    printf "%b" "${C_CYAN}> ${C_RESET}"; read -e -r dns_line
    [ -z "$dns_line" ] && { echo -e "${C_RED}NOTHING ENTERED.${N}"; sleep 1; return; }

    local dns1 dns2
    read -r dns1 dns2 <<< "$dns_line"
    apply_dns_persistent "$dns1" "$dns2"
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

_dns_reset_to_default() {
    if systemctl is-active --quiet systemd-resolved.service || command -v resolvectl >/dev/null 2>&1; then
        create_backup "/etc/systemd/resolved.conf"
        sed -i -E 's/^\s*(DNS|FallbackDNS)=/# \0/g' /etc/systemd/resolved.conf 2>/dev/null || true
        systemctl restart systemd-resolved.service 2>/dev/null || true
        resolvectl flush-caches 2>/dev/null || true
        log_message "INFO" "DNS REVERTED TO RESOLVED DEFAULT."
    else
        create_backup "/etc/resolv.conf"
        sed -i '/^nameserver /d' /etc/resolv.conf 2>/dev/null || true
        log_message "INFO" "MANUAL DNS REMOVED FROM /etc/resolv.conf."
    fi
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

_dns_show_unique() {
    echo -e "\n${B_BLUE}--- ACTIVE SYSTEM DNS (UNIQUE) ---${N}"
    _dns_collect_unique | nl -w2 -s") "
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

manage_dns() {
    clear
    if ! command -v fping &>/dev/null; then
        log_message "WARNING" "FPING TOOL NOT FOUND. ATTEMPTING TO INSTALL AUTOMATICALLY..."
        if ! install_dependencies; then
            log_message "ERROR" "AUTOMATIC INSTALLATION OF 'FPING' FAILED."
            read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
            return
        fi
        log_message "SUCCESS" "'FPING' TOOL INSTALLED SUCCESSFULLY. CONTINUING..."
        sleep 2
    fi

    local IRAN_DNS_LIST=(
        "178.22.122.100" "185.51.200.2" "10.202.10.10" "10.202.10.11" "78.157.42.100" "78.157.42.101" "185.55.226.26" "185.55.225.25" "10.202.10.202" "10.202.10.102" "194.5.175.175" "194.5.174.174" "194.36.174.161" "185.239.40.40" "85.15.1.15" "85.15.1.14" "91.99.101.102" "91.99.101.103" "92.114.28.2" "92.114.29.2" "217.218.155.155" "217.218.127.127" "91.98.98.98" "217.66.195.210" "79.175.131.2" "79.175.131.3" "188.136.215.180" "188.136.215.181" "91.99.99.91" "195.248.240.60" "195.248.240.92" "213.151.48.2" "213.151.48.3"
    )
    local GLOBAL_DNS_LIST=(
        "8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1" "9.9.9.9" "149.112.112.112" "208.67.222.222" "208.67.220.220" "8.26.56.26" "8.20.247.20" "94.140.14.14" "94.140.15.15" "77.88.8.8" "77.88.8.1" "64.6.64.6" "64.6.65.6" "4.2.2.1" "4.2.2.2" "4.2.2.3" "4.2.2.4" "84.200.69.80" "84.200.70.40" "80.80.80.80" "80.80.81.81" "156.154.70.1" "156.154.71.1" "185.228.168.9" "185.228.169.9" "76.76.19.19" "76.223.122.150" "76.76.2.0" "76.76.10.0" "195.46.39.39" "195.46.39.40" "91.239.100.100" "89.233.43.71"
    )

    find_and_set_best_dns() {
        local -n dns_list=$1
        local list_name="$2"
        echo -e "\n${B_CYAN}--- PINGING DNS SERVERS FROM THE ${list_name^^} LIST ---${C_RESET}"
        echo -e "${C_WHITE}PLEASE WAIT, THIS MAY TAKE A MOMENT...${C_RESET}"
        local fping_results
        fping_results=$(fping -C 3 -q -B1 -i10 "${dns_list[@]}" 2>&1)
        local results_array=()
        while IFS= read -r line; do
            if [[ $line && ! "$line" == *"-"* ]]; then
                local ip avg_ping
                ip=$(echo "$line" | awk '{print $1}')
                avg_ping=$(echo "$line" | awk '{s=0; for(i=3;i<=NF;i++) s+=$i; print s/(NF-2)}' | bc -l)
                results_array+=("$(printf "%.2f" $avg_ping)|$ip")
            fi
        done <<< "$fping_results"
        if [ ${#results_array[@]} -eq 0 ]; then
            log_message "ERROR" "NONE OF THE DNS SERVERS RESPONDED. PLEASE CHECK YOUR INTERNET CONNECTION."
            return
        fi
        mapfile -t sorted_results < <(printf '%s\n' "${results_array[@]}" | sort -n)
        echo
        printf "${B_BLUE}+------------------------+--------------------------+${C_RESET}\n"
        printf "${B_BLUE}| ${B_YELLOW}%-22s ${B_BLUE}| ${B_YELLOW}%-24s ${B_BLUE}|${C_RESET}\n" "DNS SERVER" "AVERAGE PING (MS)"
        printf "${B_BLUE}+------------------------+--------------------------+${C_RESET}\n"
        for result in "${sorted_results[@]}"; do
            local ping_val="${result%|*}"
            local ip_val="${result#*|}"
            printf "${B_BLUE}|${N} ${C_CYAN}%-22s ${B_BLUE}|${N} ${G}%-24s ${B_BLUE}|${N}\n" "$ip_val" "$ping_val"
        done
        printf "${B_BLUE}+------------------------+--------------------------+${C_RESET}\n"
        echo
        mapfile -t best_ips < <(printf '%s\n' "${sorted_results[@]}" | awk -F'|' '{print $2}')
        if [ "${#best_ips[@]}" -lt 2 ]; then
            log_message "WARNING" "ONLY ONE ACCESSIBLE DNS WAS FOUND. SETTING BOTH DNS TO IT."
        fi
        local best_dns_1="${best_ips[0]}"
        local best_dns_2="${best_ips[1]:-${best_ips[0]}}"
        apply_dns_persistent "$best_dns_1" "$best_dns_2"
    }

    while true; do
        clear
        echo -e "${B_CYAN}--- MANAGE AND FIND BEST DNS ---${C_RESET}\n"
        show_current_dns_smart
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "FIND AND SET BEST IRAN DNS"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "FIND AND SET BEST GLOBAL DNS"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "3" "SET MANUAL DNS (PERSISTENT)"
        printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "4" "RESET DNS TO DEFAULT"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "BACK"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1) find_and_set_best_dns IRAN_DNS_LIST "Iran"; break ;;
            2) find_and_set_best_dns GLOBAL_DNS_LIST "Global"; break ;;
            3) _dns_set_persistent_interactive; break ;;
            4) _dns_reset_to_default; break ;;
            5) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

manage_secure_dns() {
    _ensure_stubby_listen || true
    local STUBBY_CONF="/etc/stubby/stubby.yml"

    _install_stubby() {
        if ! command -v stubby &>/dev/null; then
            log_message "INFO" "INSTALLING STUBBY (SECURE DNS RESOLVER)..."
            if ! apt-get install -y -qq stubby; then
                log_message "ERROR" "FAILED TO INSTALL STUBBY."
                return 1
            fi
        fi
        systemctl enable --now stubby
        return 0
    }

    _apply_secure_dns() {
        log_message "INFO" "ENABLING SECURE DNS BY POINTING SYSTEM TO STUBBY..."
        apply_dns_persistent "127.0.0.1" "::1"
    }

    _revert_dns() {
        log_message "INFO" "REVERTING DNS TO A PUBLIC RESOLVER (CLOUDFLARE)..."
        apply_dns_persistent "1.1.1.1" "1.0.0.1"
    }

    _set_upstream_provider() {
        local provider_name="$1"
        log_message "INFO" "SETTING UPSTREAM DNS PROVIDER TO: $provider_name"
        create_backup "$STUBBY_CONF"

        local config_block
        case "$provider_name" in
            "CLOUDFLARE")
                config_block="
  - address_data: 1.1.1.1
    tls_auth_name: \"cloudflare-dns.com\"
  - address_data: 1.0.0.1
    tls_auth_name: \"cloudflare-dns.com\"
  - address_data: 2606:4700:4700::1111
    tls_auth_name: \"cloudflare-dns.com\"
  - address_data: 2606:4700:4700::1001
    tls_auth_name: \"cloudflare-dns.com\""
                ;;
            "GOOGLE")
                config_block="
  - address_data: 8.8.8.8
    tls_auth_name: \"dns.google\"
  - address_data: 8.8.4.4
    tls_auth_name: \"dns.google\"
  - address_data: 2001:4860:4860::8888
    tls_auth_name: \"dns.google\"
  - address_data: 2001:4860:4860::8844
    tls_auth_name: \"dns.google\""
                ;;
            "QUAD9")
                config_block="
  - address_data: 9.9.9.9
    tls_auth_name: \"dns.quad9.net\"
  - address_data: 149.112.112.112
    tls_auth_name: \"dns.quad9.net\"
  - address_data: 2620:fe::fe
    tls_auth_name: \"dns.quad9.net\"
  - address_data: 2620:fe::9
    tls_auth_name: \"dns.quad9.net\""
                ;;
            *)
                log_message "ERROR" "UNKNOWN DNS PROVIDER."
                return 1
                ;;
        esac

        _replace_stubby_upstreams_safely "$config_block"

        systemctl restart stubby
        log_message "SUCCESS" "STUBBY CONFIGURATION UPDATED. PROVIDER IS NOW $provider_name."
    }

    if ! _install_stubby; then
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi
    
    while true; do
        clear
        echo -e "${B_CYAN}--- MANAGE SECURE DNS (DOH/DOT) WITH STUBBY ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "1" "ENABLE SECURE DNS (USE STUBBY)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "CHANGE PROVIDER (CLOUDFLARE, GOOGLE, QUAD9)"
        printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "3" "DISABLE SECURE DNS (REVERT TO NORMAL DNS)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1) _apply_secure_dns ;;
            2)
                printf "%b" "${B_MAGENTA}SELECT PROVIDER (CLOUDFLARE/GOOGLE/QUAD9): ${C_RESET}"; read -e -r provider
                _set_upstream_provider "${provider^^}"
                ;;
            3) _revert_dns ;;
            4) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
    done
}

run_speedtest() {
    _install_speedtest_cli() {
        if command -v speedtest &>/dev/null && speedtest --version 2>/dev/null | grep -qi "OOKLA"; then
            return 0
        fi
        log_message "INFO" "INSTALLING OFFICIAL OOKLA SPEEDTEST CLI..."

        if curl -fsSL https://install.speedtest.net/app/cli/install.deb.sh | bash; then
            if command -v speedtest &>/dev/null; then
                log_message "SUCCESS" "SPEEDTEST CLI INSTALLED VIA DEB."
                return 0
            fi
        else
            log_message "WARNING" "DEB INSTALLER FAILED OR NOT SUPPORTED ON THIS DISTRO."
        fi

        if command -v snap &>/dev/null; then
            if snap install speedtest --channel=stable 2>/dev/null; then
                if command -v speedtest &>/dev/null; then
                    log_message "SUCCESS" "SPEEDTEST CLI INSTALLED VIA SNAP."
                    return 0
                fi
            else
                log_message "WARNING" "SNAP INSTALL FAILED."
            fi
        else
            log_message "WARNING" "SNAP NOT AVAILABLE ON THIS SYSTEM."
        fi

        ARCH=$(uname -m)
        URL=""
        case "$ARCH" in
            x86_64|amd64) URL="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-amd64.tgz" ;;
            aarch64|arm64) URL="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-arm64.tgz" ;;
            armv7l) URL="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-armhf.tgz" ;;
            *) URL="" ;;
        esac
        if [[ -n "$URL" ]]; then
            TMPDIR=$(mktemp -d)
            if curl -fsSL "$URL" -o "$TMPDIR/s.tgz" && tar -xzf "$TMPDIR/s.tgz" -C "$TMPDIR"; then
                install -m 0755 "$TMPDIR/speedtest" /usr/local/bin/speedtest 2>/dev/null || cp "$TMPDIR/speedtest" /usr/local/bin/speedtest
                if command -v speedtest &>/dev/null; then
                    log_message "SUCCESS" "SPEEDTEST CLI INSTALLED FROM DIRECT BINARY."
                    rm -rf "$TMPDIR"
                    return 0
                fi
            fi
            rm -rf "$TMPDIR"
        fi

        log_message "ERROR" "SPEEDTEST CLI INSTALLATION FAILED."
        return 1
    }

    if ! _install_speedtest_cli; then
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi

    clear
    echo -e "${B_CYAN}--- SERVER INTERNET SPEED TEST (SPEEDTEST) ---${C_RESET}\n"
    echo -e "${C_WHITE}THIS SECTION MEASURES YOUR DOWNLOAD/UPLOAD AND PING USING THE OFFICIAL OOKLA TOOL.${C_RESET}\n"
    log_message "INFO" "RUNNING SPEEDTEST..."

    speedtest --accept-license --accept-gdpr || log_message "ERROR" "SPEEDTEST FAILED."

    log_message "SUCCESS" "SPEEDTEST COMPLETED."
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

is_valid_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$ || "$ip" =~ ^(([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])) || "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

run_packet_loss_test() {
    clear
    echo -e "${B_CYAN}--- PACKET LOSS TEST BETWEEN SERVERS (MTR) ---${C_RESET}\n"
    if ! command -v mtr &> /dev/null || ! command -v jq &> /dev/null; then
        log_message "ERROR" "MTR AND JQ TOOLS ARE REQUIRED FOR THIS TEST. PLEASE INSTALL THEM."
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi

    local target_ip
    echo -e "${B_MAGENTA}PLEASE ENTER TARGET SERVER IP:${C_RESET}"
    read -e -r target_ip

    if ! is_valid_ip "$target_ip"; then
        log_message "ERROR" "THE IP ADDRESS ENTERED IS NOT VALID."; sleep 2
        return
    fi
    clear
    echo -e "${B_CYAN}--- PACKET LOSS TEST BETWEEN SERVERS (MTR) ---${C_RESET}\n"
    echo -e "\n${C_YELLOW}RUNNING MTR TEST FOR TARGET ${target_ip}... (THIS TAKES ABOUT 1 MINUTE)${C_RESET}"
    echo -e "${C_CYAN}PRESS CTRL+C TO CANCEL AND RETURN TO MENU.${C_RESET}\n"
    
    local MTR_JSON
    (
        trap '' INT
        MTR_JSON=$(mtr -j -c 50 --no-dns "$target_ip")
    )

    if ! echo "$MTR_JSON" | jq . > /dev/null 2>&1; then
        log_message "ERROR" "PARSING FAILED. MTR DID NOT PRODUCE VALID OUTPUT OR WAS CANCELED."
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi

    echo -e "${B_BLUE}-----------------------------------------------------------------------------------------${C_RESET}"
    printf "%-4s%-3s%-22s %-8s %-5s %-7s %-7s %-7s %-7s %-7s\n" " " "" "HOST" "LOSS%" "SNT" "LAST" "AVG" "BEST" "WRST" "STDEV"
    
    echo "$MTR_JSON" | jq -c '.report.hubs[]' | while IFS= read -r line; do
        local count host loss snt last avg best wrst stdev
        count=$(echo "$line" | jq -r '.count')
        host=$(echo "$line" | jq -r '.host')
        loss=$(echo "$line" | jq -r '."Loss%"')
        snt=$(echo "$line" | jq -r '.Snt')
        last=$(echo "$line" | jq -r '.Last')
        avg=$(echo "$line" | jq -r '.Avg')
        best=$(echo "$line" | jq -r '.Best')
        wrst=$(echo "$line" | jq -r '.Wrst')
        stdev=$(echo "$line" | jq -r '.StDev')
        printf " %-3s|-- %-22s %-7.1f%% %-5.0f %-7.1f %-7.1f %-7.1f %-7.1f %-7.1f\n" "$count." "$host" "$loss" "$snt" "$last" "$avg" "$best" "$wrst" "$stdev"
    done
    echo -e "${B_BLUE}-----------------------------------------------------------------------------------------${C_RESET}"
    log_message "SUCCESS" "MTR TEST COMPLETED."
    
    echo -e "${B_CYAN}--- AUTOMATED ANALYSIS ---${N}\n"

    local first_hop_loss final_loss final_avg_ping
    first_hop_loss=$(echo "$MTR_JSON" | jq -r '.report.hubs[0]."Loss%"')
    final_loss=$(echo "$MTR_JSON" | jq -r '.report.hubs[-1]."Loss%"')
    final_avg_ping=$(echo "$MTR_JSON" | jq -r '.report.hubs[-1].Avg')

    echo -e "${C_WHITE}▪️ PACKET LOSS AT SOURCE (HOP 1):${N} ${Y}${first_hop_loss:-0}%${N}"
    echo -e "${C_WHITE}▪️ PACKET LOSS TO DESTINATION:${N} ${Y}${final_loss:-0}%${N}"
    echo -e "${C_WHITE}▪️ AVERAGE PING TO DESTINATION:${N} ${Y}${final_avg_ping:-0} ms${N}\n"

    if (( $(echo "$first_hop_loss > 10" | bc -l) )); then
        echo -e " ${R}❌ RESULT: VERY POOR CONNECTION.${N}"
        echo -e "   REASON: SEVERE PACKET LOSS AT SOURCE (${first_hop_loss}%) INDICATES SERIOUS NETWORK ISSUE."
    elif (( $(echo "$final_loss > 5" | bc -l) )); then
        echo -e " ${R}❌ RESULT: VERY POOR CONNECTION.${N}"
        echo -e "   REASON: HIGH PACKET LOSS AT DESTINATION (${final_loss}%)."
    elif (( $(echo "$final_loss > 0" | bc -l) )); then
        echo -e " ${Y}⚠️ RESULT: POOR CONNECTION.${N}"
        echo -e "   REASON: SOME PACKET LOSS AT DESTINATION (${final_loss}%)."
    elif (( $(echo "$final_avg_ping > 200" | bc -l) )); then
        echo -e " ${B}🟡 RESULT: ACCEPTABLE BUT HIGH LATENCY.${N}"
        echo -e "   PACKET LOSS IS 0%, BUT PING IS HIGH (${final_avg_ping}ms)."
    else
        echo -e " ${G}✅ RESULT: GOOD AND STABLE CONNECTION.${N}"
        echo -e "   PACKET LOSS 0% AND GOOD PING."
    fi

    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

manage_ip_health_check() {
    while true; do
        clear
        echo -e "${B_CYAN}--- IP HEALTH CHECK ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "TEST 1 (IP.CHECK.PLACE)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "TEST 2 (BENCH.OPENODE.XYZ)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "TEST 3 (GIT.IO/JRW8R)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "BACK"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"
        read -e -r choice

        case $choice in
            1) (trap '' INT; clear; log_message "INFO" "RUNNING TEST 1..."; bash <(curl -Ls IP.Check.Place) -l en -4); break ;;
            2) (trap '' INT; clear; log_message "INFO" "RUNNING TEST 2..."; bash <(curl -L -s https://bench.openode.xyz/multi_check.sh)); break ;;
            3) (trap '' INT; clear; log_message "INFO" "RUNNING TEST 3..."; bash <(curl -L -s https://git.io/JRw8R) -E en -M 4); break ;;
            4) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

manage_network_optimization() {
    while true; do
        clear
        stty sane
        echo -e "${B_CYAN}--- NETWORK AND CONNECTION OPTIMIZATION ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "MANAGE TCP OPTIMIZERS (BBR, HYBLA, CUBIC)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "CUSTOM SYSCTL OPTIMIZER"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "CUSTOM QLEEN & MTU OPTIMIZER (PERSISTENT)"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "4" "DOMESTIC ANTI-SANCTION DNS"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "MANAGE AND FIND BEST DNS"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "6" "SETUP SECURE DNS (DOH/DOT)"
        printf "  ${C_YELLOW}%2d)${B_YELLOW} %s\n" "7" "NETWORK BASE OPTIMIZATION (ADVANCED & PERSISTENT)"
        printf "  ${C_YELLOW}%2d)${B_WHITE} %s\n" "8" "SERVER INTERNET SPEED TEST (SPEEDTEST)"
        printf "  ${C_YELLOW}%2d)${B_WHITE} %s\n" "9" "PACKET LOSS TEST BETWEEN SERVERS (MTR)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "10" "IP HEALTH CHECK"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "11" "BACK TO MAIN MENU"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1) manage_tcp_optimizers ;; 2) manage_custom_sysctl ;; 3) manage_tc_qleen_mtu ;;
            4) manage_sanction_dns ;; 5) manage_dns ;;
            6) manage_secure_dns ;; 7) run_as_bbr_optimization ;; 8) run_speedtest ;;
            9) run_packet_loss_test ;; 10) manage_ip_health_check ;;
            11) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
}

# --- MENU 3 FUNCTIONS (SECURITY AND ACCESS - EXACT TRANSFER) ---

manage_firewall() {
    _resolve_firewall_conflicts() {
        if systemctl is-active --quiet "firewalld.service" &>/dev/null; then
            log_message "WARNING" "CONFLICTING SERVICE 'FIREWALLD' DETECTED. DISABLING AUTOMATICALLY..."
            systemctl stop firewalld.service &>/dev/null
            systemctl disable firewalld.service &>/dev/null
            systemctl mask firewalld.service &>/dev/null
            log_message "SUCCESS" "FIREWALLD SERVICE DISABLED AND MASKED SUCCESSFULLY."
            echo -e "${G}FIREWALLD CONFLICT RESOLVED.${N}"
            sleep 2
        fi
        local conflict_service=""
        if systemctl list-units --full -all | grep -q 'netfilter-persistent.service'; then
            conflict_service="netfilter-persistent"
        elif systemctl list-units --full -all | grep -q 'iptables-persistent.service'; then
            conflict_service="iptables-persistent"
        fi
        if [ -n "$conflict_service" ]; then
            if systemctl is-active --quiet "${conflict_service}.service" || systemctl is-enabled --quiet "${conflict_service}.service"; then
                log_message "WARNING" "CONFLICTING SERVICE '${conflict_service}' DETECTED. DISABLING AUTOMATICALLY..."
                systemctl stop "${conflict_service}.service" &>/dev/null
                systemctl disable "${conflict_service}.service" &>/dev/null
                systemctl mask "${conflict_service}.service" &>/dev/null
                rm -f /etc/iptables/rules.v4 /etc/iptables/rules.v6 &>/dev/null
                log_message "SUCCESS" "SERVICE ${conflict_service} DISABLED AND MASKED SUCCESSFULLY."
                echo -e "${G}CONFLICTING SERVICE ${conflict_service} REMOVED.${N}"
                sleep 2
            fi
        fi
        return 0
    }

    _manage_ping_submenu() {
        local UFW_RULES_FILE_V4="/etc/ufw/before.rules"
        local UFW_RULES_FILE_V6="/etc/ufw/before6.rules"
        local ICMP_V4_PARAMS=("-p" "icmp" "--icmp-type" "echo-request")
        local ICMP_V6_PARAMS=("-p" "icmpv6" "--icmpv6-type" "echo-request")
        local V4_ACCEPT_RULE="-A ufw-before-input ${ICMP_V4_PARAMS[*]} -j ACCEPT"
        local V4_DROP_RULE="-A ufw-before-input ${ICMP_V4_PARAMS[*]} -j DROP"
        local V6_ACCEPT_RULE="-A ufw6-before-input ${ICMP_V6_PARAMS[*]} -j ACCEPT"
        local V6_DROP_RULE="-A ufw6-before-input ${ICMP_V6_PARAMS[*]} -j DROP"

        while true; do
            clear
            echo -e "${B_CYAN}--- SERVER PING MANAGEMENT (ICMP) ---${C_RESET}\n"
            local ping_status_val
            ping_status_val=$(check_ping_status)
            local ping_status_display
            if [[ "$ping_status_val" == "BLOCKED" ]]; then
                ping_status_display="${R}DISABLED (BLOCKED)${N}"
            else
                ping_status_display="${G}ENABLED (ALLOWED)${N}"
            fi
            echo -e "CURRENT PING STATUS: ${ping_status_display}\n"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "ENABLE PING"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "DISABLE PING"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK TO FIREWALL MENU"
            echo -e "${B_BLUE}-------------------------------------------------------------${C_RESET}"
            printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"
            read -e -r choice

            case $choice in
                1) 
                    log_message "INFO" "ENABLING PING..."
                    create_backup "$UFW_RULES_FILE_V4"
                    touch "$UFW_RULES_FILE_V6" && create_backup "$UFW_RULES_FILE_V6"
                    sed -i "\|$V4_DROP_RULE|d" "$UFW_RULES_FILE_V4"
                    sed -i "\|$V6_DROP_RULE|d" "$UFW_RULES_FILE_V6"
                    grep -qF -- "$V4_ACCEPT_RULE" "$UFW_RULES_FILE_V4" || sed -i '/^# End required lines/a '"$V4_ACCEPT_RULE" "$UFW_RULES_FILE_V4"
                    grep -qF -- "$V6_ACCEPT_RULE" "$UFW_RULES_FILE_V6" || sed -i '/^COMMIT/i '"$V6_ACCEPT_RULE" "$UFW_RULES_FILE_V6"
                    while iptables -D ufw-before-input "${ICMP_V4_PARAMS[@]}" -j DROP &>/dev/null; do :; done
                    while ip6tables -D ufw6-before-input "${ICMP_V6_PARAMS[@]}" -j DROP &>/dev/null; do :; done
                    iptables -C ufw-before-input "${ICMP_V4_PARAMS[@]}" -j ACCEPT &>/dev/null || iptables -I ufw-before-input 1 "${ICMP_V4_PARAMS[@]}" -j ACCEPT
                    ip6tables -C ufw6-before-input "${ICMP_V6_PARAMS[@]}" -j ACCEPT &>/dev/null || ip6tables -I ufw6-before-input 1 "${ICMP_V6_PARAMS[@]}" -j ACCEPT
                    log_message "SUCCESS" "PING HAS BEEN ENABLED."
                    ;;
                2) 
                    log_message "INFO" "DISABLING PING..."
                    create_backup "$UFW_RULES_FILE_V4"
                    touch "$UFW_RULES_FILE_V6" && create_backup "$UFW_RULES_FILE_V6"
                    sed -i "\|$V4_ACCEPT_RULE|d" "$UFW_RULES_FILE_V4"
                    sed -i "\|$V6_ACCEPT_RULE|d" "$UFW_RULES_FILE_V6"
                    grep -qF -- "$V4_DROP_RULE" "$UFW_RULES_FILE_V4" || sed -i '/^# End required lines/a '"$V4_DROP_RULE" "$UFW_RULES_FILE_V4"
                    grep -qF -- "$V6_DROP_RULE" "$UFW_RULES_FILE_V6" || sed -i '/^COMMIT/i '"$V6_DROP_RULE" "$UFW_RULES_FILE_V6"
                    while iptables -D ufw-before-input "${ICMP_V4_PARAMS[@]}" -j ACCEPT &>/dev/null; do :; done
                    while ip6tables -D ufw6-before-input "${ICMP_V6_PARAMS[@]}" -j ACCEPT &>/dev/null; do :; done
                    iptables -C ufw-before-input "${ICMP_V4_PARAMS[@]}" -j DROP &>/dev/null || iptables -I ufw-before-input 1 "${ICMP_V4_PARAMS[@]}" -j DROP
                    ip6tables -C ufw6-before-input "${ICMP_V6_PARAMS[@]}" -j DROP &>/dev/null || ip6tables -I ufw6-before-input 1 "${ICMP_V6_PARAMS[@]}" -j DROP
                    log_message "SUCCESS" "PING HAS BEEN DISABLED."
                    ;;
                3) return ;;
                *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
            esac
        done
    }

    if ! command -v ufw &> /dev/null; then
        log_message "WARNING" "UFW IS NOT INSTALLED. ATTEMPTING TO INSTALL AUTOMATICALLY..."
        if ! install_dependencies; then
            log_message "ERROR" "AUTOMATIC INSTALLATION OF UFW FAILED. PLEASE INSTALL IT MANUALLY."
            read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
            return
        fi
        sleep 1
    fi

    _resolve_firewall_conflicts

    while true; do
        clear
        echo -e "${B_CYAN}--- FIREWALL MANAGEMENT (UFW) ---${C_RESET}\n"
        local UFW_STATUS
        if ufw status | grep -q "Status: active"; then
            UFW_STATUS="${G}ACTIVE${N}"
        else
            UFW_STATUS="${R}INACTIVE${N}"
        fi
        echo -e "  ${C_WHITE}CURRENT FIREWALL STATUS:${C_RESET} ${UFW_STATUS}\n"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "ENABLE FIREWALL"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "DISABLE FIREWALL"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "SHOW STATUS AND RULES"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "ALLOW A PORT"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "DELETE RULE BY NUMBER"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "6" "AUTO-ADD OPEN PORTS"
        printf "  ${C_YELLOW}%2d)${B_YELLOW} %s\n" "7" "MANAGE SERVER PING (ICMP)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "8" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                log_message "INFO" "ENABLING FIREWALL..."
                local ssh_port
                ssh_port=$(ss -lntp | grep sshd | awk '{print $4}' | sed 's/.*://' | head -n 1)
                if [[ -n "$ssh_port" ]]; then
                    echo -e "${Y}SSH PORT (${ssh_port}) DETECTED AND ALLOWED.${N}"
                    ufw allow "$ssh_port/tcp" >/dev/null 2>&1
                else
                    log_message "WARNING" "COULD NOT DETECT SSH PORT! MAKE SURE TO ALLOW IT MANUALLY."
                fi
                ufw default deny incoming >/dev/null 2>&1
                ufw default allow outgoing >/dev/null 2>&1
                echo "y" | ufw enable
                systemctl enable ufw.service >/dev/null 2>&1
                log_message "SUCCESS" "UFW FIREWALL ENABLED AND SECURED WITH DEFAULT RULES."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                log_message "INFO" "DISABLING FIREWALL..."
                ufw disable
                log_message "SUCCESS" "UFW FIREWALL DISABLED."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                clear
                echo -e "${B_CYAN}--- CURRENT FIREWALL RULES ---${C_RESET}\n"
                ufw status verbose
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            4) 
                printf "%b" "${B_MAGENTA}ENTER PORT TO ALLOW (E.G., 443 OR 8000:9000): ${C_RESET}"
                read -e -r port_to_allow
                if [[ -n "$port_to_allow" ]]; then
                    ufw allow "$port_to_allow"
                    log_message "SUCCESS" "REQUEST TO ADD RULE FOR '${port_to_allow}' SENT TO THE FIREWALL."
                else
                    log_message "WARNING" "INVALID INPUT."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            5) 
                clear
                echo -e "${B_CYAN}--- RULES TO DELETE (NUMBERED) ---${C_RESET}\n"
                ufw status numbered
                printf "\n%b" "${B_MAGENTA}ENTER RULE NUMBER TO DELETE: ${C_RESET}"
                read -e -r rule_to_delete
                if [[ "$rule_to_delete" =~ ^[0-9]+$ ]]; then
                    yes | ufw delete "$rule_to_delete"
                    log_message "SUCCESS" "REQUEST TO DELETE RULE NUMBER ${rule_to_delete} SENT."
                else
                    log_message "WARNING" "INVALID RULE NUMBER."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            6) 
                clear
                echo -e "${B_CYAN}--- AUTO-ADDING OPEN PORTS ---${C_RESET}\n"
                local ssh_port
                ssh_port=$(ss -lntp | grep sshd | awk '{print $4}' | sed 's/.*://' | head -n 1)
                mapfile -t listening_ports < <(ss -lntu | grep 'LISTEN' | awk '{print $5}' | sed 's/.*://' | sort -un)
                mapfile -t all_ports_to_allow < <(printf "%s\n" "${listening_ports[@]}" "$ssh_port" | sort -un)

                if [ ${#all_ports_to_allow[@]} -eq 0 ]; then
                    log_message "INFO" "NO ACTIVE LISTENING PORTS FOUND TO ADD."
                else
                    echo -e "${C_WHITE}THE FOLLOWING PORTS WERE DETECTED AND RULES WERE ADDED:${N}\n"
                    printf "${B_BLUE}+------------+-----------------+----------------------+----------------+${C_RESET}\n"
                    printf "${B_BLUE}| ${B_YELLOW}%-10s ${B_BLUE}| ${B_YELLOW}%-15s ${B_BLUE}| ${B_YELLOW}%-20s ${B_BLUE}| ${B_YELLOW}%-14s ${B_BLUE}|${C_RESET}\n" "PORT" "PROTOCOL" "STATUS" "NOTE"
                    printf "${B_BLUE}+------------+-----------------+----------------------+----------------+${C_RESET}\n"
                    
                    for port in "${all_ports_to_allow[@]}"; do
                        if [[ -n "$port" ]]; then
                           ufw allow "$port" > /dev/null
                           local note=""
                           if [[ "$port" == "$ssh_port" ]]; then
                                note="SSH PORT"
                           fi
                           printf "${B_BLUE}|${N} %-10s ${B_BLUE}|${N} %-15s ${B_BLUE}|${N} ${G}%-20s ${B_BLUE}|${N} %-14s ${B_BLUE}|${N}\n" "$port" "TCP & UDP" "ALLOWED" "$note"
                        fi
                    done
                    printf "${B_BLUE}+------------+-----------------+----------------------+----------------+${C_RESET}\n"
                    
                    log_message "SUCCESS" "ALL ACTIVE LISTENING PORTS HAVE BEEN ALLOWED IN THE FIREWALL."
                    ufw reload >/dev/null
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            7) 
                _manage_ping_submenu
                ;;
            8)
                return
                ;;
            *)
                echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

manage_geoip_blocking() {
    if ! command -v ipset &>/dev/null; then
        log_message "INFO" "INSTALLING IPSET..."
        if ! apt-get install -y -qq ipset; then
            log_message "ERROR" "IPSET INSTALLATION FAILED."
            read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
            return
        fi
    fi

    _create_ipset_and_rule() {
        local set_name="$1"
        ipset create "$set_name" hash:net family inet -exist
        if ! iptables -C INPUT -m set --match-set "$set_name" src -j DROP &>/dev/null; then
            iptables -I INPUT 1 -m set --match-set "$set_name" src -j DROP
        fi
    }

    _block_country() {
        local country_code="$1"
        local upper_cc="${country_code^^}"
        local set_name="geoip-block-${upper_cc}"
        
        _create_ipset_and_rule "$set_name"

        log_message "INFO" "DOWNLOADING IP LIST FOR COUNTRY: $upper_cc"
        local zone_file_url="http://www.ipdeny.com/ipblocks/data/countries/${country_code}.zone"
        local temp_zone_file="/tmp/${country_code}.zone"
        
        if ! curl -sL --fail -o "$temp_zone_file" "$zone_file_url"; then
            log_message "ERROR" "FAILED TO DOWNLOAD IP LIST FOR $upper_cc. CHECK COUNTRY CODE."
            rm -f "$temp_zone_file"
            return
        fi

        log_message "INFO" "ADDING ${upper_cc} IPS TO FIREWALL BLACKLIST..."
        
        {
            echo "create ${set_name}-temp hash:net family inet -exist"
            awk '{print "add '"${set_name}-temp"' " $1}' "$temp_zone_file"
        } | ipset restore

        ipset swap "${set_name}-temp" "$set_name"
        ipset destroy "${set_name}-temp"

        rm -f "$temp_zone_file"
        log_message "SUCCESS" "ALL IP RANGES FOR $upper_cc BLOCKED SUCCESSFULLY."
    }

    _view_blocked_countries() {
        clear
        echo -e "${B_CYAN}--- BLOCKED COUNTRIES (VIA IPSET) ---${C_RESET}\n"
        printf "${B_BLUE}+----------------+-------------------------+${C_RESET}\n"
        printf "${B_BLUE}| ${B_YELLOW}%-14s ${B_BLUE}| ${B_YELLOW}%-23s ${B_BLUE}|${C_RESET}\n" "COUNTRY CODE" "BLOCKED IP RANGES"
        printf "${B_BLUE}+----------------+-------------------------+${C_RESET}\n"
        
        local sets
        mapfile -t sets < <(ipset list | grep -oP '(?<=Name: )geoip-block-\w+')
        
        if [ ${#sets[@]} -eq 0 ]; then
            printf "${B_BLUE}| %-40s |${C_RESET}\n" "NO COUNTRIES ARE CURRENTLY BLOCKED"
        else
            for set_name in "${sets[@]}"; do
                local cc num_entries
                cc=${set_name##*-} 
                num_entries=$(ipset list "$set_name" | grep -oP '(?<=Header: entries )\d+')
                printf "${B_BLUE}|${N} %-14s ${B_BLUE}|${N} %-23s ${B_BLUE}|${N}\n" "${cc^^}" "$num_entries"
            done
        fi
        printf "${B_BLUE}+----------------+-------------------------+${C_RESET}\n"
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
    }
    
    _unblock_all() {
        printf "%b" "${C_RED}ARE YOU SURE YOU WANT TO REMOVE ALL GEO-IP RULES? (Y/N): ${C_RESET}"
        read -e -r confirm
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            log_message "INFO" "OPERATION CANCELED."; return
        fi
        
        log_message "WARNING" "REMOVING ALL GEO-IP RULES AND LISTS..."
        ipset list | grep -oP '(?<=Name: )geoip-block-\w+' | while read -r set_name; do
            iptables -D INPUT -m set --match-set "$set_name" src -j DROP 2>/dev/null || true
            ipset destroy "$set_name" 2>/dev/null
        done
        log_message "SUCCESS" "ALL GEO-IP RULES REMOVED."
    }

    while true; do
        clear
        echo -e "${B_CYAN}--- COUNTRY BLOCKING (GEO-IP / IPSET) ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "1" "BLOCK A COUNTRY"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "VIEW BLOCKED COUNTRIES"
        printf "  ${C_YELLOW}%2d)${C_GREEN} %s\n" "3" "REMOVE ALL BLOCKING RULES"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                printf "%b" "${B_MAGENTA}ENTER 2-LETTER COUNTRY CODE (E.G., CN, RU, US): ${C_RESET}"; read -e -r country_code
                if [[ -z "$country_code" || ${#country_code} -ne 2 ]]; then
                    log_message "ERROR" "INVALID COUNTRY CODE."
                else
                    _block_country "${country_code,,}" 
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                _view_blocked_countries
                ;;
            3)
                _unblock_all
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            4)
                return
                ;;
            *)
                echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

manage_malware_scanners() {
    while true; do
        clear
        echo -e "${B_CYAN}--- MALWARE AND ROOTKIT SCANNERS ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "RUN CHKROOTKIT SCAN (FAST)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "INSTALL AND RUN RKHUNTER SCAN (COMPREHENSIVE)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                clear
                log_message "INFO" "STARTING CHKROOTKIT SCAN..."
                echo -e "${C_YELLOW}RUNNING CHKROOTKIT... THIS MAY TAKE A FEW MINUTES.${C_RESET}"
                local scan_output
                scan_output=$( (trap '' INT; chkrootkit) 2>&1 )
                
                echo -e "${B_CYAN}--- AUTOMATED ANALYSIS ---${C_RESET}"
                if echo "$scan_output" | grep -q "INFECTED"; then
                    echo -e "${R}RESULT: WARNING! INFECTED ITEMS FOUND.${N}"
                else
                    echo -e "${G}RESULT: NO OBVIOUS INFECTED ITEMS FOUND.${N}"
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                clear
                if ! command -v rkhunter &>/dev/null; then
                    log_message "WARNING" "RKHUNTER NOT FOUND. INSTALLING..."
                    install_dependencies
                fi
                log_message "INFO" "STARTING RKHUNTER SCAN..."
                echo -e "${C_YELLOW}RUNNING RKHUNTER... THIS MAY TAKE TIME.${C_RESET}"
                (
                    trap '' INT
                    rkhunter --check --sk
                )
                echo -e "\n${C_GREEN}SCAN FINISHED. CHECK LOG AT /var/log/rkhunter.log${C_RESET}"
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                return
                ;;
            *)
                echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

manage_lynis_audit() {
    while true; do
        clear
        echo -e "${B_CYAN}--- SECURITY AUDIT WITH LYNIS ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "INSTALL/UPDATE LYNIS"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "2" "RUN FULL SYSTEM AUDIT"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                log_message "INFO" "INSTALLING/UPDATING LYNIS..."
                install_dependencies
                log_message "SUCCESS" "LYNIS UPDATED."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                clear
                if ! command -v lynis &>/dev/null; then
                    log_message "ERROR" "LYNIS IS NOT INSTALLED."
                else
                    log_message "INFO" "STARTING LYNIS SYSTEM AUDIT..."
                    (
                        trap '' INT
                        lynis audit system
                    )
                    log_message "INFO" "AUDIT FINISHED. REPORT SAVED."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                return
                ;;
            *)
                echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

port_scanner_menu() {
    while true; do
        clear
        echo -e "${B_CYAN}--- PORT SCANNER (NMAP) ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "FAST SCAN (1000 COMMON PORTS)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "FULL SCAN (ALL PORTS - SLOW)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK"
        echo -e "${B_BLUE}---------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"
        read -e -r choice

        case $choice in
            1|2)
                if ! command -v nmap &> /dev/null; then
                    log_message "ERROR" "NMAP IS NOT INSTALLED. INSTALLING..."
                    install_dependencies
                fi
                printf "%b" "${B_MAGENTA}ENTER TARGET IP: ${C_RESET}"
                read -e -r target_ip
                if ! is_valid_ip "$target_ip"; then 
                    log_message "ERROR" "INVALID IP."
                else
                    echo -e "\n${C_YELLOW}SCANNING...${C_RESET}"
                    (
                        trap '' INT
                        if [ "$choice" -eq 1 ]; then
                            nmap --top-ports 1000 --open "$target_ip"
                        else
                            nmap -p- --open "$target_ip"
                        fi
                    )
                    log_message "SUCCESS" "SCAN COMPLETED."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
}

manage_ssh_port() {
    local sshd_config="/etc/ssh/sshd_config"
    echo -e "${B_CYAN}--- CHANGE SSH PORT ---${C_RESET}"
    local current_port
    current_port=$(grep "^Port " "$sshd_config" | head -1 | awk '{print $2}')
    echo -e "${C_WHITE}CURRENT PORT:${C_RESET} ${G}${current_port:-22}${N}"

    printf "%b" "${B_MAGENTA}ENTER NEW PORT (1024-65535): ${C_RESET}"; read -e -r new_port

    if [[ ! "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1024 ] || [ "$new_port" -gt 65535 ]; then
        log_message "ERROR" "INVALID PORT NUMBER."
        return
    fi
    
    if netstat -tuln | grep -q ":$new_port "; then
         log_message "ERROR" "PORT $new_port IS ALREADY IN USE."
         return
    fi

    cp "$sshd_config" "${sshd_config}.bak"
    sed -i '/^Port /d' "$sshd_config"
    sed -i '/^#Port /d' "$sshd_config"
    echo "Port $new_port" >> "$sshd_config"
    
    if systemctl restart ssh; then
         log_message "SUCCESS" "SSH PORT CHANGED TO $new_port."
    else
         log_message "ERROR" "FAILED TO RESTART SSH. RESTORING..."
         cp "${sshd_config}.bak" "$sshd_config"
         systemctl restart ssh
    fi
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

manage_ssh_root() {
  local sshd_config="/etc/ssh/sshd_config"
  echo -e "${B_CYAN}--- MANAGE ROOT LOGIN ---${C_RESET}\n"
  printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "ENABLE ROOT LOGIN (PASSWORD)"
  printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "DISABLE ROOT LOGIN (SECURE)"
  printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK"
  echo -e "${B_BLUE}-----------------------------------${C_RESET}"
  printf "%b" "${B_MAGENTA}SELECT OPTION: ${C_RESET}"; read -e -r choice

  case $choice in
    1)
      printf "%b" "${B_MAGENTA}ARE YOU SURE? (Y/N) ${C_RESET}"; read -e -r confirm
      if [[ "$confirm" =~ ^[yY]$ ]]; then
          passwd root
          sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' "$sshd_config"
          systemctl restart ssh
          log_message "SUCCESS" "ROOT LOGIN ENABLED."
      fi
      ;;
    2)
      sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' "$sshd_config"
      systemctl restart ssh
      log_message "SUCCESS" "ROOT LOGIN DISABLED (KEYS ONLY)."
      ;;
    3) return ;;
  esac
  read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

manage_ssh_access_submenu() {
    while true; do
        clear
        echo -e "${B_CYAN}--- SSH ACCESS MANAGEMENT ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "CHANGE SSH PORT"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "MANAGE ROOT LOGIN"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1) manage_ssh_port ;;
            2) manage_ssh_root ;;
            3) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
}

# --- MAIN MENU 3 ENTRY POINT ---
manage_security_access() {
    while true; do
        clear
        stty sane
        echo -e "${B_CYAN}--- SECURITY AND ACCESS MANAGEMENT ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "FIREWALL AND PING MANAGEMENT (UFW)"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "2" "GEO-IP BLOCKING (COUNTRY BLOCK)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "MALWARE AND ROOTKIT SCANNERS"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "SECURITY AUDIT WITH LYNIS"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "PORT SCANNER (NMAP)"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "6" "SSH ACCESS MANAGEMENT"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "7" "BACK TO MAIN MENU"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1) manage_firewall ;;
            2) manage_geoip_blocking ;;
            3) manage_malware_scanners ;;
            4) manage_lynis_audit ;;
            5) port_scanner_menu ;;
            6) manage_ssh_access_submenu ;;
            7) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
}

# --- MAIN LOOP ---
main() {
    apply_theme
    init_environment
    clear
    
    while true; do
      stty sane 
      clear; show_banner; show_enhanced_system_status
      echo -e "${C_WHITE}NOTE: CURRENTLY MENUS 1, 2, AND 3 ARE ACTIVE.${C_RESET}\n"
      
      printf "   ${C_YELLOW}%2d) ${B_GREEN}%s\n" "1" "PANEL INSTALLATION AND MANAGEMENT"
      printf "   ${C_YELLOW}%2d) ${B_CYAN}%s\n" "2" "NETWORK AND CONNECTION OPTIMIZATION"
      printf "   ${C_YELLOW}%2d) ${B_CYAN}%s\n" "3" "SECURITY AND ACCESS MANAGEMENT"
      printf "\n   ${C_YELLOW}%2d) ${C_RED}%s\n" "10" "EXIT"
      echo -e "${B_BLUE}------------------------------------------------------------${C_RESET}"
      printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"
      read -e -r main_choice

      case $main_choice in
        1) manage_vpn_panels ;;
        2) manage_network_optimization ;;
        3) manage_security_access ;;
        10) clear; log_message "INFO" "EXITING SCRIPT."; echo -e "\n${B_CYAN}GOODBYE!${C_RESET}\n"; stty sane; exit 0 ;;
        *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; read -n 1 -s -r -p "" ;;
      esac
    done
}
# #############################################################################
# --- MENU 4: SYSTEM AND MANAGEMENT TOOLS ---
# #############################################################################

# --- 4.1 BACKUP MANAGEMENT ---
manage_backups() {
    local BACKUP_ROOT="/root/backups"
    mkdir -p "$BACKUP_ROOT"

    _backup_create() {
        clear
        echo -e "${B_CYAN}--- CREATE NEW BACKUP ---${C_RESET}\n"
        echo -e "${B_MAGENTA}ENTER FULL PATH OF DIRECTORY TO BACKUP (E.G., /var/www):${N}"
        printf "%b" "${C_CYAN}> ${C_RESET}"; read -e -r source_dir
        
        if [ ! -d "$source_dir" ]; then
            log_message "ERROR" "SOURCE DIRECTORY NOT FOUND: $source_dir"
            read -n 1 -s -r -p "PRESS ANY KEY..."
            return
        fi

        local filename="backup-$(basename "$source_dir")-$(date +%Y%m%d-%H%M%S).tar.gz"
        local dest_file="${BACKUP_ROOT}/${filename}"

        log_message "INFO" "CREATING BACKUP OF '$source_dir'..."
        echo -e "\n${C_YELLOW}COMPRESSING FILES... PLEASE WAIT.${C_RESET}"
        
        if tar -czvf "$dest_file" -C "$(dirname "$source_dir")" "$(basename "$source_dir")"; then
            log_message "SUCCESS" "BACKUP CREATED SUCCESSFULLY AT: $dest_file"
            echo -e "\n${G}BACKUP SIZE: $(du -h "$dest_file" | awk '{print $1}')${N}"
        else
            log_message "ERROR" "BACKUP CREATION FAILED."
            rm -f "$dest_file"
        fi
        read -n 1 -s -r -p "PRESS ANY KEY..."
    }

    _backup_restore() {
        clear
        echo -e "${B_CYAN}--- RESTORE FROM BACKUP ---${C_RESET}\n"
        echo -e "${C_WHITE}AVAILABLE BACKUPS IN ${BACKUP_ROOT}:${N}"
        ls -1A "$BACKUP_ROOT"/*.tar.gz 2>/dev/null | xargs -n 1 basename
        
        echo -e "\n${B_MAGENTA}ENTER FULL BACKUP FILENAME TO RESTORE:${N}"
        printf "%b" "${C_CYAN}> ${C_RESET}"; read -e -r backup_file
        
        local full_backup_path="${BACKUP_ROOT}/${backup_file}"
        if [ ! -f "$full_backup_path" ]; then
            log_message "ERROR" "BACKUP FILE NOT FOUND: $full_backup_path"
            read -n 1 -s -r -p "PRESS ANY KEY..."
            return
        fi

        echo -e "${B_MAGENTA}ENTER DESTINATION PATH (PRESS ENTER FOR ROOT /):${N}"
        printf "%b" "${C_CYAN}> ${C_RESET}"; read -e -r dest_dir
        
        dest_dir=${dest_dir:-/}
        mkdir -p "$dest_dir"

        log_message "INFO" "RESTORING '$backup_file' TO '$dest_dir'..."
        if tar -xzvf "$full_backup_path" -C "$dest_dir"; then
            log_message "SUCCESS" "RESTORE COMPLETED."
        else
            log_message "ERROR" "RESTORE FAILED."
        fi
        read -n 1 -s -r -p "PRESS ANY KEY..."
    }

    _backup_schedule() {
        local CRON_ID="# IRNET_AUTO_BACKUP"
        local SCRIPT_PATH="/etc/irnet/auto_backup.sh"
        
        clear
        echo -e "${B_CYAN}--- SCHEDULE AUTOMATIC BACKUP ---${C_RESET}\n"
        echo -e "${B_MAGENTA}ENTER DIRECTORY PATH TO BACKUP AUTOMATICALLY:${N}"
        printf "%b" "${C_CYAN}> ${C_RESET}"; read -e -r source_dir
        
        if [ ! -d "$source_dir" ]; then
            log_message "ERROR" "SOURCE DIRECTORY NOT FOUND: $source_dir"
            read -n 1 -s -r -p "PRESS ANY KEY..."
            return
        fi

        log_message "INFO" "CREATING AUTOMATED BACKUP SCRIPT..."
        mkdir -p /etc/irnet
        tee "$SCRIPT_PATH" > /dev/null <<EOF
#!/bin/bash
BACKUP_ROOT="$BACKUP_ROOT"
SOURCE_DIR="$source_dir"
FILENAME="auto-backup-\$(basename "\$SOURCE_DIR")-\$(date +\%Y\%m\%d).tar.gz"
DEST_FILE="\${BACKUP_ROOT}/\${FILENAME}"
# Remove backups older than 7 days
find "\$BACKUP_ROOT" -type f -name "auto-backup-*.tar.gz" -mtime +7 -delete
# Create new backup
tar -czf "\$DEST_FILE" -C "\$(dirname "\$SOURCE_DIR")" "\$(basename "\$SOURCE_DIR")"
EOF
        chmod +x "$SCRIPT_PATH"

        local cron_job="0 2 * * * $SCRIPT_PATH $CRON_ID" # Every day at 2 AM
        (crontab -l 2>/dev/null | grep -v "$CRON_ID"; echo "$cron_job") | crontab -
        log_message "SUCCESS" "AUTOMATED BACKUP SCHEDULED FOR $source_dir (DAILY AT 2:00 AM)."
        read -n 1 -s -r -p "PRESS ANY KEY..."
    }

    while true; do
        clear
        echo -e "${B_CYAN}--- BACKUP MANAGEMENT ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "CREATE MANUAL BACKUP"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "RESTORE FROM BACKUP"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "3" "SCHEDULE AUTOMATIC DAILY BACKUP"
        printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "4" "REMOVE AUTOMATIC BACKUP SCHEDULE"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1) _backup_create ;;
            2) _backup_restore ;;
            3) _backup_schedule ;;
            4) 
                (crontab -l 2>/dev/null | grep -v "# IRNET_AUTO_BACKUP") | crontab -
                log_message "SUCCESS" "AUTOMATED BACKUP SCHEDULE REMOVED."
                read -n 1 -s -r -p "PRESS ANY KEY..."
                ;;
            5) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
}

# --- 4.2 SYSTEM USER MANAGEMENT ---
manage_system_users() {
    _get_visual_length() {
        local clean_string
        clean_string=$(echo -e "$1" | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g')
        echo "${#clean_string}"
    }

    _user_add_interactive() {
        clear
        echo -e "${B_CYAN}--- ADD NEW USER ---${C_RESET}\n"
        printf "%b" "${B_MAGENTA}ENTER NEW USERNAME: ${C_RESET}"; read -e -r username
        if [ -z "$username" ]; then log_message "ERROR" "USERNAME CANNOT BE EMPTY."; return; fi

        printf "%b" "${B_MAGENTA}ENTER PASSWORD FOR '$username': ${C_RESET}"; read -s -r user_password; echo
        if [ -z "$user_password" ]; then log_message "ERROR" "PASSWORD CANNOT BE EMPTY."; return; fi
        
        if ! useradd -m -s /bin/bash "$username" 2>/dev/null; then
            log_message "ERROR" "FAILED TO CREATE USER '$username'. MAYBE IT ALREADY EXISTS."; return;
        fi
        echo "${username}:${user_password}" | chpasswd
        log_message "SUCCESS" "USER '$username' CREATED SUCCESSFULLY."

        printf "%b" "${B_MAGENTA}GRANT SUDO ACCESS? (Y/N): ${C_RESET}"; read -e -r sudo_choice
        if [[ "$sudo_choice" =~ ^[Yy]$ ]]; then
            usermod -aG sudo "$username"
            log_message "SUCCESS" "SUDO ACCESS GRANTED TO '$username'."
        fi
    }

    while true; do
        clear
        echo -e "${B_CYAN}--- SYSTEM USER MANAGEMENT ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "1" "ADD NEW USER"
        printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "2" "DELETE USER"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "LIST USERS"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "CHANGE USER PASSWORD"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                _user_add_interactive
                read -n 1 -s -r -p "PRESS ANY KEY..."
                ;;
            2)
                echo -e "${B_MAGENTA}ENTER USERNAME TO DELETE:${N}"
                printf "%b" "${C_CYAN}> ${C_RESET}"; read -e -r username
                if [ -z "$username" ] || [ "$username" == "root" ]; then log_message "ERROR" "INVALID USERNAME."; continue; fi
                
                if pkill -u "$username"; then
                    log_message "INFO" "KILLED ACTIVE PROCESSES FOR USER '$username'."
                    sleep 1
                fi

                printf "%b" "${C_RED}DELETE HOME DIRECTORY TOO? (Y/N): ${C_RESET}"; read -e -r del_home_choice
                if [[ "$del_home_choice" =~ ^[Yy]$ ]]; then
                    deluser --remove-home "$username"
                else
                    deluser "$username"
                fi
                log_message "SUCCESS" "USER '$username' DELETED."
                read -n 1 -s -r -p "PRESS ANY KEY..."
                ;;
            3)
                clear
                echo -e "${B_CYAN}--- SYSTEM USERS (UID >= 1000) ---${C_RESET}\n"
                awk -F: '($3 >= 1000 && $1 != "nobody") {print "USER: " $1 " | UID: " $3 " | HOME: " $6}' /etc/passwd
                read -n 1 -s -r -p "PRESS ANY KEY..."
                ;;
            4)
                printf "%b" "${B_MAGENTA}ENTER USERNAME TO CHANGE PASSWORD: ${C_RESET}"; read -e -r username
                if [ -z "$username" ]; then log_message "ERROR" "USERNAME CANNOT BE EMPTY."; continue; fi
                passwd "$username"
                read -n 1 -s -r -p "PRESS ANY KEY..."
                ;;
            5)
                return
                ;;
            *)
                echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

# --- 4.3 SYSTEMD SERVICE MANAGEMENT ---
manage_systemd_services() {
    while true; do
        clear
        echo -e "${B_CYAN}--- SYSTEMD SERVICE MANAGEMENT ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "LIST ALL RUNNING SERVICES"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "MANAGE A SPECIFIC SERVICE"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                clear
                echo -e "${B_CYAN}--- RUNNING SERVICES ---${C_RESET}\n"
                systemctl list-units --type=service --state=running --no-pager
                read -n 1 -s -r -p "PRESS ANY KEY..."
                ;;
            2)
                printf "%b" "${B_MAGENTA}ENTER SERVICE NAME (E.G. nginx): ${C_RESET}"; read -e -r service_name
                if [ -z "$service_name" ]; then log_message "ERROR" "SERVICE NAME CANNOT BE EMPTY."; continue; fi

                while true; do
                    clear
                    echo -e "${B_CYAN}--- MANAGE SERVICE: ${service_name} ---${C_RESET}\n"
                    systemctl status "$service_name" --no-pager
                    echo -e "\n${B_BLUE}----------------------------------------------------${C_RESET}"
                    printf "  ${C_YELLOW}%s\n" "1) START  2) STOP  3) RESTART  4) RELOAD"
                    printf "  ${C_YELLOW}%s\n" "5) ENABLE (ON BOOT)  6) DISABLE (ON BOOT)  7) BACK"
                    echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
                    printf "%b" "${B_MAGENTA}OPTION: ${C_RESET}"; read -e -r action_choice

                    case $action_choice in
                        1) systemctl start "$service_name" ;;
                        2) systemctl stop "$service_name" ;;
                        3) systemctl restart "$service_name" ;;
                        4) systemctl reload "$service_name" ;;
                        5) systemctl enable "$service_name" ;;
                        6) systemctl disable "$service_name" ;;
                        7) break ;;
                        *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
                    esac
                done
                ;;
            3)
                return
                ;;
            *)
                echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

# --- 4.4 CRON JOB MANAGEMENT ---
manage_cron_jobs() {
    while true; do
        clear
        echo -e "${B_CYAN}--- CRON JOB MANAGEMENT ---${C_RESET}\n"
        echo -e "${C_WHITE}CURRENT ROOT CRON JOBS:${N}"
        crontab -l 2>/dev/null | cat -n
        echo -e "\n${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "ADD NEW CRON JOB"
        printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "2" "DELETE CRON JOB BY LINE NUMBER"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                echo -e "${B_MAGENTA}ENTER SCHEDULE (E.G. */15 * * * *):${N}"
                printf "%b" "${C_CYAN}> ${C_RESET}"; read -e -r schedule
                
                echo -e "${B_MAGENTA}ENTER COMMAND (E.G. /usr/bin/apt update):${N}"
                printf "%b" "${C_CYAN}> ${C_RESET}"; read -e -r command
                
                if [[ -n "$schedule" && -n "$command" ]]; then
                    (crontab -l 2>/dev/null; echo "$schedule $command") | crontab -
                    log_message "SUCCESS" "NEW CRON JOB ADDED."
                else
                    log_message "ERROR" "SCHEDULE AND COMMAND CANNOT BE EMPTY."
                fi
                read -n 1 -s -r -p "PRESS ANY KEY..."
                ;;
            2)
                echo -e "${B_MAGENTA}ENTER LINE NUMBER TO DELETE:${N}"
                printf "%b" "${C_CYAN}> ${C_RESET}"; read -e -r line_num
                
                if [[ "$line_num" =~ ^[0-9]+$ ]]; then
                    (crontab -l | sed -e "${line_num}d") | crontab -
                    log_message "SUCCESS" "CRON JOB AT LINE $line_num DELETED."
                else
                    log_message "ERROR" "INVALID LINE NUMBER."
                fi
                read -n 1 -s -r -p "PRESS ANY KEY..."
                ;;
            3)
                return
                ;;
            *)
                echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

# --- 4.5 SYSTEM CLEANUP AND LOGS ---
manage_cleanup_submenu() {
    _system_cleanup() {
        clear
        log_message "INFO" "STARTING SYSTEM CLEANUP..."
        echo -e "${B_CYAN}--- SYSTEM CLEANUP ---${C_RESET}\n"
        
        echo -e "${C_YELLOW}DISK USAGE BEFORE:${C_RESET}"
        df -h / | tail -n 1
        
        echo -e "\n${C_YELLOW}REMOVING UNUSED PACKAGES AND CACHE...${C_RESET}"
        apt-get clean > /dev/null 2>&1
        apt-get autoremove -y --purge > /dev/null 2>&1
        
        log_message "SUCCESS" "CLEANUP COMPLETED."
        echo -e "${C_YELLOW}DISK USAGE AFTER:${C_RESET}"
        df -h / | tail -n 1
        read -n 1 -s -r -p "PRESS ANY KEY..."
    }

    _log_cleanup() {
        if [ ! -f "$LOG_FILE" ]; then
            log_message "INFO" "LOG FILE NOT FOUND."
            return
        fi
        local log_size
        log_size=$(du -h "$LOG_FILE" | awk '{print $1}')
        echo -e "${C_WHITE}CURRENT LOG SIZE ($LOG_FILE): ${B_GREEN}${log_size}${N}"
        printf "%b" "${C_RED}WARNING: THIS WILL CLEAR THE SCRIPT LOG. CONTINUE? (Y/N): ${C_RESET}"
        read -e -r choice
        if [[ "$choice" =~ ^[yY]$ ]]; then
            > "$LOG_FILE"
            log_message "SUCCESS" "LOG FILE TRUNCATED."
        fi
        read -n 1 -s -r -p "PRESS ANY KEY..."
    }

    _journal_vacuum() {
        printf "%b" "${B_MAGENTA}ENTER MAX SIZE (E.G. 100M) OR TIME (E.G. 2weeks): ${C_RESET}"; read -e -r limit
        if [ -n "$limit" ]; then
            journalctl --vacuum-size="$limit" 2>/dev/null || journalctl --vacuum-time="$limit"
            log_message "SUCCESS" "JOURNALD VACUUMED."
        fi
        read -n 1 -s -r -p "PRESS ANY KEY..."
    }

    while true; do
        clear
        echo -e "${B_CYAN}--- CLEANUP MENU ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "SYSTEM CLEANUP (APT/CACHE)"
        printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "2" "SCRIPT LOG CLEANUP"
        printf "  ${C_YELLOW}%2d)${B_YELLOW} %s\n" "3" "JOURNALD LOG CLEANUP"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1) _system_cleanup ;;
            2) _log_cleanup ;;
            3) _journal_vacuum ;;
            4) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
}

# ###########################################################################
# --- FIND FASTEST APT MIRROR (OPTIMIZED - NO TEMP FILES) ---
# ###########################################################################

advanced_mirror_test() {
    # 1. Define Mirrors
    local MIRRORS=(
        "http://archive.ubuntu.com/ubuntu/"
        "https://mirror.mobinhost.com/ubuntu/"
        "https://mirrors.pardisco.co/ubuntu/"
        "https://mirror.shatel.ir/ubuntu/"
        "https://archive.ito.gov.ir/ubuntu/"
        "http://mirror.arvancloud.ir/ubuntu/"
        "https://mirror-linux.runflare.com/ubuntu/"
        "https://mirror.aminidc.com/ubuntu/"
        "http://mirror.faraso.org/ubuntu/"
        "https://ir.ubuntu.sindad.cloud/ubuntu/"
        "https://ubuntu-mirror.kimiahost.com/ubuntu/"
        "https://archive.ubuntu.petiak.ir/ubuntu/"
        "https://ubuntu.hostiran.ir/ubuntuarchive/"
        "https://ubuntu.bardia.tech/"
        "https://mirror.iranserver.com/ubuntu/"
        "https://ir.archive.ubuntu.com/ubuntu/"
        "https://mirror.0-1.cloud/ubuntu/"
        "http://linuxmirrors.ir/pub/ubuntu/"
        "http://repo.iut.ac.ir/repo/Ubuntu/"
        "http://ubuntu.byteiran.com/ubuntu/"
        "https://mirror.rasanegar.com/ubuntu/"
        "http://mirrors.sharif.ir/ubuntu/"
        "http://mirror.ut.ac.ir/ubuntu/"
        "https://ubuntu.pars.host/ubuntu/"
        "https://ubuntu.parsvds.com/ubuntu/"
        "https://ubuntu.pishgaman.net/ubuntu/"
    )

    clear
    log_message "INFO" "--- ADVANCED APT REPOSITORY ANALYSIS ---"
    echo -e "${B_CYAN}--- FINDING FASTEST APT MIRROR ---${C_RESET}\n"
    
    # Arrays to store results
    local valid_results=() 
    
    local total_mirrors=${#MIRRORS[@]}
    local current=0

    # Detect OS Codename
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        CODENAME=$VERSION_CODENAME
    else
        CODENAME=$(lsb_release -sc)
    fi

    echo -e "${C_WHITE}OS CODENAME: ${B_YELLOW}$CODENAME${C_RESET}"
    echo -e "${B_BLUE}----------------------------------------------------------------${C_RESET}"
    printf "%-45s %-15s\n" "MIRROR URL" "LATENCY"
    echo -e "${B_BLUE}----------------------------------------------------------------${C_RESET}"

    # 2. Scanning Loop
    for url in "${MIRRORS[@]}"; do
        ((current++))
        echo -ne "\r${C_YELLOW}SCANNING [$current/$total_mirrors]: ${C_WHITE}Checking...${C_RESET}"
        
        # Check latency
        time_taken=$(curl -o /dev/null -s -w "%{time_total}" --connect-timeout 2 --max-time 3 "$url" 2>/dev/null)
        
        echo -ne "\r\033[K" # Clear line

        if [ -n "$time_taken" ] && [ "$time_taken" != "0.000000" ]; then
            printf "${C_WHITE}%-45s ${B_GREEN}%-15s${C_RESET}\n" "${url:0:43}" "${time_taken}s"
            # Store as "latency|url" for sorting
            valid_results+=("$time_taken|$url")
        else
            printf "${C_RED}%-45s ${C_RED}%-15s${C_RESET}\n" "${url:0:43}" "TIMEOUT"
        fi
    done

    echo -e "${B_BLUE}----------------------------------------------------------------${C_RESET}"
    
    if [ ${#valid_results[@]} -eq 0 ]; then
        log_message "ERROR" "NO REACHABLE MIRRORS FOUND."
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi

    # 3. Sort Results (Fastest First)
    # Using sort -n on the first field (latency)
    IFS=$'\n' sorted_results=($(sort -n <<<"${valid_results[*]}"))
    unset IFS

    # Extract best mirror details
    best_entry="${sorted_results[0]}"
    best_time="${best_entry%%|*}"
    best_url="${best_entry#*|}"

    echo -e "\n${B_GREEN}FASTEST MIRROR FOUND:${C_RESET} ${B_YELLOW}$best_url${C_RESET} (${best_time}s)"
    echo -e "${B_BLUE}----------------------------------------------------------------${C_RESET}"
    
    # 4. Selection Menu
    echo -e "HOW DO YOU WANT TO PROCEED?"
    echo -e "  ${B_GREEN}[A]${C_RESET} AUTO-SELECT FASTEST (Recommended)"
    echo -e "  ${B_CYAN}[M]${C_RESET} MANUAL SELECTION FROM LIST"
    echo -e "  ${C_RED}[X]${C_RESET} CANCEL"
    
    echo -ne "\n${B_MAGENTA}ENTER CHOICE (A/M/X): ${C_RESET}"
    read -e -r user_choice

    local final_mirror=""

    case "${user_choice^^}" in
        A)
            final_mirror="$best_url"
            log_message "INFO" "AUTO-SELECTED FASTEST MIRROR: $final_mirror"
            ;;
        M)
            echo -e "\n${B_CYAN}--- TOP FASTEST MIRRORS ---${C_RESET}"
            local i=0
            local limit=10 # Show top 10
            if [ ${#sorted_results[@]} -lt 10 ]; then limit=${#sorted_results[@]}; fi
            
            for ((i=0; i<limit; i++)); do
                entry="${sorted_results[$i]}"
                t="${entry%%|*}"
                u="${entry#*|}"
                printf "  ${C_YELLOW}%2d)${C_RESET} %-40s [${B_GREEN}%s${C_RESET}]\n" "$((i+1))" "$u" "${t}s"
            done
            
            echo -ne "\n${B_MAGENTA}ENTER NUMBER (1-$limit): ${C_RESET}"
            read -e -r manual_num
            
            if [[ "$manual_num" =~ ^[0-9]+$ ]] && [ "$manual_num" -ge 1 ] && [ "$manual_num" -le "$limit" ]; then
                index=$((manual_num-1))
                entry="${sorted_results[$index]}"
                final_mirror="${entry#*|}"
                log_message "INFO" "MANUALLY SELECTED MIRROR: $final_mirror"
            else
                log_message "ERROR" "INVALID SELECTION."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                return
            fi
            ;;
        X)
            log_message "INFO" "OPERATION CANCELED."
            return
            ;;
        *)
            log_message "ERROR" "INVALID OPTION."
            return
            ;;
    esac

    # 5. Apply Changes
    if [ -n "$final_mirror" ]; then
        local timestamp=$(date +"%Y%m%d_%H%M%S")
        log_message "INFO" "BACKUP: /etc/apt/sources.list.bak_$timestamp"
        cp /etc/apt/sources.list "/etc/apt/sources.list.bak_$timestamp"
        
        log_message "INFO" "APPLYING NEW MIRROR..."
        cat > /etc/apt/sources.list <<EOF
# Generated by Advanced Ubuntu Script - $timestamp
# Mirror: $final_mirror

deb $final_mirror $CODENAME main restricted universe multiverse
deb $final_mirror $CODENAME-updates main restricted universe multiverse
deb $final_mirror $CODENAME-backports main restricted universe multiverse
deb $final_mirror $CODENAME-security main restricted universe multiverse
EOF
        log_message "SUCCESS" "SOURCES.LIST UPDATED SUCCESSFULLY."
        
        echo -e "\n${C_YELLOW}UPDATING PACKAGE LISTS (apt update)...${C_RESET}"
        apt update
        log_message "SUCCESS" "MIRROR UPDATE COMPLETED."
    fi
    
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}


# --- 4.7 AUTO REBOOT MANAGEMENT ---
manage_reboot_cron() {
    clear
    echo -e "${B_CYAN}--- AUTO REBOOT MANAGEMENT ---${C_RESET}\n"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "REBOOT EVERY 3 HOURS"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "REBOOT EVERY 12 HOURS"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "REBOOT DAILY AT SPECIFIC TIME"
    printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "4" "REMOVE REBOOT SCHEDULE"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "BACK"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice
    
    case $choice in
        1)
            (crontab -l 2>/dev/null | grep -v "shutdown -r"; echo "0 */3 * * * /sbin/shutdown -r now") | crontab -
            log_message "SUCCESS" "AUTO REBOOT SET: EVERY 3 HOURS."
            ;;
        2)
            (crontab -l 2>/dev/null | grep -v "shutdown -r"; echo "0 */12 * * * /sbin/shutdown -r now") | crontab -
            log_message "SUCCESS" "AUTO REBOOT SET: EVERY 12 HOURS."
            ;;
        3)
            printf "%b" "${B_MAGENTA}ENTER HOUR (0-23): ${C_RESET}"; read -e -r hr
            (crontab -l 2>/dev/null | grep -v "shutdown -r"; echo "0 $hr * * * /sbin/shutdown -r now") | crontab -
            log_message "SUCCESS" "AUTO REBOOT SET: DAILY AT $hr:00."
            ;;
        4)
            crontab -l | grep -v "shutdown -r" | crontab -
            log_message "SUCCESS" "AUTO REBOOT REMOVED."
            ;;
        5) return ;;
        *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}" ;;
    esac
    read -n 1 -s -r -p "PRESS ANY KEY..."
}

# --- 4.8 AUTO RESTART XRAY SERVICE ---
manage_xray_auto_restart() {
    clear
    echo -e "${B_CYAN}--- XRAY AUTO RESTART ---${C_RESET}\n"
    local xray_service=""
    for s in "xray" "x-ui" "tx-ui" "3x-ui"; do
        if systemctl list-units --full -all | grep -q "$s.service"; then
            xray_service="$s"
            break
        fi
    done

    if [ -z "$xray_service" ]; then
        log_message "ERROR" "NO XRAY SERVICE FOUND."
        read -n 1 -s -r -p "PRESS ANY KEY..."
        return
    fi
    
    echo -e "${C_WHITE}DETECTED SERVICE: ${B_GREEN}${xray_service}${C_RESET}\n"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "RESTART EVERY 1 HOUR"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "RESTART EVERY 6 HOURS"
    printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "3" "REMOVE RESTART SCHEDULE"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "BACK"
    printf "%b" "${B_MAGENTA}OPTION: ${C_RESET}"; read -e -r choice

    case $choice in
        1)
            (crontab -l 2>/dev/null | grep -v "restart $xray_service"; echo "0 * * * * systemctl restart $xray_service") | crontab -
            log_message "SUCCESS" "AUTO RESTART SET: HOURLY."
            ;;
        2)
            (crontab -l 2>/dev/null | grep -v "restart $xray_service"; echo "0 */6 * * * systemctl restart $xray_service") | crontab -
            log_message "SUCCESS" "AUTO RESTART SET: EVERY 6 HOURS."
            ;;
        3)
            crontab -l | grep -v "restart $xray_service" | crontab -
            log_message "SUCCESS" "AUTO RESTART REMOVED."
            ;;
        4) return ;;
    esac
    read -n 1 -s -r -p "PRESS ANY KEY..."
}

# --- 4.9 FIX WHATSAPP TIME ---
fix_whatsapp_time() {
    clear
    log_message "INFO" "FIXING WHATSAPP TIME ISSUE..."
    timedatectl set-timezone Asia/Tehran
    log_message "SUCCESS" "TIMEZONE SET TO ASIA/TEHRAN."
    read -n 1 -s -r -p "PRESS ANY KEY..."
}

# --- MENU 4 MAIN ENTRY ---
manage_system_tools() {
    while true; do
        clear
        stty sane
        echo -e "${B_CYAN}--- SYSTEM AND MANAGEMENT TOOLS ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "1" "BACKUP MANAGEMENT"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "2" "SYSTEM USER MANAGEMENT"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "3" "SYSTEMD SERVICE MANAGEMENT"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "4" "CRON JOB MANAGEMENT"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "SYSTEM CLEANUP & LOGS"
        printf "  ${C_YELLOW}%2d)${B_YELLOW} %s\n" "6" "FIND FASTEST APT MIRROR"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "7" "AUTO REBOOT MANAGEMENT"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "8" "AUTO RESTART XRAY SERVICE"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "9" "FIX WHATSAPP DATE ISSUE"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "10" "BACK TO MAIN MENU"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1) manage_backups ;;
            2) manage_system_users ;;
            3) manage_systemd_services ;;
            4) manage_cron_jobs ;;
            5) manage_cleanup_submenu ;;
            6) advanced_mirror_test ;;
            7) manage_reboot_cron ;;
            8) manage_xray_auto_restart ;;
            9) fix_whatsapp_time ;;
            10) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
}

# ###########################################################################
# --- WEB TOOLS AND SERVICES FUNCTIONS (TRANSLATED & EXTRACTED) ---
# ###########################################################################

manage_docker() {
    _install_docker() {
        log_message "INFO" "CHECKING AND INSTALLING DOCKER..."
        if command -v docker &>/dev/null; then
            log_message "INFO" "DOCKER IS ALREADY INSTALLED."
            return 0
        fi

        log_message "INFO" "INSTALLING DOCKER PREREQUISITES..."
        if ! install_dependencies; then
            log_message "ERROR" "FAILED TO INSTALL DOCKER PREREQUISITES."
            return 1
        fi

        log_message "INFO" "ADDING DOCKER OFFICIAL GPG KEY..."
        install -m 0755 -d /etc/apt/keyrings
        if ! curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc; then
            log_message "ERROR" "FAILED TO DOWNLOAD DOCKER GPG KEY."
            return 1
        fi
        chmod a+r /etc/apt/keyrings/docker.asc

        log_message "INFO" "SETTING UP DOCKER APT REPOSITORY..."
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
          $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
          tee /etc/apt/sources.list.d/docker.list > /dev/null

        log_message "INFO" "INSTALLING DOCKER ENGINE..."
        apt-get update -qq
        if ! apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
            log_message "ERROR" "FAILED TO INSTALL DOCKER ENGINE PACKAGES."
            return 1
        fi

        systemctl enable --now docker
        check_service_status "docker"
        log_message "SUCCESS" "DOCKER INSTALLED AND STARTED SUCCESSFULLY."
        return 0
    }

    _manage_docker_containers() {
        while true; do
            clear
            echo -e "${B_CYAN}--- MANAGE DOCKER CONTAINERS ---${C_RESET}\n"
            echo -e "${C_WHITE}CURRENT CONTAINERS:${C_RESET}"
            docker ps -a
            echo -e "\n${B_BLUE}----------------------------------------------------${C_RESET}"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "START A CONTAINER"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "STOP A CONTAINER"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "RESTART A CONTAINER"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "VIEW CONTAINER LOGS"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "BACK TO DOCKER MENU"
            echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
            printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

            local container_id
            case $choice in
                1|2|3)
                    printf "%b" "${B_MAGENTA}ENTER CONTAINER NAME OR ID: ${C_RESET}"; read -e -r container_id
                    if [ -z "$container_id" ]; then
                        log_message "WARNING" "NO CONTAINER ID PROVIDED. ABORTING."
                        sleep 2; continue
                    fi
                    if [ "$choice" -eq 1 ]; then
                        log_message "INFO" "STARTING CONTAINER: $container_id"
                        docker start "$container_id"
                    elif [ "$choice" -eq 2 ]; then
                        log_message "INFO" "STOPPING CONTAINER: $container_id"
                        docker stop "$container_id"
                    elif [ "$choice" -eq 3 ]; then
                        log_message "INFO" "RESTARTING CONTAINER: $container_id"
                        docker restart "$container_id"
                    fi
                    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                    ;;
                4)
                    printf "%b" "${B_MAGENTA}ENTER CONTAINER NAME OR ID: ${C_RESET}"; read -e -r container_id
                    if [ -z "$container_id" ]; then
                        log_message "WARNING" "NO CONTAINER ID PROVIDED. ABORTING."
                        sleep 2; continue
                    fi
                    log_message "INFO" "VIEWING LOGS FOR CONTAINER: $container_id (PRESS CTRL+C TO EXIT LOGS)"
                    ( trap '' INT; docker logs -f "$container_id" )
                    log_message "INFO" "LOG VIEWING EXITED."
                    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                    ;;
                5)
                    return 0
                    ;;
                *)
                    echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1
                    ;;
            esac
        done
    }

    while true; do
        clear
        echo -e "${B_CYAN}--- DOCKER INSTALLATION AND MANAGEMENT ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "INSTALL DOCKER AND DOCKER-COMPOSE"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "2" "MANAGE CONTAINERS (START, STOP, LOGS)"
        printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "3" "PRUNE DOCKER SYSTEM (DELETE UNUSED DATA)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                _install_docker
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                if ! command -v docker &>/dev/null; then
                    log_message "ERROR" "DOCKER IS NOT INSTALLED. PLEASE INSTALL IT FIRST."
                else
                    _manage_docker_containers
                fi
                ;;
            3)
                if ! command -v docker &>/dev/null; then
                    log_message "ERROR" "DOCKER IS NOT INSTALLED."
                else
                    printf "%b" "${C_RED}**WARNING:** THIS WILL REMOVE ALL STOPPED CONTAINERS, NETWORKS, AND UNUSED IMAGES. SURE? (Y/N): ${C_RESET}"
                    read -e -r confirm
                    if [[ "$confirm" =~ ^[yY]$ ]]; then
                        log_message "WARNING" "PRUNING DOCKER SYSTEM..."
                        docker system prune -a -f
                        log_message "SUCCESS" "DOCKER SYSTEM PRUNED."
                    else
                        log_message "INFO" "DOCKER PRUNE CANCELED."
                    fi
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            4)
                return
                ;;
            *)
                echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

manage_certbot() {
    while true; do
        clear
        echo -e "${B_CYAN}--- SSL CERTIFICATE MANAGEMENT (CERTBOT) ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "INSTALL CERTBOT"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "GET NEW CERTIFICATE"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "3" "LIST EXISTING CERTIFICATES"
        printf "  ${C_YELLOW}%2d)${B_YELLOW} %s\n" "4" "FORCE RENEW CERTIFICATE"
        printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "5" "DELETE A CERTIFICATE"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "6" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                log_message "INFO" "INSTALLING CERTBOT..."
                install_dependencies
                if ! command -v certbot &>/dev/null; then
                    log_message "WARNING" "CERTBOT NOT FOUND AFTER APT. TRYING SNAP..."
                    if command -v snap &>/dev/null; then
                        snap install core 2>/dev/null || true
                        snap refresh 2>/dev/null || true
                        snap install --classic certbot 2>/dev/null || true
                        if [ -x /snap/bin/certbot ] && ! command -v certbot &>/dev/null; then
                            ln -sf /snap/bin/certbot /usr/local/bin/certbot 2>/dev/null || true
                        fi
                    else
                        log_message "WARNING" "SNAP NOT AVAILABLE. PLEASE INSTALL CERTBOT MANUALLY."
                    fi
                fi
                if command -v certbot &>/dev/null; then
                    log_message "SUCCESS" "CERTBOT INSTALLED/AVAILABLE."
                else
                    log_message "ERROR" "CERTBOT STILL NOT FOUND."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                echo -e "\n${B_CYAN}SELECT METHOD:${C_RESET}"
                echo "  1) STANDALONE (STOPS WEB SERVER TEMPORARILY)"
                echo "  2) WEBROOT (REQUIRES ACTIVE WEB SERVER PATH)"
                printf "%b" "${B_MAGENTA}YOUR CHOICE: ${C_RESET}"; read -e -r method_choice

                printf "%b" "${B_MAGENTA}ENTER DOMAIN NAME (E.G. my.domain.com): ${C_RESET}"; read -e -r domain_name
                if [ -z "$domain_name" ]; then
                    log_message "ERROR" "DOMAIN NAME CANNOT BE EMPTY."
                elif [ "$method_choice" -eq 1 ]; then
                    log_message "INFO" "GETTING NEW CERTIFICATE FOR $domain_name USING STANDALONE METHOD..."
                    certbot certonly --standalone -d "$domain_name"
                elif [ "$method_choice" -eq 2 ]; then
                    printf "%b" "${B_MAGENTA}ENTER WEBROOT PATH (E.G. /var/www/html): ${C_RESET}"; read -e -r webroot_path
                    log_message "INFO" "GETTING NEW CERTIFICATE FOR $domain_name USING WEBROOT METHOD..."
                    certbot certonly --webroot -w "$webroot_path" -d "$domain_name"
                else
                    log_message "ERROR" "INVALID SELECTION."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                clear
                log_message "INFO" "LISTING CERTIFICATES..."
                echo
                if command -v certbot &>/dev/null; then
                    echo -e "${B_CYAN}--- CERTBOT CERTIFICATES (OFFICIAL TOOL) ---${C_RESET}"
                    certbot certificates 2>/dev/null || echo -e "${Y}NO CERTIFICATES FOUND BY CERTBOT.${N}"
                    echo
                else
                    echo -e "${B_YELLOW}CERTBOT IS NOT INSTALLED.${C_RESET}"
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            4)
                printf "%b" "${B_MAGENTA}ENTER DOMAIN NAME TO RENEW: ${C_RESET}"; read -e -r domain_to_renew
                if [ -n "$domain_to_renew" ]; then
                    log_message "WARNING" "FORCE-RENEWING CERTIFICATE FOR $domain_to_renew..."
                    certbot renew --force-renewal -d "$domain_to_renew"
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            5)
                printf "%b" "${B_MAGENTA}ENTER DOMAIN NAME TO DELETE: ${C_RESET}"; read -e -r domain_to_delete
                if [ -n "$domain_to_delete" ]; then
                    log_message "WARNING" "DELETING CERTIFICATE FOR $domain_to_delete..."
                    certbot delete --cert-name "$domain_to_delete"
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            6)
                return
                ;;
            *)
                echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

manage_nginx() {
    local NGINX_ROOT_DIR="/var/www/bookstore"
    local NGINX_SITE_CONF="/etc/nginx/sites-available/bookstore"

    _nginx_install_template() {
        log_message "INFO" "INSTALLING NGINX AND DEPENDENCIES..."
        if ! apt-get install -y -qq nginx-full unzip; then
            log_message "ERROR" "FAILED TO INSTALL NGINX."
            return 1
        fi
        log_message "INFO" "CREATING WEBSITE DIRECTORY: $NGINX_ROOT_DIR"
        mkdir -p "$NGINX_ROOT_DIR"
        log_message "INFO" "GENERATING BOOKSTORE HTML TEMPLATE..."
        
        # HTML Content (Content remains bilingual for display, but script logs are English)
        tee "${NGINX_ROOT_DIR}/index.html" > /dev/null <<'EOF'
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Engineering Bookstore</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Roboto', sans-serif; margin: 0; background: #f8f9fa; color: #212529; }
        .container { width: 90%; max-width: 1200px; margin: 0 auto; padding: 0 15px; }
        header { background: #fff; padding: 1rem 0; box-shadow: 0 4px 12px rgba(0,0,0,0.08); text-align: center; }
        h1 { color: #0d6efd; }
        .book-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 2rem; padding: 3rem 0; }
        .book-card { background: #fff; text-align: center; padding: 1rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
        .price { color: #0d6efd; font-weight: bold; font-size: 1.2em; }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>ENGINEERING BOOKSTORE</h1>
        </div>
    </header>
    <main class="container">
        <div class="book-grid">
            <div class="book-card"><h3>STRUCTURAL ANALYSIS</h3><p>R. C. HIBBELER</p><p class="price">$75.00</p></div>
            <div class="book-card"><h3>SOIL MECHANICS</h3><p>BRAJA M. DAS</p><p class="price">$62.00</p></div>
            <div class="book-card"><h3>THERMODYNAMICS</h3><p>CENGEL, BOLES</p><p class="price">$81.00</p></div>
            <div class="book-card"><h3>ALGORITHM DESIGN</h3><p>KLEINBERG</p><p class="price">$95.00</p></div>
        </div>
    </main>
</body>
</html>
EOF
        
        log_message "INFO" "CREATING NGINX SITE CONFIGURATION..."
        tee "$NGINX_SITE_CONF" > /dev/null <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    root ${NGINX_ROOT_DIR};
    index index.html index.htm;
    server_name _;
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
        ln -sf "$NGINX_SITE_CONF" /etc/nginx/sites-enabled/
        rm -f /etc/nginx/sites-enabled/default
        log_message "INFO" "TESTING NGINX CONFIGURATION AND RESTARTING..."
        if nginx -t; then
            systemctl restart nginx
            check_service_status "nginx"
            log_message "SUCCESS" "NGINX INSTALLED AND BOOKSTORE TEMPLATE IS LIVE."
        else
            log_message "ERROR" "NGINX CONFIG TEST FAILED."
        fi
    }

    _nginx_uninstall() {
        printf "%b" "${C_RED}**WARNING:** THIS WILL COMPLETELY REMOVE NGINX AND ALL CONFIGS. SURE? (Y/N): ${C_RESET}"; read -e -r confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            log_message "INFO" "UNINSTALLATION CANCELED."; return
        fi
        log_message "WARNING" "UNINSTALLING NGINX AND ALL RELATED FILES..."
        systemctl stop nginx
        apt-get purge -y -qq nginx nginx-common nginx-full
        rm -rf /etc/nginx /var/log/nginx "$NGINX_ROOT_DIR"
        log_message "SUCCESS" "NGINX UNINSTALLED COMPLETELY."
    }

    _nginx_manage_settings() {
        printf "%b" "${B_MAGENTA}ENTER CONFIG PATH (DEFAULT: /etc/nginx/sites-available/default): ${C_RESET}"; read -e -r conf_path
        conf_path=${conf_path:-/etc/nginx/sites-available/default}
        if [ -f "$conf_path" ]; then
            nano "$conf_path"
            echo -e "\n${Y}TESTING NGINX CONFIG...${N}"
            if nginx -t; then
                systemctl restart nginx
                log_message "SUCCESS" "NGINX RESTARTED."
            else
                log_message "ERROR" "NGINX CONFIG TEST FAILED. CHANGES WERE NOT APPLIED."
            fi
        else
            log_message "ERROR" "CONFIG FILE NOT FOUND: $conf_path"
        fi
    }

    _nginx_view_logs() {
        (
            trap '' INT
            printf "%b" "${B_MAGENTA}SELECT LOG TYPE (access/error): ${C_RESET}"; read -e -r log_type
            if [[ "$log_type" == "access" || "$log_type" == "error" ]]; then
                clear
                echo -e "${Y}VIEWING ${log_type}.log... (PRESS CTRL+C TO EXIT)${N}"
                tail -f "/var/log/nginx/${log_type}.log"
            else
                log_message "ERROR" "INVALID LOG TYPE."
            fi
        )
    }

    _nginx_reset_mariadb() {
        clear
        log_message "WARNING" "--- FULL MARIADB RESET ---"
        echo -e "${R}**CRITICAL WARNING:** THIS WILL REMOVE ALL MARIADB/MYSQL PACKAGES."
        echo -e "${R}ALL DATABASES, USERS, AND CONFIGS WILL BE LOST FOREVER.${N}"
        printf "%b" "${B_MAGENTA}ARE YOU SURE? (Y/N): ${C_RESET}"; read -e -r confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            log_message "INFO" "MARIADB RESET CANCELED."; return
        fi

        log_message "WARNING" "STOPPING AND PURGING MARIADB..."
        systemctl stop mariadb 2>/dev/null
        systemctl disable mariadb 2>/dev/null
        apt-get purge -y 'mariadb-*' 'mysql-*'
        rm -rf /etc/mysql /var/lib/mysql /var/log/mysql
        apt-get autoremove -y
        apt-get clean
        log_message "SUCCESS" "MARIADB HAS BEEN COMPLETELY WIPED."
    }

    _nginx_install_lemp() {
        log_message "INFO" "INSTALLING LEMP STACK (NGINX, MARIADB, PHP)..."
        
        if ! apt-get install -y -qq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" nginx-full mariadb-server php-fpm php-mysql; then
            log_message "ERROR" "FAILED TO INSTALL LEMP STACK PACKAGES."
            return 1
        fi
        
        log_message "INFO" "SECURING MARIADB INSTALLATION..."
        if sudo mysql -e "DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; FLUSH PRIVILEGES;"; then
            log_message "SUCCESS" "INITIAL DATABASE HARDENING COMPLETED."
        else
            log_message "ERROR" "FAILED TO RUN INITIAL HARDENING STEPS."
            return 1
        fi

        log_message "INFO" "SETTING ROOT PASSWORD..."
        printf "%b" "${B_MAGENTA}ENTER NEW ROOT PASSWORD FOR DATABASE: ${C_RESET}"; read -s -r db_root_password
        echo

        if sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${db_root_password}'; FLUSH PRIVILEGES;"; then
            log_message "SUCCESS" "DATABASE ROOT PASSWORD SET SUCCESSFULLY."
        else
            log_message "ERROR" "FAILED TO SET ROOT PASSWORD."
            return 1
        fi

        log_message "INFO" "CONFIGURING NGINX FOR PHP..."
        local php_version
        php_version=$(php -v | head -n 1 | cut -d " " -f 2 | cut -d "." -f 1,2)
        local php_sock_path="/run/php/php${php_version}-fpm.sock"
        local default_conf="/etc/nginx/sites-available/default"
        
        create_backup "$default_conf"
        tee "$default_conf" > /dev/null <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/html;
    index index.php index.html index.htm;
    server_name _;
    location / {
        try_files \$uri \$uri/ =404;
    }
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${php_sock_path};
    }
}
EOF
        echo "<?php phpinfo(); ?>" > /var/www/html/info.php
        systemctl restart "php${php_version}-fpm"
        systemctl restart nginx
        
        local ip_addr
        ip_addr=$(hostname -I | awk '{print $1}')
        echo -e "\n${G}LEMP STACK INSTALLED SUCCESSFULLY.${N}"
        echo -e "${Y}TEST PHP AT: http://${ip_addr}/info.php${N}"
        echo -e "${R}IMPORTANT: DELETE info.php AFTER TESTING.${N}"
    }

    while true; do
        clear
        echo -e "${B_CYAN}--- NGINX WEB SERVER MANAGEMENT ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "1" "INSTALL LEMP STACK (NGINX, MARIADB, PHP)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "INSTALL NGINX + BOOKSTORE TEMPLATE"
        printf "  ${C_YELLOW}%2d)${C_RED} %s\n" "3" "UNINSTALL NGINX COMPLETELY"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "EDIT CONFIGURATION FILES"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "VIEW NGINX LOGS"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "6" "CHECK NGINX SERVICE STATUS"
        printf "  ${C_YELLOW}%2d)${R} %s\n" "7" "FULL MARIADB RESET"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "8" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1) _nginx_install_lemp ;;
            2) _nginx_install_template ;;
            3) _nginx_uninstall ;;
            4) _nginx_manage_settings ;;
            5) _nginx_view_logs ;;
            6) 
                clear; systemctl status nginx --no-pager
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            7) _nginx_reset_mariadb ;;
            8) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
    done
}

manage_web_services() {
    while true; do
        clear
        stty sane
        echo -e "${B_CYAN}--- WEB TOOLS AND SERVICES ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "1" "NGINX WEB SERVER MANAGEMENT"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "SSL CERTIFICATE MANAGEMENT (CERTBOT)"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "3" "DOCKER INSTALLATION AND MANAGEMENT"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "BACK TO MAIN MENU"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1) manage_nginx ;;
            2) manage_certbot ;;
            3) manage_docker ;;
            4) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
}

# ###########################################################################
# --- MONITORING AND DIAGNOSTICS FUNCTIONS (TRANSLATED & EXTRACTED) ---
# ###########################################################################

manage_system_monitors() {
    while true; do
        clear
        echo -e "${B_CYAN}--- ADVANCED SYSTEM RESOURCE MONITORING ---${C_RESET}\n"
        echo -e "${C_WHITE}THESE TOOLS ALLOW YOU TO VIEW REAL-TIME CPU, MEMORY, AND RUNNING PROCESSES.${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "1" "RUN BTOP (ADVANCED & GRAPHICAL)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "RUN HTOP (CLASSIC & LIGHTWEIGHT)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                clear
                if ! command -v btop &>/dev/null; then
                    log_message "WARNING" "BTOP NOT FOUND. ATTEMPTING TO INSTALL..."
                    install_dependencies
                    if ! command -v btop &>/dev/null; then
                        log_message "ERROR" "BTOP INSTALLATION FAILED. PLEASE CHECK APT LOGS. IT MAY NOT BE SUPPORTED ON YOUR OS."
                        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                        continue
                    fi
                fi
                log_message "INFO" "LAUNCHING BTOP SYSTEM MONITOR..."
                echo -e "${C_WHITE}RUNNING BTOP MONITOR...${C_RESET}"
                echo -e "${B_YELLOW}NOTE: BTOP REQUIRES A MODERN TERMINAL. IF DISPLAY ISSUES OCCUR, USE HTOP.${C_RESET}"
                echo -e "${C_CYAN}PRESS 'q' TO EXIT AND RETURN TO MENU.${C_RESET}\n"
                sleep 2
                btop
                log_message "INFO" "BTOP SESSION FINISHED."
                ;;
            2)
                clear
                if ! command -v htop &>/dev/null; then
                    log_message "WARNING" "HTOP NOT FOUND. ATTEMPTING TO INSTALL..."
                    install_dependencies
                     if ! command -v htop &>/dev/null; then
                        log_message "ERROR" "HTOP INSTALLATION FAILED. PLEASE CHECK APT LOGS."
                        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                        continue
                    fi
                fi
                log_message "INFO" "LAUNCHING HTOP SYSTEM MONITOR..."
                echo -e "${C_WHITE}RUNNING HTOP MONITOR...${C_RESET}"
                echo -e "${C_CYAN}PRESS 'q' TO EXIT AND RETURN TO MENU.${C_RESET}\n"
                sleep 2
                htop
                log_message "INFO" "HTOP SESSION FINISHED."
                ;;
            3)
                return
                ;;
            *)
                echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

manage_network_traffic() {
    clear
    if ! command -v iftop &>/dev/null; then
        log_message "WARNING" "IFTOP NOT FOUND. ATTEMPTING TO INSTALL..."
        install_dependencies
        if ! command -v iftop &>/dev/null; then
            log_message "ERROR" "IFTOP INSTALLATION FAILED. PLEASE CHECK APT LOGS."
            read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
            return
        fi
    fi
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        log_message "ERROR" "PRIMARY NETWORK INTERFACE NOT FOUND."
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi
    log_message "INFO" "LAUNCHING IFTOP ON INTERFACE $PRIMARY_INTERFACE..."
    echo -e "${B_CYAN}--- LIVE NETWORK TRAFFIC VIEW (IFTOP) ---${C_RESET}\n"
    echo -e "${C_WHITE}DISPLAYING TRAFFIC ON INTERFACE: ${B_YELLOW}${PRIMARY_INTERFACE}${C_RESET}"
    echo -e "${C_CYAN}PRESS 'q' TO EXIT AND RETURN TO MENU.${C_RESET}\n"
    sleep 2
    iftop -i "$PRIMARY_INTERFACE"
    log_message "SUCCESS" "IFTOP SESSION FINISHED."
}

manage_monitoring_diagnostics() {
    while true; do
        clear
        stty sane
        echo -e "${B_CYAN}--- MONITORING AND DIAGNOSTICS TOOLS ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "ADVANCED RESOURCE MONITORING (BTOP/HTOP)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "LIVE NETWORK TRAFFIC VIEW (IFTOP)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "BACK TO MAIN MENU"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"; read -e -r choice

        case $choice in
            1) manage_system_monitors ;;
            2) manage_network_traffic ;;
            3) return ;;
            *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; sleep 1 ;;
        esac
    done
}

# ###########################################################################
# --- UPDATE AND SOFTWARE MANAGEMENT FUNCTIONS ---
# ###########################################################################

update_server_software() {
    clear
    log_message "INFO" "STARTING SERVER SOFTWARE UPDATE AND UPGRADE..."
    echo -e "${B_CYAN}--- UPDATE AND UPGRADE SERVER SOFTWARE ---${C_RESET}\n"
    
    echo -e "${C_YELLOW}STEP 1: UPDATING REPOSITORIES AND UPGRADING PACKAGES...${C_RESET}"
    log_message "INFO" "EXECUTING: apt update && apt upgrade -y"
    # Running update and upgrade
    apt update && apt upgrade -y
    
    echo -e "\n${C_YELLOW}STEP 2: INSTALLING ESSENTIAL PACKAGES (CURL, SOCAT)...${C_RESET}"
    log_message "INFO" "EXECUTING: apt install curl socat -y"
    # Running package installation
    apt install curl socat -y
    
    echo -e "\n${B_GREEN}----------------------------------------------------${C_RESET}"
    log_message "SUCCESS" "SYSTEM UPDATE AND SOFTWARE INSTALLATION COMPLETED."
    echo -e "${B_GREEN}----------------------------------------------------${C_RESET}"
    
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

# --- MAIN LOOP ---
main() {
    apply_theme
    init_environment
    clear
    
    # --- ADDED LOADING BAR HERE ---
    progress_bar "LOADING SCRIPT..." 2
    # ------------------------------

    while true; do
      stty sane 
      clear; show_banner; show_enhanced_system_status
      echo -e "${C_WHITE}NOTE: ALL MENUS ARE ACTIVE.${C_RESET}\n"
      
      printf "   ${C_YELLOW}%2d) ${B_GREEN}%s\n" "1" "PANEL INSTALLATION AND MANAGEMENT"
      printf "   ${C_YELLOW}%2d) ${B_CYAN}%s\n" "2" "NETWORK AND CONNECTION OPTIMIZATION"
      printf "   ${C_YELLOW}%2d) ${B_CYAN}%s\n" "3" "SECURITY AND ACCESS MANAGEMENT"
      printf "   ${C_YELLOW}%2d) ${B_CYAN}%s\n" "4" "SYSTEM AND MANAGEMENT TOOLS"
      printf "   ${C_YELLOW}%2d) ${B_CYAN}%s\n" "5" "WEB TOOLS AND SERVICES"
      printf "   ${C_YELLOW}%2d) ${B_CYAN}%s\n" "6" "MONITORING AND DIAGNOSTICS"
      printf "   ${C_YELLOW}%2d) ${C_WHITE}%s\n" "7" "UPDATE AND UPGRADE SERVER SOFTWARE"
      printf "\n   ${C_YELLOW}%2d) ${C_RED}%s\n" "10" "EXIT"
      echo -e "${B_BLUE}------------------------------------------------------------${C_RESET}"
      printf "%b" "${B_MAGENTA}PLEASE SELECT AN OPTION: ${C_RESET}"
      read -e -r main_choice

      case $main_choice in
        1) manage_vpn_panels ;;
        2) manage_network_optimization ;;
        3) manage_security_access ;;
        4) manage_system_tools ;;
        5) manage_web_services ;;
        6) manage_monitoring_diagnostics ;;
        7) update_server_software ;;
        10) clear; log_message "INFO" "EXITING SCRIPT."; echo -e "\n${B_CYAN}GOODBYE!${C_RESET}\n"; stty sane; exit 0 ;;
        *) echo -e "\n${C_RED}INVALID OPTION!${C_RESET}"; read -n 1 -s -r -p "" ;;
      esac
    done
}

main "$@"