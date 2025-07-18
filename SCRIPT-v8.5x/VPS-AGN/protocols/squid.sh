#!/bin/bash
# Revised Squid Proxy Installer - 07/17/2025
# Installs and configures Squid proxy with port and host management

# ANSI color codes
declare -A colors=( [white]="\033[1;37m" [blue]="\033[1;34m" [green]="\033[1;32m" [cyan]="\033[1;36m" [red]="\033[1;31m" [reset]="\033[0m" )

# Base directory (adjust as needed)
SCPdir="/etc/CYRUS-V"
SCPfrm="${SCPdir}/tools"
SCPinst="${SCPdir}/protocols"

# Check base directories
for dir in "$SCPfrm" "$SCPinst"; do
    if [[ ! -d "$dir" ]]; then
        echo -e "${colors[red]}Error: Directory $dir does not exist${colors[reset]}"
        exit 1
    fi
done

# Detect package manager
if command -v apt >/dev/null 2>&1; then
    PKG_MANAGER="apt"
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
else
    echo -e "${colors[red]}Error: No supported package manager found (apt/yum/dnf)${colors[reset]}"
    exit 1
fi

# Detect Squid service and config path
if [[ -d /etc/squid ]]; then
    SQUID_CONF="/etc/squid/squid.conf"
    SQUID_SERVICE="squid"
elif [[ -d /etc/squid3 ]]; then
    SQUID_CONF="/etc/squid3/squid.conf"
    SQUID_SERVICE="squid3"
else
    SQUID_CONF="/etc/squid/squid.conf" # Default for new installations
    SQUID_SERVICE="squid"
fi

# List open TCP ports
mportas() {
    if ! command -v ss >/dev/null 2>&1; then
        echo -e "${colors[red]}Error: 'ss' command not found. Please install net-tools or iproute2${colors[reset]}"
        exit 1
    fi
    local ports=()
    while IFS= read -r line; do
        port=$(echo "$line" | grep -oP '\d+\s+LISTEN' | awk '{print $1}')
        service=$(echo "$line" | grep -oP '^\S+')
        [[ -n "$port" && -n "$service" && ! "${ports[*]}" =~ "$service $port" ]] && ports+=("$service $port")
    done < <(ss -tuln | grep LISTEN)
    printf "%s\n" "${ports[@]}"
}

# Get public IP
fun_ip() {
    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${colors[red]}Error: 'curl' command not found. Installing...${colors[reset]}"
        $PKG_MANAGER install curl -y >/dev/null 2>&1 || {
            echo -e "${colors[red]}Error: Failed to install curl${colors[reset]}"
            exit 1
        }
    fi
    local local_ip=$(ip -4 addr show | grep -v '127\.[0-9]' | grep -oP 'inet \K[\d.]+' | head -1)
    local public_ip=$(curl -s --connect-timeout 5 ipv4.icanhazip.com)
    IP=${public_ip:-$local_ip}
    if [[ -z "$IP" ]]; then
        echo -e "${colors[red]}Error: Unable to determine IP address${colors[reset]}"
        exit 1
    fi
    echo "$IP"
}

# Optimize network interface for SSH
fun_eth() {
    local eth=$(ip link | grep -v lo | grep 'state UP' | awk -F: '{print $2}' | tr -d ' ' | head -1)
    if [[ -z "$eth" ]]; then
        echo -e "${colors[red]}Error: No active network interface found${colors[reset]}"
        return 1
    fi
    echo -e "${colors[cyan]}Apply network optimization for SSH? (Advanced users)${colors[reset]}"
    read -p "[y/N]: " -e -i n sshsn
    if [[ "$sshsn" =~ ^[Yy]$ ]]; then
        echo -e "${colors[blue]}Optimizing network interface for SSH...${colors[reset]}"
        read -p "Enter RX rate [1-999999999, default 999999999]: " rx
        rx=${rx:-999999999}
        read -p "Enter TX rate [1-999999999, default 999999999]: " tx
        tx=${tx:-999999999}
        if ! command -v ethtool >/dev/null 2>&1; then
            echo -e "${colors[blue]}Installing ethtool...${colors[reset]}"
            $PKG_MANAGER install ethtool -y >/dev/null 2>&1 || {
                echo -e "${colors[red]}Error: Failed to install ethtool${colors[reset]}"
                return 1
            }
        fi
        if ! ethtool -G "$eth" rx "$rx" tx "$tx" >/dev/null 2>&1; then
            echo -e "${colors[red]}Error: Failed to apply ethtool settings${colors[reset]}"
            return 1
        fi
        echo -e "${colors[green]}Network optimization applied${colors[reset]}"
    fi
}

# Progress bar for commands
fun_bar() {
    local comando="$1"
    local pid
    $comando >/dev/null 2>&1 &
    pid=$!
    echo -ne "${colors[yellow]}["
    while kill -0 "$pid" 2>/dev/null; do
        for ((i=0; i<20; i++)); do
            echo -ne "${colors[red]}#"
            sleep 0.1
        done
        echo -ne "${colors[yellow]}]"
        sleep 0.5
        echo -ne "\r${colors[yellow]}["
    done
    echo -e "${colors[yellow]}]${colors[green]} - 100%${colors[reset]}"
}

# Install and configure Squid
fun_squid() {
    if [[ -e "$SQUID_CONF" ]]; then
        echo -e "${colors[green]}Squid already installed. Removing...${colors[reset]}"
        systemctl stop "$SQUID_SERVICE" >/dev/null 2>&1
        fun_bar "$PKG_MANAGER remove squid squid3 -y"
        rm -f "$SQUID_CONF" /etc/payloads /etc/opendns
        echo -e "${colors[green]}Squid removed successfully${colors[reset]}"
        return 0
    fi

    echo -e "${colors[white]}Squid Proxy Installer by CYRUS${colors[reset]}"
    local ip
    ip=$(fun_ip)
    echo -e "${colors[cyan]}Detected IP: $ip${colors[reset]}"
    read -p "Confirm IP [$ip]: " -e input_ip
    ip=${input_ip:-$ip}
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "${colors[red]}Error: Invalid IP address${colors[reset]}"
        exit 1
    fi

    echo -e "${colors[cyan]}Enter ports for Squid (e.g., 80 8080 3128)${colors[reset]}"
    read -p "Ports: " ports_input
    read -r -a total_ports <<< "$ports_input"
    local valid_ports=()
    for port in "${total_ports[@]}"; do
        if [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]; then
            if mportas | grep -q "$port"; then
                echo -e "${colors[yellow]}Port $port: ${colors[red]}Already in use${colors[reset]}"
            else
                echo -e "${colors[yellow]}Port $port: ${colors[green]}OK${colors[reset]}"
                valid_ports+=("$port")
            fi
        else
            echo -e "${colors[yellow]}Port $port: ${colors[red]}Invalid${colors[reset]}"
        fi
    done
    if [[ ${#valid_ports[@]} -eq 0 ]]; then
        echo -e "${colors[red]}Error: No valid ports provided${colors[reset]}"
        exit 1
    fi

    echo -e "${colors[blue]}Installing Squid...${colors[reset]}"
    fun_bar "$PKG_MANAGER install squid -y"
    if ! command -v squid >/dev/null 2>&1; then
        echo -e "${colors[red]}Error: Squid installation failed${colors[reset]}"
        exit 1
    fi

    echo -e "${colors[blue]}Configuring Squid...${colors[reset]}"
    cat > /etc/payloads << 'EOF'
.bookclaro.com.br/
.claro.com.ar/
.claro.com.br/
.claro.com.co/
.claro.com.ec/
.claro.com.gt/
.cloudfront.net/
.claro.com.ni/
.claro.com.pe/
.claro.com.sv/
.claro.cr/
.clarocurtas.com.br/
.claroideas.com/
.claroideias.com.br/
.claromusica.com/
.clarosomdechamada.com.br/
.clarovideo.com/
.facebook.net/
.facebook.com/
.netclaro.com.br/
.oi.com.br/
.oimusica.com.br/
.speedtest.net/
.tim.com.br/
.timanamaria.com.br/
.vivo.com.br/
.rdio.com/
.compute-1.amazonaws.com/
.portalrecarga.vivo.com.br/
.vivo.ddivulga.com/
EOF

    echo -e "${colors[cyan]}Choose Squid configuration:${colors[reset]}"
    echo -e "[1] Basic"
    echo -e "[2] Advanced"
    read -p "[1/2]: " -e -i 1 proxy_opt
    if [[ ! "$proxy_opt" =~ ^[1-2]$ ]]; then
        proxy_opt=1
        echo -e "${colors[yellow]}Defaulting to Basic configuration${colors[reset]}"
    fi

    if [[ "$proxy_opt" -eq 2 ]]; then
        echo -e "${colors[blue]}Installing Advanced Squid configuration${colors[reset]}"
        cat > "$SQUID_CONF" << EOF
# Advanced Squid Configuration
acl url1 dstdomain -i $ip
acl url2 dstdomain -i 127.0.0.1
acl url3 url_regex -i '/etc/payloads'
acl url5 dstdomain -i localhost
acl accept method GET POST CONNECT OPTIONS PUT HEAD TRACE PATCH PROPFIND DELETE
acl all src 0.0.0.0/0
http_access allow url1
http_access allow url2
http_access allow url3
http_access allow url5
http_access allow accept
http_access deny all

# Request Headers
request_header_access Allow allow all
request_header_access Authorization allow all
request_header_access WWW-Authenticate allow all
request_header_access Proxy-Authorization allow all
request_header_access Proxy-Authenticate allow all
request_header_access Cache-Control allow all
request_header_access Content-Encoding allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Expires allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Last-Modified allow all
request_header_access Location allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Content-Language allow all
request_header_access Mime-Version allow all
request_header_access Retry-After allow all
request_header_access Title allow all
request_header_access Connection allow all
request_header_access Proxy-Connection allow all
request_header_access User-Agent allow all
request_header_access Cookie allow all

# Response Headers
reply_header_access Via deny all
reply_header_access X-Cache deny all
reply_header_access X-Cache-Lookup deny all

# Ports
$(for port in "${valid_ports[@]}"; do echo "http_port $port"; done)

# Hostname
visible_hostname CYRUS-V

via off
forwarded_for off
pipeline_prefetch off
EOF
    else
        echo -e "${colors[blue]}Installing Basic Squid configuration${colors[reset]}"
        cat > "$SQUID_CONF" << EOF
# Basic Squid Configuration
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80 21 443 70 210 1025-65535 280 488 591 777
acl CONNECT method CONNECT
acl SSH dst $ip/32
http_access allow SSH
http_access allow localhost
http_access deny all
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320

# Ports
$(for port in "${valid_ports[@]}"; do echo "http_port $port"; done)

# Hostname
visible_hostname CYRUS-V

via off
forwarded_for off
pipeline_prefetch off
EOF
    fi

    touch /etc/opendns
    fun_eth

    echo -e "${colors[blue]}Restarting services...${colors[reset]}"
    if ! systemctl restart "$SQUID_SERVICE" >/dev/null 2>&1 || ! systemctl restart ssh >/dev/null 2>&1; then
        echo -e "${colors[red]}Error: Failed to restart services${colors[reset]}"
        exit 1
    fi
    echo -e "${colors[green]}Services restarted successfully${colors[reset]}"

    if command -v ufw >/dev/null 2>&1; then
        for port in "${valid_ports[@]}"; do
            ufw allow "$port"/tcp >/dev/null 2>&1
        done
        echo -e "${colors[green]}Firewall rules updated (ufw)${colors[reset]}"
    elif command -v iptables >/dev/null 2>&1; then
        for port in "${valid_ports[@]}"; do
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        done
        echo -e "${colors[green]}Firewall rules updated (iptables)${colors[reset]}"
    else
        echo -e "${colors[yellow]}Warning: No firewall (ufw/iptables) found, ports not opened${colors[reset]}"
    fi

    echo -e "${colors[green]}Squid configured successfully${colors[reset]}"
}

# Manage existing Squid installation
online_squid() {
    local payload="/etc/payloads"
    echo -e "${colors[white]}Squid Proxy Manager${colors[reset]}"
    echo -e "[1] Add Host to Squid"
    echo -e "[2] Remove Host from Squid"
    echo -e "[3] Uninstall Squid"
    echo -e "[0] Exit"
    read -p "[0-3]: " option
    case $option in
        0) return 0 ;;
        1)
            echo -e "${colors[cyan]}Current Hosts:${colors[reset]}"
            [[ -f "$payload" ]] && awk -F "/" '{print $1,$2,$3,$4}' "$payload"
            local host
            while true; do
                read -p "Enter new host (e.g., .example.com): " host
                [[ "$host" =~ ^\..+ ]] && break
                echo -e "${colors[red]}Host must start with a dot${colors[reset]}"
            done
            if grep -Fx "$host/" "$payload" >/dev/null; then
                echo -e "${colors[red]}Host already exists${colors[reset]}"
                return 1
            fi
            echo "$host/" >> "$payload"
            echo -e "${colors[green]}Host added successfully${colors[reset]}"
            awk -F "/" '{print $1,$2,$3,$4}' "$payload"
            systemctl reload "$SQUID_SERVICE" >/dev/null 2>&1 || {
                echo -e "${colors[red]}Error: Failed to reload Squid${colors[reset]}"
                return 1
            }
            ;;
        2)
            echo -e "${colors[cyan]}Current Hosts:${colors[reset]}"
            [[ -f "$payload" ]] && awk -F "/" '{print $1,$2,$3,$4}' "$payload"
            local host
            while true; do
                read -p "Enter host to remove (e.g., .example.com): " host
                [[ "$host" =~ ^\..+ ]] && break
                echo -e "${colors[red]}Host must start with a dot${colors[reset]}"
            done
            if ! grep -Fx "$host/" "$payload" >/dev/null; then
                echo -e "${colors[red]}Host not found${colors[reset]}"
                return 1
            fi
            grep -vFx "$host/" "$payload" > "$(mktemp)" && mv "$(mktemp)" "$payload"
            echo -e "${colors[green]}Host removed successfully${colors[reset]}"
            awk -F "/" '{print $1,$2,$3,$4}' "$payload"
            systemctl reload "$SQUID_SERVICE" >/dev/null 2>&1 || {
                echo -e "${colors[red]}Error: Failed to reload Squid${colors[reset]}"
                return 1
            }
            ;;
        3) fun_squid ;;
        *) echo -e "${colors[red]}Invalid option${colors[reset]}" ;;
    esac
}

# Main execution
if [[ -e "$SQUID_CONF" ]]; then
    online_squid
else
    fun_squid
fi