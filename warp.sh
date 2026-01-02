#!/usr/bin/env bash
#
# Cloudflare WARP Installer (P3TERX warp.sh) - patched:
# A) Correct per-mode Address/DNS (IPv4-only / IPv6-only / Dual)
# B) Idempotent ip rule (PreUp del / PostDown del)
# C) Fix non-global PostUp + route replace
# D) Separate interfaces + systemd units per mode; auto-disable others
#

shVersion='beta39-patched3-A_B_C_D'

FontColor_Red="\033[31m"
FontColor_Red_Bold="\033[1;31m"
FontColor_Green="\033[32m"
FontColor_Green_Bold="\033[1;32m"
FontColor_Yellow="\033[33m"
FontColor_Yellow_Bold="\033[1;33m"
FontColor_Purple="\033[35m"
FontColor_Purple_Bold="\033[1;35m"
FontColor_Suffix="\033[0m"

log() {
    local LEVEL="$1"
    local MSG="$2"
    case "${LEVEL}" in
    INFO)
        local LEVEL="[${FontColor_Green}${LEVEL}${FontColor_Suffix}]"
        local MSG="${LEVEL} ${MSG}"
        ;;
    WARN)
        local LEVEL="[${FontColor_Yellow}${LEVEL}${FontColor_Suffix}]"
        local MSG="${LEVEL} ${MSG}"
        ;;
    ERROR)
        local LEVEL="[${FontColor_Red}${LEVEL}${FontColor_Suffix}]"
        local MSG="${LEVEL} ${MSG}"
        ;;
    *) ;;
    esac
    echo -e "${MSG}"
}

if [[ $(uname -s) != Linux ]]; then
    log ERROR "This operating system is not supported."
    exit 1
fi

if [[ $(id -u) != 0 ]]; then
    log ERROR "This script must be run as root."
    exit 1
fi

if [[ -z $(command -v curl) ]]; then
    log ERROR "cURL is not installed."
    exit 1
fi

WGCF_Profile='wgcf-profile.conf'
WGCF_ProfileDir="/etc/warp"
WGCF_ProfilePath="${WGCF_ProfileDir}/${WGCF_Profile}"

# ===== Interface mapping (D) =====
WG_IFACE_V4="wgcf4"
WG_IFACE_V6="wgcf6"
WG_IFACE_DUAL="wgcfd"
WG_IFACE_NG="wgcfng"
ALL_WG_INTERFACES=("${WG_IFACE_V4}" "${WG_IFACE_V6}" "${WG_IFACE_DUAL}" "${WG_IFACE_NG}")

# Active interface (will be set by mode)
WireGuard_Interface=''
WireGuard_ConfPath=''

WireGuard_Interface_DNS_IPv4='1.1.1.1,1.0.0.1'
WireGuard_Interface_DNS_IPv6='2606:4700:4700::1111,2606:4700:4700::1001'
WireGuard_Interface_DNS_46="${WireGuard_Interface_DNS_IPv4},${WireGuard_Interface_DNS_IPv6}"

WireGuard_Interface_Rule_table='51888'
WireGuard_Interface_Rule_fwmark='51888'
WireGuard_Interface_MTU='1280'

WireGuard_Peer_Endpoint_IP4='162.159.192.1'
WireGuard_Peer_Endpoint_IP6='2606:4700:d0::a29f:c001'
WireGuard_Peer_Endpoint_IPv4="${WireGuard_Peer_Endpoint_IP4}:2408"
WireGuard_Peer_Endpoint_IPv6="[${WireGuard_Peer_Endpoint_IP6}]:2408"
WireGuard_Peer_Endpoint_Domain='engage.cloudflareclient.com:2408'
WireGuard_Peer_AllowedIPs_IPv4='0.0.0.0/0'
WireGuard_Peer_AllowedIPs_IPv6='::/0'
WireGuard_Peer_AllowedIPs_DualStack='0.0.0.0/0,::/0'

TestIPv4_1='1.0.0.1'
TestIPv4_2='9.9.9.9'
TestIPv6_1='2606:4700:4700::1001'
TestIPv6_2='2620:fe::fe'
CF_Trace_URL='https://www.cloudflare.com/cdn-cgi/trace'

# ===== PATCH HELPERS =====
ensure_wireguard_dir() {
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard
}

# Debian10/old repo fallback build wg + wg-quick
install_wireguard_tools_from_source_debian10() {
    log INFO "Debian10/old repo: building wireguard-tools (wg + wg-quick) from source..."

    apt update -y
    apt install -y curl ca-certificates tar xz-utils iproute2 openresolv build-essential

    local VER="v1.0.20210914"
    local TMP="/tmp/wgtools"
    rm -rf "$TMP"
    mkdir -p "$TMP"
    cd "$TMP" || return 1

    curl -L -o wireguard-tools.tar.xz \
      "https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-${VER}.tar.xz" || return 1

    tar -xf wireguard-tools.tar.xz || return 1
    cd wireguard-tools-* || return 1

    make -C src -j"$(nproc)" && make -C src install || return 1

    if ! command -v wg-quick >/dev/null 2>&1; then
        if [[ -d contrib/wg-quick ]]; then
            make -C contrib/wg-quick -j"$(nproc)" && make -C contrib/wg-quick install || return 1
        elif [[ -d src/wg-quick ]]; then
            make -C src/wg-quick -j"$(nproc)" && make -C src/wg-quick install || return 1
        else
            log ERROR "wg-quick not found after install, and no known build dir exists."
            return 1
        fi
    fi

    systemctl daemon-reload >/dev/null 2>&1 || true
    command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1
}

Get_System_Info() {
    source /etc/os-release
    SysInfo_OS_CodeName="${VERSION_CODENAME}"
    SysInfo_OS_Name_lowercase="${ID}"
    SysInfo_OS_Name_Full="${PRETTY_NAME}"
    SysInfo_RelatedOS="${ID_LIKE}"
    SysInfo_Kernel="$(uname -r)"
    SysInfo_Kernel_Ver_major="$(uname -r | awk -F . '{print $1}')"
    SysInfo_Kernel_Ver_minor="$(uname -r | awk -F . '{print $2}')"
    SysInfo_Arch="$(uname -m)"
    SysInfo_Virt="$(systemd-detect-virt)"
    case ${SysInfo_RelatedOS} in
    *fedora* | *rhel*)
        SysInfo_OS_Ver_major="$(rpm -E '%{rhel}' 2>/dev/null)"
        ;;
    *)
        SysInfo_OS_Ver_major="$(echo ${VERSION_ID} | cut -d. -f1)"
        ;;
    esac
}

Print_System_Info() {
    echo -e "
System Information
---------------------------------------------------
  Operating System: ${SysInfo_OS_Name_Full}
      Linux Kernel: ${SysInfo_Kernel}
      Architecture: ${SysInfo_Arch}
    Virtualization: ${SysInfo_Virt}
---------------------------------------------------
"
}

Install_Requirements_Debian() {
    if [[ ! $(command -v gpg) ]]; then
        apt update
        apt install gnupg -y
    fi
    if [[ ! $(apt list 2>/dev/null | grep apt-transport-https | grep installed) ]]; then
        apt update
        apt install apt-transport-https -y
    fi
}

Install_WARP_Client_Debian() {
    if [[ ${SysInfo_OS_Name_lowercase} = ubuntu ]]; then
        case ${SysInfo_OS_CodeName} in
        bionic | focal | jammy | noble) ;;
        *)
            log ERROR "This operating system is not supported."
            exit 1
            ;;
        esac
    elif [[ ${SysInfo_OS_Name_lowercase} = debian ]]; then
        case ${SysInfo_OS_CodeName} in
        buster | bullseye | bookworm | trixie) ;;
        *)
            log ERROR "This operating system is not supported."
            exit 1
            ;;
        esac
    fi
    Install_Requirements_Debian
    curl https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ ${SysInfo_OS_CodeName} main" | tee /etc/apt/sources.list.d/cloudflare-client.list
    apt update
    apt install cloudflare-warp -y
}

Install_WARP_Client_CentOS() {
    if [[ ${SysInfo_OS_Ver_major} = 8 ]]; then
        rpm -ivh http://pkg.cloudflareclient.com/cloudflare-release-el8.rpm
        yum install cloudflare-warp -y
    else
        log ERROR "This operating system is not supported."
        exit 1
    fi
}

Check_WARP_Client() {
    WARP_Client_Status=$(systemctl is-active warp-svc 2>/dev/null)
    WARP_Client_SelfStart=$(systemctl is-enabled warp-svc 2>/dev/null)
}

Install_WARP_Client() {
    Print_System_Info
    log INFO "Installing Cloudflare WARP Client..."
    if [[ ${SysInfo_Arch} != x86_64 ]]; then
        log ERROR "This CPU architecture is not supported: ${SysInfo_Arch}"
        exit 1
    fi
    case ${SysInfo_OS_Name_lowercase} in
    *debian* | *ubuntu*)
        Install_WARP_Client_Debian
        ;;
    *centos* | *rhel*)
        Install_WARP_Client_CentOS
        ;;
    *)
        if [[ ${SysInfo_RelatedOS} = *rhel* || ${SysInfo_RelatedOS} = *fedora* ]]; then
            Install_WARP_Client_CentOS
        else
            log ERROR "This operating system is not supported."
            exit 1
        fi
        ;;
    esac
    Check_WARP_Client
    if [[ ${WARP_Client_Status} = active ]]; then
        log INFO "Cloudflare WARP Client installed successfully!"
    else
        log ERROR "warp-svc failure to run!"
        journalctl -u warp-svc --no-pager
        exit 1
    fi
}

Uninstall_WARP_Client() {
    log INFO "Uninstalling Cloudflare WARP Client..."
    case ${SysInfo_OS_Name_lowercase} in
    *debian* | *ubuntu*)
        apt purge cloudflare-warp -y
        rm -f /etc/apt/sources.list.d/cloudflare-client.list /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        ;;
    *centos* | *rhel*)
        yum remove cloudflare-warp -y
        ;;
    *)
        if [[ ${SysInfo_RelatedOS} = *rhel* || ${SysInfo_RelatedOS} = *fedora* ]]; then
            yum remove cloudflare-warp -y
        else
            log ERROR "This operating system is not supported."
            exit 1
        fi
        ;;
    esac
}

Restart_WARP_Client() {
    log INFO "Restarting Cloudflare WARP Client..."
    systemctl restart warp-svc
    Check_WARP_Client
    if [[ ${WARP_Client_Status} = active ]]; then
        log INFO "Cloudflare WARP Client has been restarted."
    else
        log ERROR "Cloudflare WARP Client failure to run!"
        journalctl -u warp-svc --no-pager
        exit 1
    fi
}

# NEW warp-cli registration style + fallback old
Init_WARP_Client() {
    Check_WARP_Client
    if [[ ${WARP_Client_SelfStart} != enabled || ${WARP_Client_Status} != active ]]; then
        Install_WARP_Client
    fi

    if ! warp-cli --accept-tos registration show >/dev/null 2>&1; then
        log INFO "Cloudflare WARP registration in progress..."
        warp-cli --accept-tos registration new >/dev/null 2>&1 || warp-cli --accept-tos register >/dev/null 2>&1 || true
    fi
}

Connect_WARP() {
    log INFO "Connecting to WARP..."
    warp-cli --accept-tos connect
    log INFO "Enable WARP Always-On..."
    warp-cli --accept-tos enable-always-on >/dev/null 2>&1 || true
}

Disconnect_WARP() {
    log INFO "Disable WARP Always-On..."
    warp-cli --accept-tos disable-always-on >/dev/null 2>&1 || true
    log INFO "Disconnect from WARP..."
    warp-cli --accept-tos disconnect >/dev/null 2>&1 || true

    warp-cli --accept-tos mode warp >/dev/null 2>&1 || warp-cli --accept-tos set-mode warp >/dev/null 2>&1 || true
}

Set_WARP_Mode_Proxy() {
    log INFO "Setting up WARP Proxy Mode..."
    warp-cli --accept-tos mode proxy >/dev/null 2>&1 || warp-cli --accept-tos set-mode proxy
}

Get_WARP_Proxy_Port() {
    WARP_Proxy_Port='40000'
}

Set_WARP_Proxy_Port() {
    Get_WARP_Proxy_Port
    log INFO "Setting SOCKS5 proxy port: ${WARP_Proxy_Port}"
    warp-cli --accept-tos proxy port "${WARP_Proxy_Port}" >/dev/null 2>&1 || true
}

Enable_WARP_Client_Proxy() {
    Init_WARP_Client
    Set_WARP_Mode_Proxy
    Set_WARP_Proxy_Port
    Connect_WARP
    Print_WARP_Client_Status
}

Print_Delimiter() {
    printf '=%.0s' $(seq $(tput cols))
    echo
}

Install_wgcf() {
    curl -fsSL https://raw.githubusercontent.com/NevermoreSSH/script/master/wgcf.sh | bash
}

Uninstall_wgcf() {
    rm -f /usr/local/bin/wgcf
}

Register_WARP_Account() {
    while [[ ! -f wgcf-account.toml ]]; do
        Install_wgcf
        log INFO "Cloudflare WARP Account registration in progress..."
        yes | wgcf register
        sleep 3
    done
}

Generate_WGCF_Profile() {
    while [[ ! -f ${WGCF_Profile} ]]; do
        Register_WARP_Account
        log INFO "WARP WireGuard profile (wgcf-profile.conf) generation in progress..."
        wgcf generate
    done
    Uninstall_wgcf
}

Backup_WGCF_Profile() {
    mkdir -p ${WGCF_ProfileDir}
    mv -f wgcf* ${WGCF_ProfileDir} 2>/dev/null || true
}

# ===== A) Read WGCF profile with CIDR split =====
Read_WGCF_Profile() {
    WireGuard_Interface_PrivateKey=$(grep ^PrivateKey "${WGCF_ProfilePath}" | cut -d= -f2- | awk '$1=$1')
    WireGuard_Peer_PublicKey=$(grep ^PublicKey "${WGCF_ProfilePath}" | cut -d= -f2- | awk '$1=$1')

    local addr_line
    addr_line=$(grep ^Address "${WGCF_ProfilePath}" | cut -d= -f2- | awk '$1=$1' | tr -d ' ')
    WireGuard_Interface_Address_IPv4_CIDR=$(echo "$addr_line" | cut -d, -f1)
    WireGuard_Interface_Address_IPv6_CIDR=$(echo "$addr_line" | cut -d, -f2)

    WireGuard_Interface_Address_IPv4=$(echo "${WireGuard_Interface_Address_IPv4_CIDR}" | cut -d'/' -f1)
    WireGuard_Interface_Address_IPv6=$(echo "${WireGuard_Interface_Address_IPv6_CIDR}" | cut -d'/' -f1)

    WireGuard_Interface_Address_46="${WireGuard_Interface_Address_IPv4_CIDR},${WireGuard_Interface_Address_IPv6_CIDR}"
}

Load_WGCF_Profile() {
    if [[ -f ${WGCF_Profile} ]]; then
        Backup_WGCF_Profile
        Read_WGCF_Profile
    elif [[ -f ${WGCF_ProfilePath} ]]; then
        Read_WGCF_Profile
    else
        Generate_WGCF_Profile
        Backup_WGCF_Profile
        Read_WGCF_Profile
    fi
}

Install_WireGuardTools_Debian() {
    apt update
    apt install -y iproute2 openresolv

    if apt-cache show wireguard-tools >/dev/null 2>&1; then
        apt install -y wireguard-tools --no-install-recommends
    else
        log WARN "wireguard-tools not found in apt. Fallback to source build..."
        install_wireguard_tools_from_source_debian10 || {
            log ERROR "Failed to build/install wireguard-tools from source."
            exit 1
        }
    fi
}

Install_WireGuardTools_Ubuntu() {
    apt update
    apt install iproute2 openresolv -y
    apt install wireguard-tools --no-install-recommends -y
}

Install_WireGuardTools_CentOS() {
    yum install epel-release -y || yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-${SysInfo_OS_Ver_major}.noarch.rpm -y
    yum install iproute iptables wireguard-tools -y
}

Install_WireGuardTools_Fedora() {
    dnf install iproute iptables wireguard-tools -y
}

Install_WireGuardTools_Arch() {
    pacman -Sy iproute2 openresolv wireguard-tools --noconfirm
}

Install_WireGuardTools() {
    log INFO "Installing wireguard-tools..."
    case ${SysInfo_OS_Name_lowercase} in
    *debian*)
        Install_WireGuardTools_Debian
        ;;
    *ubuntu*)
        Install_WireGuardTools_Ubuntu
        ;;
    *centos* | *rhel*)
        Install_WireGuardTools_CentOS
        ;;
    *fedora*)
        Install_WireGuardTools_Fedora
        ;;
    *arch*)
        Install_WireGuardTools_Arch
        ;;
    *)
        if [[ ${SysInfo_RelatedOS} = *rhel* || ${SysInfo_RelatedOS} = *fedora* ]]; then
            Install_WireGuardTools_CentOS
        else
            log ERROR "This operating system is not supported."
            exit 1
        fi
        ;;
    esac
}

Install_WireGuardGo() {
    case ${SysInfo_Virt} in
    openvz | lxc*)
        curl -fsSL https://raw.githubusercontent.com/NevermoreSSH/script/master/wireguard-go.sh | bash
        ;;
    *)
        if [[ ${SysInfo_Kernel_Ver_major} -lt 5 || ${SysInfo_Kernel_Ver_minor} -lt 6 ]]; then
            curl -fsSL https://raw.githubusercontent.com/NevermoreSSH/script/master/wireguard-go.sh | bash
        fi
        ;;
    esac
}

# ===== D) Mode -> Interface selector =====
Set_Mode_Interface() {
    local mode="$1"
    case "$mode" in
        v4)   WireGuard_Interface="${WG_IFACE_V4}" ;;
        v6)   WireGuard_Interface="${WG_IFACE_V6}" ;;
        dual) WireGuard_Interface="${WG_IFACE_DUAL}" ;;
        ng)   WireGuard_Interface="${WG_IFACE_NG}" ;;
        *)
            log ERROR "Unknown mode: $mode"
            exit 1
            ;;
    esac
    WireGuard_ConfPath="/etc/wireguard/${WireGuard_Interface}.conf"
}

Disable_WireGuard_All() {
    Check_WARP_Client
    for iface in "${ALL_WG_INTERFACES[@]}"; do
        systemctl disable "wg-quick@${iface}" --now >/dev/null 2>&1 || true
    done
    if [[ ${WARP_Client_Status} = active ]]; then
        systemctl start warp-svc >/dev/null 2>&1 || true
    fi
}

Disable_Other_WG_Units() {
    local keep="$1"
    Check_WARP_Client
    for iface in "${ALL_WG_INTERFACES[@]}"; do
        [[ "$iface" == "$keep" ]] && continue
        systemctl disable "wg-quick@${iface}" --now >/dev/null 2>&1 || true
    done
}

Check_WireGuard() {
    # check current interface
    WireGuard_Status=$(systemctl is-active "wg-quick@${WireGuard_Interface}" 2>/dev/null)
    WireGuard_SelfStart=$(systemctl is-enabled "wg-quick@${WireGuard_Interface}" 2>/dev/null)
}

Install_WireGuard() {
    Print_System_Info
    # Don't rely on unit status for install; just ensure tools exist
    if ! command -v wg >/dev/null 2>&1 || ! command -v wg-quick >/dev/null 2>&1; then
        Install_WireGuardTools
        Install_WireGuardGo
    else
        log INFO "WireGuard tools already installed."
    fi
}

Start_WireGuard() {
    command -v wg-quick >/dev/null 2>&1 || {
        log ERROR "wg-quick not found. WireGuard tools not installed properly."
        exit 1
    }

    # D) Disable other WG units so reboot stays in last mode
    Disable_Other_WG_Units "${WireGuard_Interface}"

    Check_WARP_Client
    log INFO "Starting WireGuard (${WireGuard_Interface})..."
    if [[ ${WARP_Client_Status} = active ]]; then
        systemctl stop warp-svc >/dev/null 2>&1 || true
        systemctl enable "wg-quick@${WireGuard_Interface}" --now
        systemctl start warp-svc >/dev/null 2>&1 || true
    else
        systemctl enable "wg-quick@${WireGuard_Interface}" --now
    fi

    Check_WireGuard
    if [[ ${WireGuard_Status} = active ]]; then
        log INFO "WireGuard is running."
    else
        log ERROR "WireGuard failure to run!"
        journalctl -u "wg-quick@${WireGuard_Interface}" --no-pager
        exit 1
    fi
}

Restart_WireGuard() {
    Disable_Other_WG_Units "${WireGuard_Interface}"

    Check_WARP_Client
    log INFO "Restarting WireGuard (${WireGuard_Interface})..."
    if [[ ${WARP_Client_Status} = active ]]; then
        systemctl stop warp-svc >/dev/null 2>&1 || true
        systemctl restart "wg-quick@${WireGuard_Interface}"
        systemctl start warp-svc >/dev/null 2>&1 || true
    else
        systemctl restart "wg-quick@${WireGuard_Interface}"
    fi

    Check_WireGuard
    if [[ ${WireGuard_Status} = active ]]; then
        log INFO "WireGuard has been restarted."
    else
        log ERROR "WireGuard failure to run!"
        journalctl -u "wg-quick@${WireGuard_Interface}" --no-pager
        exit 1
    fi
}

Enable_IPv6_Support() {
    if [[ $(sysctl -a 2>/dev/null | grep 'disable_ipv6.*=.*1') || $(cat /etc/sysctl.{conf,d/*} 2>/dev/null | grep 'disable_ipv6.*=.*1') ]]; then
        sed -i '/disable_ipv6/d' /etc/sysctl.{conf,d/*} 2>/dev/null
        echo 'net.ipv6.conf.all.disable_ipv6 = 0' >/etc/sysctl.d/ipv6.conf
        sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
    fi
}

Enable_WireGuard() {
    Enable_IPv6_Support
    Check_WireGuard
    if [[ ${WireGuard_SelfStart} = enabled ]]; then
        Restart_WireGuard
    else
        Start_WireGuard
    fi
}

Disable_WireGuard() {
    Check_WARP_Client
    Check_WireGuard
    if [[ ${WireGuard_SelfStart} = enabled || ${WireGuard_Status} = active ]]; then
        log INFO "Disabling WireGuard (${WireGuard_Interface})..."
        if [[ ${WARP_Client_Status} = active ]]; then
            systemctl stop warp-svc >/dev/null 2>&1 || true
            systemctl disable "wg-quick@${WireGuard_Interface}" --now
            systemctl start warp-svc >/dev/null 2>&1 || true
        else
            systemctl disable "wg-quick@${WireGuard_Interface}" --now
        fi
        Check_WireGuard
        if [[ ${WireGuard_SelfStart} != enabled && ${WireGuard_Status} != active ]]; then
            log INFO "WireGuard has been disabled."
        else
            log ERROR "WireGuard disable failure!"
        fi
    else
        log INFO "WireGuard is disabled."
    fi
}

Check_Network_Status_IPv4() {
    if ping -c1 -W1 ${TestIPv4_1} >/dev/null 2>&1 || ping -c1 -W1 ${TestIPv4_2} >/dev/null 2>&1; then
        IPv4Status='on'
    else
        IPv4Status='off'
    fi
}

Check_Network_Status_IPv6() {
    if ping6 -c1 -W1 ${TestIPv6_1} >/dev/null 2>&1 || ping6 -c1 -W1 ${TestIPv6_2} >/dev/null 2>&1; then
        IPv6Status='on'
    else
        IPv6Status='off'
    fi
}

Check_Network_Status() {
    # Original behavior disables WG before checking.
    # With multi-iface (D), disable all.
    Disable_WireGuard_All
    Check_Network_Status_IPv4
    Check_Network_Status_IPv6
}

Check_IPv4_addr() {
    IPv4_addr=$(
        ip route get ${TestIPv4_1} 2>/dev/null | grep -oP 'src \K\S+' ||
            ip route get ${TestIPv4_2} 2>/dev/null | grep -oP 'src \K\S+'
    )
}

Check_IPv6_addr() {
    IPv6_addr=$(
        ip route get ${TestIPv6_1} 2>/dev/null | grep -oP 'src \K\S+' ||
            ip route get ${TestIPv6_2} 2>/dev/null | grep -oP 'src \K\S+'
    )
}

Get_IP_addr() {
    Check_Network_Status
    if [[ ${IPv4Status} = on ]]; then
        log INFO "Getting the network interface IPv4 address..."
        Check_IPv4_addr
        [[ ${IPv4_addr} ]] && log INFO "IPv4 Address: ${IPv4_addr}" || log WARN "IPv4 address not obtained."
    fi
    if [[ ${IPv6Status} = on ]]; then
        log INFO "Getting the network interface IPv6 address..."
        Check_IPv6_addr
        [[ ${IPv6_addr} ]] && log INFO "IPv6 Address: ${IPv6_addr}" || log WARN "IPv6 address not obtained."
    fi
}

Get_WireGuard_Interface_MTU() {
    log INFO "Getting the best MTU value for WireGuard..."
    MTU_Preset=1500
    MTU_Increment=10
    if [[ ${IPv4Status} = off && ${IPv6Status} = on ]]; then
        CMD_ping='ping6'
        MTU_TestIP_1="${TestIPv6_1}"
        MTU_TestIP_2="${TestIPv6_2}"
    else
        CMD_ping='ping'
        MTU_TestIP_1="${TestIPv4_1}"
        MTU_TestIP_2="${TestIPv4_2}"
    fi
    while true; do
        if ${CMD_ping} -c1 -W1 -s$((${MTU_Preset} - 28)) -Mdo ${MTU_TestIP_1} >/dev/null 2>&1 || ${CMD_ping} -c1 -W1 -s$((${MTU_Preset} - 28)) -Mdo ${MTU_TestIP_2} >/dev/null 2>&1; then
            MTU_Increment=1
            MTU_Preset=$((${MTU_Preset} + ${MTU_Increment}))
        else
            MTU_Preset=$((${MTU_Preset} - ${MTU_Increment}))
            [[ ${MTU_Increment} = 1 ]] && break
        fi
        if [[ ${MTU_Preset} -le 1360 ]]; then
            log WARN "MTU is set to the lowest value."
            MTU_Preset='1360'
            break
        fi
    done
    WireGuard_Interface_MTU=$((${MTU_Preset} - 80))
    log INFO "WireGuard MTU: ${WireGuard_Interface_MTU}"
}

# ===== A) Interface writer now takes Address + DNS =====
Generate_WireGuardProfile_Interface() {
    local ADDR="$1"
    local DNS="$2"

    ensure_wireguard_dir
    Get_WireGuard_Interface_MTU
    log INFO "WireGuard profile (${WireGuard_ConfPath}) generation in progress..."
    cat <<EOF >"${WireGuard_ConfPath}"

[Interface]
PrivateKey = ${WireGuard_Interface_PrivateKey}
Address = ${ADDR}
DNS = ${DNS}
MTU = ${WireGuard_Interface_MTU}
EOF
}

# ===== B) Idempotent ip rules (PreUp del, PostDown del) =====
Generate_WireGuardProfile_Interface_Rule_IPv4_Global_srcIP() {
cat <<EOF >>"${WireGuard_ConfPath}"
PreUp = ip -4 rule del from ${IPv4_addr} lookup main prio 18 2>/dev/null || true
PostUp = ip -4 rule add from ${IPv4_addr} lookup main prio 18 2>/dev/null || true
PostDown = ip -4 rule del from ${IPv4_addr} lookup main prio 18 2>/dev/null || true
EOF
}

Generate_WireGuardProfile_Interface_Rule_IPv6_Global_srcIP() {
cat <<EOF >>"${WireGuard_ConfPath}"
PreUp = ip -6 rule del from ${IPv6_addr} lookup main prio 18 2>/dev/null || true
PostUp = ip -6 rule add from ${IPv6_addr} lookup main prio 18 2>/dev/null || true
PostDown = ip -6 rule del from ${IPv6_addr} lookup main prio 18 2>/dev/null || true
EOF
}

Generate_WireGuardProfile_Interface_Rule_TableOff() {
cat <<EOF >>"${WireGuard_ConfPath}"
Table = off
EOF
}

# ===== C) non-global: PostUp correct + route replace + idempotent adds =====
Generate_WireGuardProfile_Interface_Rule_IPv4_nonGlobal() {
cat <<EOF >>"${WireGuard_ConfPath}"
PostUp = ip -4 route replace default dev ${WireGuard_Interface} table ${WireGuard_Interface_Rule_table}
PostUp = ip -4 rule add from ${WireGuard_Interface_Address_IPv4} lookup ${WireGuard_Interface_Rule_table} 2>/dev/null || true
PostDown = ip -4 rule del from ${WireGuard_Interface_Address_IPv4} lookup ${WireGuard_Interface_Rule_table} 2>/dev/null || true
PostUp = ip -4 rule add fwmark ${WireGuard_Interface_Rule_fwmark} lookup ${WireGuard_Interface_Rule_table} 2>/dev/null || true
PostDown = ip -4 rule del fwmark ${WireGuard_Interface_Rule_fwmark} lookup ${WireGuard_Interface_Rule_table} 2>/dev/null || true
PostUp = ip -4 rule add table main suppress_prefixlength 0 2>/dev/null || true
PostDown = ip -4 rule del table main suppress_prefixlength 0 2>/dev/null || true
EOF
}

Generate_WireGuardProfile_Interface_Rule_IPv6_nonGlobal() {
cat <<EOF >>"${WireGuard_ConfPath}"
PostUp = ip -6 route replace default dev ${WireGuard_Interface} table ${WireGuard_Interface_Rule_table}
PostUp = ip -6 rule add from ${WireGuard_Interface_Address_IPv6} lookup ${WireGuard_Interface_Rule_table} 2>/dev/null || true
PostDown = ip -6 rule del from ${WireGuard_Interface_Address_IPv6} lookup ${WireGuard_Interface_Rule_table} 2>/dev/null || true
PostUp = ip -6 rule add fwmark ${WireGuard_Interface_Rule_fwmark} lookup ${WireGuard_Interface_Rule_table} 2>/dev/null || true
PostDown = ip -6 rule del fwmark ${WireGuard_Interface_Rule_fwmark} lookup ${WireGuard_Interface_Rule_table} 2>/dev/null || true
PostUp = ip -6 rule add table main suppress_prefixlength 0 2>/dev/null || true
PostDown = ip -6 rule del table main suppress_prefixlength 0 2>/dev/null || true
EOF
}

Generate_WireGuardProfile_Interface_Rule_DualStack_nonGlobal() {
    Generate_WireGuardProfile_Interface_Rule_TableOff
    Generate_WireGuardProfile_Interface_Rule_IPv4_nonGlobal
    Generate_WireGuardProfile_Interface_Rule_IPv6_nonGlobal
}

Generate_WireGuardProfile_Peer() {
cat <<EOF >>"${WireGuard_ConfPath}"

[Peer]
PublicKey = ${WireGuard_Peer_PublicKey}
AllowedIPs = ${WireGuard_Peer_AllowedIPs}
Endpoint = ${WireGuard_Peer_Endpoint}
EOF
}

Check_WireGuard_Peer_Endpoint() {
    if ping -c1 -W1 ${WireGuard_Peer_Endpoint_IP4} >/dev/null 2>&1; then
        WireGuard_Peer_Endpoint="${WireGuard_Peer_Endpoint_IPv4}"
    elif ping6 -c1 -W1 ${WireGuard_Peer_Endpoint_IP6} >/dev/null 2>&1; then
        WireGuard_Peer_Endpoint="${WireGuard_Peer_Endpoint_IPv6}"
    else
        WireGuard_Peer_Endpoint="${WireGuard_Peer_Endpoint_Domain}"
    fi
}

# ===== STATUS PRINT =====
Check_WARP_Client_Status() {
    Check_WARP_Client
    case ${WARP_Client_Status} in
    active) WARP_Client_Status_en="${FontColor_Green}Running${FontColor_Suffix}" ;;
    *)      WARP_Client_Status_en="${FontColor_Red}Stopped${FontColor_Suffix}" ;;
    esac
}

Check_WARP_Proxy_Status() {
    Check_WARP_Client
    if [[ ${WARP_Client_Status} = active ]]; then
        Get_WARP_Proxy_Port
        WARP_Proxy_Status=$(curl -sx "socks5h://127.0.0.1:${WARP_Proxy_Port}" ${CF_Trace_URL} --connect-timeout 2 | grep warp | cut -d= -f2)
    else
        unset WARP_Proxy_Status
    fi
    case ${WARP_Proxy_Status} in
    on)   WARP_Proxy_Status_en="${FontColor_Green}${WARP_Proxy_Port}${FontColor_Suffix}" ;;
    plus) WARP_Proxy_Status_en="${FontColor_Green}${WARP_Proxy_Port}(WARP+)${FontColor_Suffix}" ;;
    *)    WARP_Proxy_Status_en="${FontColor_Red}Off${FontColor_Suffix}" ;;
    esac
}

Check_WireGuard_Status() {
    if [[ -n "${WireGuard_Interface}" ]]; then
        Check_WireGuard
        case ${WireGuard_Status} in
        active) WireGuard_Status_en="${FontColor_Green}Running(${WireGuard_Interface})${FontColor_Suffix}" ;;
        *)      WireGuard_Status_en="${FontColor_Red}Stopped${FontColor_Suffix}" ;;
        esac
    else
        WireGuard_Status_en="${FontColor_Red}Stopped${FontColor_Suffix}"
    fi
}

Check_WARP_WireGuard_Status() {
    Check_Network_Status_IPv4
    if [[ ${IPv4Status} = on ]]; then
        WARP_IPv4_Status=$(curl -s4 ${CF_Trace_URL} --connect-timeout 2 | grep warp | cut -d= -f2)
    else
        unset WARP_IPv4_Status
    fi
    case ${WARP_IPv4_Status} in
    on)   WARP_IPv4_Status_en="${FontColor_Green}WARP${FontColor_Suffix}" ;;
    plus) WARP_IPv4_Status_en="${FontColor_Green}WARP+${FontColor_Suffix}" ;;
    off)  WARP_IPv4_Status_en="Normal" ;;
    *)    WARP_IPv4_Status_en="Normal" ;;
    esac

    Check_Network_Status_IPv6
    if [[ ${IPv6Status} = on ]]; then
        WARP_IPv6_Status=$(curl -s6 ${CF_Trace_URL} --connect-timeout 2 | grep warp | cut -d= -f2)
    else
        unset WARP_IPv6_Status
    fi
    case ${WARP_IPv6_Status} in
    on)   WARP_IPv6_Status_en="${FontColor_Green}WARP${FontColor_Suffix}" ;;
    plus) WARP_IPv6_Status_en="${FontColor_Green}WARP+${FontColor_Suffix}" ;;
    off)  WARP_IPv6_Status_en="Normal" ;;
    *)    WARP_IPv6_Status_en="Normal" ;;
    esac

    if [[ ${IPv4Status} = off && ${IPv6Status} = off ]]; then
        log ERROR "Cloudflare WARP network anomaly, WireGuard tunnel established failed."
        Disable_WireGuard_All
        exit 1
    fi
}

Check_ALL_Status() {
    Check_WARP_Client_Status
    Check_WARP_Proxy_Status
    # show any active wg-quick unit among our list
    WireGuard_Status_en="${FontColor_Red}Stopped${FontColor_Suffix}"
    for iface in "${ALL_WG_INTERFACES[@]}"; do
        if systemctl is-active "wg-quick@${iface}" >/dev/null 2>&1; then
            WireGuard_Status_en="${FontColor_Green}Running(${iface})${FontColor_Suffix}"
            break
        fi
    done
    Check_WARP_WireGuard_Status
}

Print_WARP_Client_Status() {
    log INFO "Status check in progress..."
    sleep 2
    Check_WARP_Client_Status
    Check_WARP_Proxy_Status
    echo -e "
 ----------------------------
 WARP Client\t: ${WARP_Client_Status_en}
 SOCKS5 Port\t: ${WARP_Proxy_Status_en}
 ----------------------------
"
    log INFO "Done."
}

Print_WARP_WireGuard_Status() {
    log INFO "Status check in progress..."
    Check_WireGuard_Status
    Check_WARP_WireGuard_Status
    echo -e "
 ----------------------------
 WireGuard\t: ${WireGuard_Status_en}
 IPv4 Network\t: ${WARP_IPv4_Status_en}
 IPv6 Network\t: ${WARP_IPv6_Status_en}
 ----------------------------
"
    log INFO "Done."
}

Print_ALL_Status() {
    log INFO "Status check in progress..."
    Check_ALL_Status
    echo -e "
 ----------------------------
 WARP Client\t: ${WARP_Client_Status_en}
 SOCKS5 Port\t: ${WARP_Proxy_Status_en}
 ----------------------------
 WireGuard\t: ${WireGuard_Status_en}
 IPv4 Network\t: ${WARP_IPv4_Status_en}
 IPv6 Network\t: ${WARP_IPv6_Status_en}
 ----------------------------
"
}

View_WireGuard_Profile() {
    Print_Delimiter
    cat "${WireGuard_ConfPath}"
    Print_Delimiter
}

# ===== MAIN CONFIG =====
# A) Per-mode Address/DNS strict
Set_WARP_IPv4() {
    Set_Mode_Interface v4
    Install_WireGuard
    Get_IP_addr
    Load_WGCF_Profile

    WireGuard_Peer_AllowedIPs="${WireGuard_Peer_AllowedIPs_IPv4}"
    WireGuard_Interface_DNS="${WireGuard_Interface_DNS_IPv4}"
    Check_WireGuard_Peer_Endpoint

    Generate_WireGuardProfile_Interface "${WireGuard_Interface_Address_IPv4_CIDR}" "${WireGuard_Interface_DNS}"
    if [[ -n ${IPv4_addr} ]]; then
        Generate_WireGuardProfile_Interface_Rule_IPv4_Global_srcIP
    fi
    Generate_WireGuardProfile_Peer

    View_WireGuard_Profile
    Enable_WireGuard
    Print_WARP_WireGuard_Status
}

Set_WARP_IPv6() {
    Set_Mode_Interface v6
    Install_WireGuard
    Get_IP_addr
    Load_WGCF_Profile

    WireGuard_Peer_AllowedIPs="${WireGuard_Peer_AllowedIPs_IPv6}"
    WireGuard_Interface_DNS="${WireGuard_Interface_DNS_IPv6}"
    Check_WireGuard_Peer_Endpoint

    Generate_WireGuardProfile_Interface "${WireGuard_Interface_Address_IPv6_CIDR}" "${WireGuard_Interface_DNS}"
    if [[ -n ${IPv6_addr} ]]; then
        Generate_WireGuardProfile_Interface_Rule_IPv6_Global_srcIP
    fi
    Generate_WireGuardProfile_Peer

    View_WireGuard_Profile
    Enable_WireGuard
    Print_WARP_WireGuard_Status
}

Set_WARP_DualStack() {
    Set_Mode_Interface dual
    Install_WireGuard
    Get_IP_addr
    Load_WGCF_Profile

    WireGuard_Interface_DNS="${WireGuard_Interface_DNS_46}"
    WireGuard_Peer_AllowedIPs="${WireGuard_Peer_AllowedIPs_DualStack}"
    Check_WireGuard_Peer_Endpoint

    Generate_WireGuardProfile_Interface "${WireGuard_Interface_Address_46}" "${WireGuard_Interface_DNS}"
    if [[ -n ${IPv4_addr} ]]; then
        Generate_WireGuardProfile_Interface_Rule_IPv4_Global_srcIP
    fi
    if [[ -n ${IPv6_addr} ]]; then
        Generate_WireGuardProfile_Interface_Rule_IPv6_Global_srcIP
    fi
    Generate_WireGuardProfile_Peer

    View_WireGuard_Profile
    Enable_WireGuard
    Print_WARP_WireGuard_Status
}

Set_WARP_DualStack_nonGlobal() {
    Set_Mode_Interface ng
    Install_WireGuard
    Get_IP_addr
    Load_WGCF_Profile

    WireGuard_Interface_DNS="${WireGuard_Interface_DNS_46}"
    WireGuard_Peer_AllowedIPs="${WireGuard_Peer_AllowedIPs_DualStack}"
    Check_WireGuard_Peer_Endpoint

    Generate_WireGuardProfile_Interface "${WireGuard_Interface_Address_46}" "${WireGuard_Interface_DNS}"
    Generate_WireGuardProfile_Interface_Rule_DualStack_nonGlobal
    Generate_WireGuardProfile_Peer

    View_WireGuard_Profile
    Enable_WireGuard
    Print_WARP_WireGuard_Status
}

Print_Usage() {
    echo -e "
Cloudflare WARP Installer [${shVersion}]

USAGE:
    warp2 <SUBCOMMAND>

SUBCOMMANDS:
    install         Install Cloudflare WARP Official Linux Client
    uninstall       Uninstall Cloudflare WARP Official Linux Client
    restart         Restart Cloudflare WARP Official Linux Client
    proxy           Enable WARP Client Proxy Mode (SOCKS5 port: 40000)
    unproxy         Disable WARP Client Proxy Mode
    wg              Install WireGuard and related components (tools)
    wg4             Configure WARP WireGuard IPv4 ONLY (Global)  -> iface ${WG_IFACE_V4}
    wg6             Configure WARP WireGuard IPv6 ONLY (Global)  -> iface ${WG_IFACE_V6}
    wgd             Configure WARP WireGuard Dual Stack (Global) -> iface ${WG_IFACE_DUAL}
    wgx             Configure WARP WireGuard Non-Global (Dual)   -> iface ${WG_IFACE_NG}
    rwg             Restart WireGuard service (auto detect active iface)
    dwg             Disable ALL WARP WireGuard services
    status          Show status
    version         Show script version
    help            Show this help
"
}

Restart_WireGuard_Auto() {
    # restart whichever is active; if none active, restart last-known (default dual)
    local active=""
    for iface in "${ALL_WG_INTERFACES[@]}"; do
        if systemctl is-active "wg-quick@${iface}" >/dev/null 2>&1; then
            active="$iface"
            break
        fi
    done
    [[ -z "$active" ]] && active="${WG_IFACE_DUAL}"
    WireGuard_Interface="$active"
    WireGuard_ConfPath="/etc/wireguard/${WireGuard_Interface}.conf"
    Restart_WireGuard
}

# ===== ENTRY =====
if [ $# -ge 1 ]; then
    Get_System_Info
    case ${1} in
    install)   Install_WARP_Client ;;
    uninstall) Uninstall_WARP_Client ;;
    restart)   Restart_WARP_Client ;;
    proxy|socks5|s5)   Enable_WARP_Client_Proxy ;;
    unproxy|unsocks5|uns5) Disconnect_WARP ;;
    wg)    Install_WireGuard ;;
    wg4|4) Set_WARP_IPv4 ;;
    wg6|6) Set_WARP_IPv6 ;;
    wgd|d) Set_WARP_DualStack ;;
    wgx|x) Set_WARP_DualStack_nonGlobal ;;
    rwg)   Restart_WireGuard_Auto ;;
    dwg)   Disable_WireGuard_All ;;
    status) Print_ALL_Status ;;
    help)  Print_Usage ;;
    version) echo "${shVersion}" ;;
    *)
        log ERROR "Invalid Parameters: $*"
        Print_Usage
        exit 1
        ;;
    esac
else
    Print_Usage
fi
