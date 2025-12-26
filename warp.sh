#!/usr/bin/env bash
#
# https://github.com/P3TERX/warp.sh
# Description: Cloudflare WARP Installer (custom fixed)
# System Required: Debian, Ubuntu, Fedora, CentOS, Oracle Linux, Arch Linux
# Version: 1.0.40_Final-custom1
#
# MIT License
#
# Copyright (c) 2021-2024 P3TERX <https://p3terx.com>
# Modifications (c) 2025 community fixes (IPv4-only systemd drop-in, Ubuntu/Debian codename updates, wgcf parsing fixes)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

shVersion='1.0.40_Final-custom1'

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
        LEVEL="[${FontColor_Green}${LEVEL}${FontColor_Suffix}]"
        ;;
    WARN)
        LEVEL="[${FontColor_Yellow}${LEVEL}${FontColor_Suffix}]"
        ;;
    ERROR)
        LEVEL="[${FontColor_Red}${LEVEL}${FontColor_Suffix}]"
        ;;
    *) ;;
    esac
    echo -e "${LEVEL} ${MSG}"
}

die() {
    log ERROR "$1"
    exit 1
}

if [[ $(uname -s) != Linux ]]; then
    die "This operating system is not supported."
fi

if [[ $(id -u) != 0 ]]; then
    die "This script must be run as root."
fi

if [[ -z $(command -v curl) ]]; then
    die "cURL is not installed."
fi

WGCF_Profile='wgcf-profile.conf'
WGCF_ProfileDir="/etc/warp"
WGCF_ProfilePath="${WGCF_ProfileDir}/${WGCF_Profile}"

WireGuard_Interface='wgcf'
WireGuard_ConfPath="/etc/wireguard/${WireGuard_Interface}.conf"

# systemd drop-in for IPv4-only enforcement (wg4)
WG_SYSTEMD_DROPIN_DIR="/etc/systemd/system/wg-quick@${WireGuard_Interface}.service.d"
WG_SYSTEMD_IPV4_ONLY_DROPIN="${WG_SYSTEMD_DROPIN_DIR}/10-warp-ipv4-only.conf"
WG_IPV4_ONLY_HELPER="/usr/local/bin/warp-wgcf-ipv4-only"

# DNS (you can change if you want)
WireGuard_Interface_DNS_IPv4='1.1.1.1,1.0.0.1'
WireGuard_Interface_DNS_IPv6='2606:4700:4700::1111,2606:4700:4700::1001'
WireGuard_Interface_DNS_46="${WireGuard_Interface_DNS_IPv4},${WireGuard_Interface_DNS_IPv6}"
WireGuard_Interface_DNS_64="${WireGuard_Interface_DNS_IPv6},${WireGuard_Interface_DNS_IPv4}"
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

Get_System_Info() {
    # shellcheck disable=SC1091
    source /etc/os-release

    SysInfo_OS_CodeName="${VERSION_CODENAME:-}"
    SysInfo_OS_Name_lowercase="${ID:-unknown}"
    SysInfo_OS_Name_Full="${PRETTY_NAME:-Linux}"
    SysInfo_RelatedOS="${ID_LIKE:-}"
    SysInfo_Kernel="$(uname -r)"
    SysInfo_Kernel_Ver_major="$(uname -r | awk -F . '{print $1}')"
    SysInfo_Kernel_Ver_minor="$(uname -r | awk -F . '{print $2}')"
    SysInfo_Arch="$(uname -m)"
    SysInfo_Virt="$(systemd-detect-virt 2>/dev/null || echo unknown)"

    # Fallback codename if missing (minimal images sometimes)
    if [[ -z "${SysInfo_OS_CodeName}" ]]; then
        case "${SysInfo_OS_Name_lowercase}:${VERSION_ID:-}" in
        ubuntu:22.04) SysInfo_OS_CodeName="jammy" ;;
        ubuntu:24.04) SysInfo_OS_CodeName="noble" ;;
        debian:12) SysInfo_OS_CodeName="bookworm" ;;
        debian:13) SysInfo_OS_CodeName="trixie" ;;
        debian:11) SysInfo_OS_CodeName="bullseye" ;;
        debian:10) SysInfo_OS_CodeName="buster" ;;
        *) SysInfo_OS_CodeName="" ;;
        esac
    fi

    # Major version
    case "${SysInfo_RelatedOS}" in
    *fedora* | *rhel*)
        SysInfo_OS_Ver_major="$(rpm -E '%{rhel}' 2>/dev/null || echo 0)"
        ;;
    *)
        SysInfo_OS_Ver_major="$(echo "${VERSION_ID:-0}" | cut -d. -f1)"
        ;;
    esac

    # deb architecture for repo (amd64/arm64)
    if command -v dpkg >/dev/null 2>&1; then
        SysInfo_DpkgArch="$(dpkg --print-architecture)"
    else
        case "${SysInfo_Arch}" in
        x86_64) SysInfo_DpkgArch="amd64" ;;
        aarch64 | arm64) SysInfo_DpkgArch="arm64" ;;
        *) SysInfo_DpkgArch="${SysInfo_Arch}" ;;
        esac
    fi
}

Print_System_Info() {
    echo -e "
System Information
---------------------------------------------------
  Operating System: ${SysInfo_OS_Name_Full}
      Linux Kernel: ${SysInfo_Kernel}
      Architecture: ${SysInfo_Arch} (${SysInfo_DpkgArch})
    Virtualization: ${SysInfo_Virt}
---------------------------------------------------
"
}

Install_Requirements_Debian() {
    export DEBIAN_FRONTEND=noninteractive
    apt update -y

    if ! command -v gpg >/dev/null 2>&1; then
        apt install -y gnupg
    fi
    # apt-transport-https is built-in on modern apt, but keep safe
    if ! dpkg -s apt-transport-https >/dev/null 2>&1; then
        apt install -y apt-transport-https || true
    fi
    apt install -y ca-certificates
}

Validate_WARP_Supported_Deb_Ubuntu() {
    # Official docs: Ubuntu 22.04/24.04, Debian 12/13
    # We enforce these by default to avoid broken repo.
    if [[ "${SysInfo_OS_Name_lowercase}" == "ubuntu" ]]; then
        case "${SysInfo_OS_CodeName}" in
        jammy | noble) return 0 ;;
        *)
            die "Unsupported Ubuntu codename: ${SysInfo_OS_CodeName:-unknown}. Supported: jammy (22.04), noble (24.04)."
            ;;
        esac
    elif [[ "${SysInfo_OS_Name_lowercase}" == "debian" ]]; then
        case "${SysInfo_OS_CodeName}" in
        bookworm | trixie) return 0 ;;
        *)
            die "Unsupported Debian codename: ${SysInfo_OS_CodeName:-unknown}. Supported: bookworm (12), trixie (13)."
            ;;
        esac
    fi
}

Install_WARP_Client_Debian() {
    Validate_WARP_Supported_Deb_Ubuntu
    Install_Requirements_Debian

    log INFO "Adding Cloudflare WARP repository..."
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
      | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg

    cat >/etc/apt/sources.list.d/cloudflare-client.list <<EOF
deb [arch=${SysInfo_DpkgArch} signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ ${SysInfo_OS_CodeName} main
EOF

    apt update -y
    apt install -y cloudflare-warp
}

Install_WARP_Client_CentOS() {
    if [[ "${SysInfo_OS_Ver_major}" == "8" ]]; then
        rpm -ivh http://pkg.cloudflareclient.com/cloudflare-release-el8.rpm
        yum install -y cloudflare-warp
    else
        die "This operating system is not supported."
    fi
}

Check_WARP_Client() {
    WARP_Client_Status="$(systemctl is-active warp-svc 2>/dev/null || echo inactive)"
    WARP_Client_SelfStart="$(systemctl is-enabled warp-svc 2>/dev/null || echo disabled)"
}

Install_WARP_Client() {
    Print_System_Info
    log INFO "Installing Cloudflare WARP Client..."

    case "${SysInfo_DpkgArch}" in
    amd64 | arm64) ;;
    *)
        die "This CPU architecture is not supported by this installer: ${SysInfo_Arch} (${SysInfo_DpkgArch})"
        ;;
    esac

    case "${SysInfo_OS_Name_lowercase}" in
    debian | ubuntu)
        Install_WARP_Client_Debian
        ;;
    centos | rhel)
        Install_WARP_Client_CentOS
        ;;
    *)
        if [[ "${SysInfo_RelatedOS}" == *rhel* || "${SysInfo_RelatedOS}" == *fedora* ]]; then
            Install_WARP_Client_CentOS
        else
            die "This operating system is not supported."
        fi
        ;;
    esac

    Check_WARP_Client
    systemctl enable --now warp-svc >/dev/null 2>&1 || true
    Check_WARP_Client

    if [[ "${WARP_Client_Status}" == "active" ]]; then
        log INFO "Cloudflare WARP Client installed successfully!"
    else
        log ERROR "warp-svc failed to run!"
        journalctl -u warp-svc --no-pager || true
        exit 1
    fi
}

Uninstall_WARP_Client() {
    log INFO "Uninstalling Cloudflare WARP Client..."
    case "${SysInfo_OS_Name_lowercase}" in
    debian | ubuntu)
        apt purge -y cloudflare-warp || true
        rm -f /etc/apt/sources.list.d/cloudflare-client.list /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        ;;
    centos | rhel)
        yum remove -y cloudflare-warp || true
        ;;
    *)
        if [[ "${SysInfo_RelatedOS}" == *rhel* || "${SysInfo_RelatedOS}" == *fedora* ]]; then
            yum remove -y cloudflare-warp || true
        else
            die "This operating system is not supported."
        fi
        ;;
    esac
}

Restart_WARP_Client() {
    log INFO "Restarting Cloudflare WARP Client..."
    systemctl restart warp-svc || true
    Check_WARP_Client
    if [[ "${WARP_Client_Status}" == "active" ]]; then
        log INFO "Cloudflare WARP Client has been restarted."
    else
        log ERROR "Cloudflare WARP Client failed to run!"
        journalctl -u warp-svc --no-pager || true
        exit 1
    fi
}

Init_WARP_Client() {
    Check_WARP_Client
    if [[ "${WARP_Client_SelfStart}" != "enabled" || "${WARP_Client_Status}" != "active" ]]; then
        Install_WARP_Client
    fi

    # Old warp-cli compatibility (some versions)
    if warp-cli --accept-tos account 2>/dev/null | grep -qi "Missing"; then
        log INFO "Cloudflare WARP account registration in progress..."
        warp-cli --accept-tos register || true
    fi
}

Connect_WARP() {
    log INFO "Connecting to WARP..."
    warp-cli --accept-tos connect || true
    log INFO "Enable WARP Always-On..."
    warp-cli --accept-tos enable-always-on || true
}

Disconnect_WARP() {
    log INFO "Disable WARP Always-On..."
    warp-cli --accept-tos disable-always-on || true
    log INFO "Disconnect from WARP..."
    warp-cli --accept-tos disconnect || true
}

Set_WARP_Mode_Proxy() {
    log INFO "Setting WARP Proxy mode (legacy)..."
    warp-cli --accept-tos set-mode proxy || true
}

Enable_WARP_Client_Proxy() {
    Init_WARP_Client
    Set_WARP_Mode_Proxy
    Connect_WARP
    Print_WARP_Client_Status
}

Get_WARP_Proxy_Port() {
    WARP_Proxy_Port='40000'
}

Print_Delimiter() {
    printf '=%.0s' $(seq "$(tput cols 2>/dev/null || echo 80)")
    echo
}

Install_wgcf() {
    # Keep existing known-good installer (works for many VPS)
    curl -fsSL git.io/wgcf.sh | bash
}

Uninstall_wgcf() {
    rm -f /usr/local/bin/wgcf
}

Register_WARP_Account() {
    while [[ ! -f wgcf-account.toml ]]; do
        Install_wgcf
        log INFO "Cloudflare WARP account registration in progress (wgcf)..."
        yes | wgcf register || true
        sleep 2
    done
}

Generate_WGCF_Profile() {
    while [[ ! -f ${WGCF_Profile} ]]; do
        Register_WARP_Account
        log INFO "WARP WireGuard profile (${WGCF_Profile}) generation in progress..."
        wgcf generate || true
        sleep 1
    done
    Uninstall_wgcf
}

Backup_WGCF_Profile() {
    mkdir -p "${WGCF_ProfileDir}"
    mv -f wgcf* "${WGCF_ProfileDir}/" 2>/dev/null || true
}

Read_WGCF_Profile() {
    local profile="${WGCF_ProfilePath}"

    WireGuard_Interface_PrivateKey="$(grep -m1 '^PrivateKey' "$profile" | cut -d= -f2- | xargs)"
    WireGuard_Peer_PublicKey="$(grep -m1 '^PublicKey' "$profile" | cut -d= -f2- | xargs)"

    # Normalize Address: remove CRLF + all spaces, keep comma separation
    # Example: "172.16.0.2/32, 2606:.../128" -> "172.16.0.2/32,2606:.../128"
    local addr
    addr="$(grep -m1 '^Address' "$profile" | cut -d= -f2- | tr -d '\r' | sed 's/[[:space:]]//g')"

    WireGuard_Interface_Address="${addr}"
    WireGuard_Interface_Address_IPv4_CIDR="$(echo "$addr" | cut -d, -f1 | xargs)"
    WireGuard_Interface_Address_IPv6_CIDR="$(echo "$addr" | cut -d, -f2 | xargs)"

    WireGuard_Interface_Address_IPv4="$(echo "${WireGuard_Interface_Address_IPv4_CIDR}" | cut -d/ -f1 | xargs)"
    WireGuard_Interface_Address_IPv6="$(echo "${WireGuard_Interface_Address_IPv6_CIDR}" | cut -d/ -f1 | xargs)"
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

    if [[ -z "${WireGuard_Interface_PrivateKey:-}" || -z "${WireGuard_Peer_PublicKey:-}" || -z "${WireGuard_Interface_Address:-}" ]]; then
        die "Failed to read wgcf profile. Please check: ${WGCF_ProfilePath}"
    fi
}

Disable_WG_Systemd_IPv4Only() {
    rm -f "${WG_SYSTEMD_IPV4_ONLY_DROPIN}" "${WG_IPV4_ONLY_HELPER}"
    rmdir --ignore-fail-on-non-empty "${WG_SYSTEMD_DROPIN_DIR}" 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
}

Enable_WG_Systemd_IPv4Only() {
    mkdir -p "${WG_SYSTEMD_DROPIN_DIR}"

    cat > "${WG_IPV4_ONLY_HELPER}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
CONF="/etc/wireguard/wgcf.conf"
[[ -f "$CONF" ]] || exit 0

# Keep only the first (IPv4) part in Address=
if grep -qE '^Address[[:space:]]*=' "$CONF"; then
  sed -i -E 's/^(Address[[:space:]]*=[[:space:]]*[^,]+).*/\1/' "$CONF"
fi

# Keep only IPv4 in AllowedIPs=
if grep -qE '^AllowedIPs[[:space:]]*=' "$CONF"; then
  sed -i -E 's/^(AllowedIPs[[:space:]]*=[[:space:]]*[^,]+).*/\1/' "$CONF"
fi

# Force IPv4 DNS only
if grep -qE '^DNS[[:space:]]*=' "$CONF"; then
  sed -i -E 's/^DNS[[:space:]]*=.*/DNS = 1.1.1.1,1.0.0.1/' "$CONF"
fi
EOF
    chmod 0755 "${WG_IPV4_ONLY_HELPER}"

    cat > "${WG_SYSTEMD_IPV4_ONLY_DROPIN}" <<EOF
[Unit]
Wants=network-online.target
After=network-online.target

[Service]
ExecStartPre=${WG_IPV4_ONLY_HELPER}
EOF

    systemctl daemon-reload >/dev/null 2>&1 || true
}

Install_WireGuardTools_Debian() {
    case "${SysInfo_OS_Ver_major}" in
    10)
        if [[ -z $(grep -RhsE '^deb .* buster-backports .* main' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null) ]]; then
            echo "deb http://deb.debian.org/debian buster-backports main" > /etc/apt/sources.list.d/backports.list
        fi
        ;;
    *)
        if [[ "${SysInfo_OS_Ver_major}" -lt 10 ]]; then
            die "This Debian version is not supported."
        fi
        ;;
    esac

    apt update -y
    apt install -y iproute2 openresolv
    apt install -y wireguard-tools --no-install-recommends
}

Install_WireGuardTools_Ubuntu() {
    apt update -y
    apt install -y iproute2 openresolv
    apt install -y wireguard-tools --no-install-recommends
}

Install_WireGuardTools_CentOS() {
    yum install -y epel-release || yum install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${SysInfo_OS_Ver_major}.noarch.rpm"
    yum install -y iproute iptables wireguard-tools
}

Install_WireGuardTools_Fedora() {
    dnf install -y iproute iptables wireguard-tools
}

Install_WireGuardTools_Arch() {
    pacman -Sy --noconfirm iproute2 openresolv wireguard-tools
}

Install_WireGuardTools() {
    log INFO "Installing wireguard-tools..."
    case "${SysInfo_OS_Name_lowercase}" in
    debian) Install_WireGuardTools_Debian ;;
    ubuntu) Install_WireGuardTools_Ubuntu ;;
    centos | rhel) Install_WireGuardTools_CentOS ;;
    fedora) Install_WireGuardTools_Fedora ;;
    arch) Install_WireGuardTools_Arch ;;
    *)
        if [[ "${SysInfo_RelatedOS}" == *rhel* || "${SysInfo_RelatedOS}" == *fedora* ]]; then
            Install_WireGuardTools_CentOS
        else
            die "This operating system is not supported."
        fi
        ;;
    esac
}

Install_WireGuardGo() {
    case "${SysInfo_Virt}" in
    openvz | lxc*)
        curl -fsSL git.io/wireguard-go.sh | bash
        ;;
    *)
        if [[ "${SysInfo_Kernel_Ver_major}" -lt 5 || "${SysInfo_Kernel_Ver_minor}" -lt 6 ]]; then
            curl -fsSL git.io/wireguard-go.sh | bash
        fi
        ;;
    esac
}

Check_WireGuard() {
    WireGuard_Status="$(systemctl is-active wg-quick@${WireGuard_Interface} 2>/dev/null || echo inactive)"
    WireGuard_SelfStart="$(systemctl is-enabled wg-quick@${WireGuard_Interface} 2>/dev/null || echo disabled)"
}

Install_WireGuard() {
    Print_System_Info
    Check_WireGuard
    if [[ "${WireGuard_SelfStart}" != "enabled" && "${WireGuard_Status}" != "active" ]]; then
        Install_WireGuardTools
        Install_WireGuardGo
    else
        log INFO "WireGuard is installed (or already configured)."
    fi
}

Start_WireGuard() {
    Check_WARP_Client
    log INFO "Starting WireGuard..."
    if [[ "${WARP_Client_Status}" == "active" ]]; then
        systemctl stop warp-svc >/dev/null 2>&1 || true
        systemctl enable --now wg-quick@${WireGuard_Interface}
        systemctl start warp-svc >/dev/null 2>&1 || true
    else
        systemctl enable --now wg-quick@${WireGuard_Interface}
    fi

    Check_WireGuard
    if [[ "${WireGuard_Status}" == "active" ]]; then
        log INFO "WireGuard is running."
    else
        log ERROR "WireGuard failed to run!"
        journalctl -u wg-quick@${WireGuard_Interface} --no-pager || true
        exit 1
    fi
}

Restart_WireGuard() {
    Check_WARP_Client
    log INFO "Restarting WireGuard..."
    if [[ "${WARP_Client_Status}" == "active" ]]; then
        systemctl stop warp-svc >/dev/null 2>&1 || true
        systemctl restart wg-quick@${WireGuard_Interface} || true
        systemctl start warp-svc >/dev/null 2>&1 || true
    else
        systemctl restart wg-quick@${WireGuard_Interface} || true
    fi

    Check_WireGuard
    if [[ "${WireGuard_Status}" == "active" ]]; then
        log INFO "WireGuard has been restarted."
    else
        log ERROR "WireGuard failed to run!"
        journalctl -u wg-quick@${WireGuard_Interface} --no-pager || true
        exit 1
    fi
}

Enable_IPv6_Support() {
    # Do not force-remove ipv6 settings; just ensure it's not globally disabled if needed.
    # Also set default to 0 (common issue: default=1 causes "IPv6 is disabled on this device").
    if sysctl -a 2>/dev/null | grep -qE 'net\.ipv6\.conf\.(all|default)\.disable_ipv6\s*=\s*1'; then
        log WARN "IPv6 is disabled by sysctl. Enabling IPv6 (all/default) to avoid wg-quick IPv6 errors..."
        mkdir -p /etc/sysctl.d
        cat >/etc/sysctl.d/99-warp-ipv6.conf <<EOF
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
EOF
        sysctl -p /etc/sysctl.d/99-warp-ipv6.conf >/dev/null 2>&1 || true
    fi
}

Enable_WireGuard() {
    # For wg4 IPv4-only, we don't need IPv6; but enabling does not hurt.
    Enable_IPv6_Support
    Check_WireGuard
    if [[ "${WireGuard_SelfStart}" == "enabled" ]]; then
        Restart_WireGuard
    else
        Start_WireGuard
    fi
}

Stop_WireGuard() {
    Check_WARP_Client
    Check_WireGuard
    if [[ "${WireGuard_Status}" == "active" ]]; then
        log INFO "Stopping WireGuard..."
        if [[ "${WARP_Client_Status}" == "active" ]]; then
            systemctl stop warp-svc >/dev/null 2>&1 || true
            systemctl stop wg-quick@${WireGuard_Interface} || true
            systemctl start warp-svc >/dev/null 2>&1 || true
        else
            systemctl stop wg-quick@${WireGuard_Interface} || true
        fi
    else
        log INFO "WireGuard is stopped."
    fi
}

Disable_WireGuard() {
    Check_WARP_Client
    Check_WireGuard
    if [[ "${WireGuard_SelfStart}" == "enabled" || "${WireGuard_Status}" == "active" ]]; then
        log INFO "Disabling WireGuard..."
        if [[ "${WARP_Client_Status}" == "active" ]]; then
            systemctl stop warp-svc >/dev/null 2>&1 || true
            systemctl disable --now wg-quick@${WireGuard_Interface} || true
            systemctl start warp-svc >/dev/null 2>&1 || true
        else
            systemctl disable --now wg-quick@${WireGuard_Interface} || true
        fi
        Check_WireGuard
        if [[ "${WireGuard_SelfStart}" != "enabled" && "${WireGuard_Status}" != "active" ]]; then
            log INFO "WireGuard has been disabled."
        else
            log ERROR "Failed to disable WireGuard."
        fi
    else
        log INFO "WireGuard is disabled."
    fi
}

Print_WireGuard_Log() {
    journalctl -u wg-quick@${WireGuard_Interface} -f
}

Check_Network_Status_IPv4() {
    if curl -4 -fsS --connect-timeout 2 --max-time 3 "${CF_Trace_URL}" >/dev/null 2>&1; then
        IPv4Status='on'
    else
        IPv4Status='off'
    fi
}

Check_Network_Status_IPv6() {
    if curl -6 -fsS --connect-timeout 2 --max-time 3 "${CF_Trace_URL}" >/dev/null 2>&1; then
        IPv6Status='on'
    else
        IPv6Status='off'
    fi
}

Check_Network_Status() {
    Stop_WireGuard
    Check_Network_Status_IPv4
    Check_Network_Status_IPv6
}

Check_IPv4_addr() {
    IPv4_addr="$(
        ip route get "${TestIPv4_1}" 2>/dev/null | grep -oP 'src \K\S+' ||
        ip route get "${TestIPv4_2}" 2>/dev/null | grep -oP 'src \K\S+' || true
    )"
}

Check_IPv6_addr() {
    IPv6_addr="$(
        ip -6 route get "${TestIPv6_1}" 2>/dev/null | grep -oP 'src \K\S+' ||
        ip -6 route get "${TestIPv6_2}" 2>/dev/null | grep -oP 'src \K\S+' || true
    )"
}

Get_IP_addr() {
    Check_Network_Status
    if [[ "${IPv4Status}" == "on" ]]; then
        log INFO "Getting network IPv4 address..."
        Check_IPv4_addr
        [[ -n "${IPv4_addr:-}" ]] && log INFO "IPv4 Address: ${IPv4_addr}" || log WARN "IPv4 address not obtained."
    fi
    if [[ "${IPv6Status}" == "on" ]]; then
        log INFO "Getting network IPv6 address..."
        Check_IPv6_addr
        [[ -n "${IPv6_addr:-}" ]] && log INFO "IPv6 Address: ${IPv6_addr}" || log WARN "IPv6 address not obtained."
    fi
}

Get_WireGuard_Interface_MTU() {
    log INFO "Getting the best MTU value for WireGuard..."
    local MTU_Preset=1500
    local MTU_Increment=10
    local CMD_ping MTU_TestIP_1 MTU_TestIP_2

    if [[ "${IPv4Status}" == "off" && "${IPv6Status}" == "on" ]]; then
        CMD_ping='ping6'
        MTU_TestIP_1="${TestIPv6_1}"
        MTU_TestIP_2="${TestIPv6_2}"
    else
        CMD_ping='ping'
        MTU_TestIP_1="${TestIPv4_1}"
        MTU_TestIP_2="${TestIPv4_2}"
    fi

    while true; do
        if ${CMD_ping} -c1 -W1 -s$((MTU_Preset - 28)) -Mdo "${MTU_TestIP_1}" >/dev/null 2>&1 || \
           ${CMD_ping} -c1 -W1 -s$((MTU_Preset - 28)) -Mdo "${MTU_TestIP_2}" >/dev/null 2>&1; then
            MTU_Increment=1
            MTU_Preset=$((MTU_Preset + MTU_Increment))
        else
            MTU_Preset=$((MTU_Preset - MTU_Increment))
            if [[ "${MTU_Increment}" == "1" ]]; then
                break
            fi
        fi
        if [[ "${MTU_Preset}" -le 1360 ]]; then
            log WARN "MTU reached minimum threshold. Using 1360."
            MTU_Preset='1360'
            break
        fi
    done

    WireGuard_Interface_MTU=$((MTU_Preset - 80))
    log INFO "WireGuard MTU: ${WireGuard_Interface_MTU}"
}

Generate_WireGuardProfile_Interface() {
    Get_WireGuard_Interface_MTU
    log INFO "Generating WireGuard profile: ${WireGuard_ConfPath}"
    mkdir -p /etc/wireguard
    cat <<EOF >"${WireGuard_ConfPath}"
# Generated by P3TERX/warp.sh (custom fixed)
# Visit https://github.com/P3TERX/warp.sh for more information

[Interface]
PrivateKey = ${WireGuard_Interface_PrivateKey}
Address = ${WireGuard_Interface_Address}
DNS = ${WireGuard_Interface_DNS}
MTU = ${WireGuard_Interface_MTU}
EOF
}

Generate_WireGuardProfile_Interface_Rule_TableOff() {
    cat <<EOF >>"${WireGuard_ConfPath}"
Table = off
EOF
}

Generate_WireGuardProfile_Interface_Rule_IPv4_nonGlobal() {
    cat <<EOF >>"${WireGuard_ConfPath}"
PostUp = ip -4 route add default dev ${WireGuard_Interface} table ${WireGuard_Interface_Rule_table}
PostUp = ip -4 rule add from ${WireGuard_Interface_Address_IPv4} lookup ${WireGuard_Interface_Rule_table}
PostDown = ip -4 rule delete from ${WireGuard_Interface_Address_IPv4} lookup ${WireGuard_Interface_Rule_table}
PostUp = ip -4 rule add fwmark ${WireGuard_Interface_Rule_fwmark} lookup ${WireGuard_Interface_Rule_table}
PostDown = ip -4 rule delete fwmark ${WireGuard_Interface_Rule_fwmark} lookup ${WireGuard_Interface_Rule_table}
PostUp = ip -4 rule add table main suppress_prefixlength 0
PostDown = ip -4 rule delete table main suppress_prefixlength 0
EOF
}

Generate_WireGuardProfile_Interface_Rule_IPv6_nonGlobal() {
    cat <<EOF >>"${WireGuard_ConfPath}"
PostUp = ip -6 route add default dev ${WireGuard_Interface} table ${WireGuard_Interface_Rule_table}
PostUp = ip -6 rule add from ${WireGuard_Interface_Address_IPv6} lookup ${WireGuard_Interface_Rule_table}
PostDown = ip -6 rule delete from ${WireGuard_Interface_Address_IPv6} lookup ${WireGuard_Interface_Rule_table}
PostUp = ip -6 rule add fwmark ${WireGuard_Interface_Rule_fwmark} lookup ${WireGuard_Interface_Rule_table}
PostDown = ip -6 rule delete fwmark ${WireGuard_Interface_Rule_fwmark} lookup ${WireGuard_Interface_Rule_table}
PostUp = ip -6 rule add table main suppress_prefixlength 0
PostDown = ip -6 rule delete table main suppress_prefixlength 0
EOF
}

Generate_WireGuardProfile_Interface_Rule_DualStack_nonGlobal() {
    Generate_WireGuardProfile_Interface_Rule_TableOff
    Generate_WireGuardProfile_Interface_Rule_IPv4_nonGlobal
    Generate_WireGuardProfile_Interface_Rule_IPv6_nonGlobal
}

Generate_WireGuardProfile_Interface_Rule_IPv4_Global_srcIP() {
    cat <<EOF >>"${WireGuard_ConfPath}"
PostUp = ip -4 rule add from ${IPv4_addr} lookup main prio 18
PostDown = ip -4 rule delete from ${IPv4_addr} lookup main prio 18
EOF
}

Generate_WireGuardProfile_Interface_Rule_IPv6_Global_srcIP() {
    cat <<EOF >>"${WireGuard_ConfPath}"
PostUp = ip -6 rule add from ${IPv6_addr} lookup main prio 18
PostDown = ip -6 rule delete from ${IPv6_addr} lookup main prio 18
EOF
}

Generate_WireGuardProfile_Peer() {
    cat <<EOF >>"${WireGuard_ConfPath}"

[Peer]
PublicKey = ${WireGuard_Peer_PublicKey}
AllowedIPs = ${WireGuard_Peer_AllowedIPs}
Endpoint = ${WireGuard_Peer_Endpoint}
EOF
}

Check_WARP_Client_Status() {
    Check_WARP_Client
    if [[ "${WARP_Client_Status}" == "active" ]]; then
        WARP_Client_Status_en="${FontColor_Green}Running${FontColor_Suffix}"
    else
        WARP_Client_Status_en="${FontColor_Red}Stopped${FontColor_Suffix}"
    fi
    WARP_Client_Status_zh="${WARP_Client_Status_en}"
}

Check_WARP_Proxy_Status() {
    Check_WARP_Client
    if [[ "${WARP_Client_Status}" == "active" ]]; then
        Get_WARP_Proxy_Port
        WARP_Proxy_Status="$(curl -sx "socks5h://127.0.0.1:${WARP_Proxy_Port}" "${CF_Trace_URL}" --connect-timeout 2 2>/dev/null | grep warp | cut -d= -f2)"
    else
        WARP_Proxy_Status=""
    fi

    case "${WARP_Proxy_Status}" in
    on)
        WARP_Proxy_Status_en="${FontColor_Green}${WARP_Proxy_Port}${FontColor_Suffix}"
        ;;
    plus)
        WARP_Proxy_Status_en="${FontColor_Green}${WARP_Proxy_Port}(WARP+)${FontColor_Suffix}"
        ;;
    *)
        WARP_Proxy_Status_en="${FontColor_Red}Off${FontColor_Suffix}"
        ;;
    esac
    WARP_Proxy_Status_zh="${WARP_Proxy_Status_en}"
}

Check_WireGuard_Status() {
    Check_WireGuard
    if [[ "${WireGuard_Status}" == "active" ]]; then
        WireGuard_Status_en="${FontColor_Green}Running${FontColor_Suffix}"
    else
        WireGuard_Status_en="${FontColor_Red}Stopped${FontColor_Suffix}"
    fi
    WireGuard_Status_zh="${WireGuard_Status_en}"
}

Check_WARP_WireGuard_Status() {
    Check_Network_Status_IPv4
    if [[ "${IPv4Status}" == "on" ]]; then
        WARP_IPv4_Status="$(curl -s4 "${CF_Trace_URL}" --connect-timeout 2 2>/dev/null | grep warp | cut -d= -f2)"
    else
        WARP_IPv4_Status=""
    fi

    case "${WARP_IPv4_Status}" in
    on)   WARP_IPv4_Status_en="${FontColor_Green}WARP${FontColor_Suffix}" ;;
    plus) WARP_IPv4_Status_en="${FontColor_Green}WARP+${FontColor_Suffix}" ;;
    off|"") WARP_IPv4_Status_en="Normal" ;;
    *)    WARP_IPv4_Status_en="Normal" ;;
    esac
    WARP_IPv4_Status_zh="${WARP_IPv4_Status_en}"

    Check_Network_Status_IPv6
    if [[ "${IPv6Status}" == "on" ]]; then
        WARP_IPv6_Status="$(curl -s6 "${CF_Trace_URL}" --connect-timeout 2 2>/dev/null | grep warp | cut -d= -f2)"
    else
        WARP_IPv6_Status=""
    fi

    case "${WARP_IPv6_Status}" in
    on)   WARP_IPv6_Status_en="${FontColor_Green}WARP${FontColor_Suffix}" ;;
    plus) WARP_IPv6_Status_en="${FontColor_Green}WARP+${FontColor_Suffix}" ;;
    off|"") WARP_IPv6_Status_en="Unconnected" ;;
    *)    WARP_IPv6_Status_en="Unconnected" ;;
    esac
    WARP_IPv6_Status_zh="${WARP_IPv6_Status_en}"

    # Do NOT auto-disable WireGuard on “anomaly” (many VPS block IPv6 or curl6)
    if [[ "${IPv4Status}" == "off" && "${IPv6Status}" == "off" ]]; then
        log WARN "Network check failed (curl -4/-6). This VPS may block some traffic during setup. WireGuard remains enabled."
        return 0
    fi
}

Check_ALL_Status() {
    Check_WARP_Client_Status
    Check_WARP_Proxy_Status
    Check_WireGuard_Status
    Check_WARP_WireGuard_Status
}

Print_WARP_Client_Status() {
    log INFO "Status check in progress..."
    sleep 1
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
    cat "${WireGuard_ConfPath}" || true
    Print_Delimiter
}

Check_WireGuard_Peer_Endpoint() {
    if ping -c1 -W1 "${WireGuard_Peer_Endpoint_IP4}" >/dev/null 2>&1; then
        WireGuard_Peer_Endpoint="${WireGuard_Peer_Endpoint_IPv4}"
    elif ping6 -c1 -W1 "${WireGuard_Peer_Endpoint_IP6}" >/dev/null 2>&1; then
        WireGuard_Peer_Endpoint="${WireGuard_Peer_Endpoint_IPv6}"
    else
        WireGuard_Peer_Endpoint="${WireGuard_Peer_Endpoint_Domain}"
    fi
}

Set_WARP_IPv4() {
    Install_WireGuard
    Get_IP_addr
    Load_WGCF_Profile

    # IPv4-only mode:
    # - config writes IPv4-only Address/DNS/AllowedIPs
    # - systemd drop-in enforces IPv4-only at every start/reboot (no need to disable IPv6 globally)
    WireGuard_Interface_Address="${WireGuard_Interface_Address_IPv4_CIDR}"
    WireGuard_Interface_DNS="${WireGuard_Interface_DNS_IPv4}"
    WireGuard_Peer_AllowedIPs="${WireGuard_Peer_AllowedIPs_IPv4}"

    Check_WireGuard_Peer_Endpoint
    Generate_WireGuardProfile_Interface
    if [[ -n "${IPv4_addr:-}" ]]; then
        Generate_WireGuardProfile_Interface_Rule_IPv4_Global_srcIP
    fi
    Generate_WireGuardProfile_Peer
    View_WireGuard_Profile

    Enable_WG_Systemd_IPv4Only
    Enable_WireGuard
    Print_WARP_WireGuard_Status
}

Set_WARP_IPv6() {
    Install_WireGuard
    Get_IP_addr
    Load_WGCF_Profile

    Disable_WG_Systemd_IPv4Only
    if [[ "${IPv4Status}" == "off" && "${IPv6Status}" == "on" ]]; then
        WireGuard_Interface_DNS="${WireGuard_Interface_DNS_64}"
    else
        WireGuard_Interface_DNS="${WireGuard_Interface_DNS_46}"
    fi

    WireGuard_Interface_Address="${WireGuard_Interface_Address_IPv6_CIDR}"
    WireGuard_Peer_AllowedIPs="${WireGuard_Peer_AllowedIPs_IPv6}"

    Check_WireGuard_Peer_Endpoint
    Generate_WireGuardProfile_Interface
    if [[ -n "${IPv6_addr:-}" ]]; then
        Generate_WireGuardProfile_Interface_Rule_IPv6_Global_srcIP
    fi
    Generate_WireGuardProfile_Peer
    View_WireGuard_Profile
    Enable_WireGuard
    Print_WARP_WireGuard_Status
}

Set_WARP_DualStack() {
    Install_WireGuard
    Get_IP_addr
    Load_WGCF_Profile

    Disable_WG_Systemd_IPv4Only
    WireGuard_Interface_Address="${WireGuard_Interface_Address}"
    WireGuard_Interface_DNS="${WireGuard_Interface_DNS_46}"
    WireGuard_Peer_AllowedIPs="${WireGuard_Peer_AllowedIPs_DualStack}"

    Check_WireGuard_Peer_Endpoint
    Generate_WireGuardProfile_Interface
    if [[ -n "${IPv4_addr:-}" ]]; then
        Generate_WireGuardProfile_Interface_Rule_IPv4_Global_srcIP
    fi
    if [[ -n "${IPv6_addr:-}" ]]; then
        Generate_WireGuardProfile_Interface_Rule_IPv6_Global_srcIP
    fi
    Generate_WireGuardProfile_Peer
    View_WireGuard_Profile
    Enable_WireGuard
    Print_WARP_WireGuard_Status
}

Set_WARP_DualStack_nonGlobal() {
    Install_WireGuard
    Get_IP_addr
    Load_WGCF_Profile

    Disable_WG_Systemd_IPv4Only
    WireGuard_Interface_Address="${WireGuard_Interface_Address}"
    WireGuard_Interface_DNS="${WireGuard_Interface_DNS_46}"
    WireGuard_Peer_AllowedIPs="${WireGuard_Peer_AllowedIPs_DualStack}"

    Check_WireGuard_Peer_Endpoint
    Generate_WireGuardProfile_Interface
    Generate_WireGuardProfile_Interface_Rule_DualStack_nonGlobal
    Generate_WireGuardProfile_Peer
    View_WireGuard_Profile
    Enable_WireGuard
    Print_WARP_WireGuard_Status
}

Menu_Title="${FontColor_Yellow_Bold}Cloudflare WARP Installer${FontColor_Suffix} ${FontColor_Red}[${shVersion}]${FontColor_Suffix}"

Menu_WARP_Client() {
    clear
    echo -e "
${Menu_Title}

 -------------------------
 WARP Client Status : ${WARP_Client_Status_zh}
 SOCKS5 Port        : ${WARP_Proxy_Status_zh}
 -------------------------

Manage WARP Official Client:

 ${FontColor_Green_Bold}0${FontColor_Suffix}. Back to main menu
 -
 ${FontColor_Green_Bold}1${FontColor_Suffix}. Enable SOCKS5 Proxy (legacy)
 ${FontColor_Green_Bold}2${FontColor_Suffix}. Disable SOCKS5 Proxy (legacy)
 ${FontColor_Green_Bold}3${FontColor_Suffix}. Restart WARP Client
 ${FontColor_Green_Bold}4${FontColor_Suffix}. Uninstall WARP Client
"
    read -r -p "Enter option: " MenuNumber
    echo
    case ${MenuNumber} in
    0) Start_Menu ;;
    1) Enable_WARP_Client_Proxy ;;
    2) Disconnect_WARP ;;
    3) Restart_WARP_Client ;;
    4) Uninstall_WARP_Client ;;
    *) log ERROR "Invalid input!"; sleep 1; Menu_WARP_Client ;;
    esac
}

Menu_WARP_WireGuard() {
    clear
    echo -e "
${Menu_Title}

 -------------------------
 WireGuard Status : ${WireGuard_Status_zh}
 IPv4 Network     : ${WARP_IPv4_Status_zh}
 IPv6 Network     : ${WARP_IPv6_Status_zh}
 -------------------------

Manage WARP WireGuard:

 ${FontColor_Green_Bold}0${FontColor_Suffix}. Back to main menu
 -
 ${FontColor_Green_Bold}1${FontColor_Suffix}. View WireGuard Logs
 ${FontColor_Green_Bold}2${FontColor_Suffix}. Restart WireGuard Service
 ${FontColor_Green_Bold}3${FontColor_Suffix}. Disable WireGuard
"
    read -r -p "Enter option: " MenuNumber
    echo
    case ${MenuNumber} in
    0) Start_Menu ;;
    1) Print_WireGuard_Log ;;
    2) Restart_WireGuard ;;
    3) Disable_WireGuard ;;
    *) log ERROR "Invalid input!"; sleep 1; Menu_WARP_WireGuard ;;
    esac
}

Start_Menu() {
    log INFO "Checking status..."
    Check_ALL_Status
    clear
    echo -e "
${Menu_Title}

 -------------------------
 WARP Client Status : ${WARP_Client_Status_zh}
 SOCKS5 Port        : ${WARP_Proxy_Status_zh}
 -------------------------
 WireGuard Status : ${WireGuard_Status_zh}
 IPv4 Network     : ${WARP_IPv4_Status_zh}
 IPv6 Network     : ${WARP_IPv6_Status_zh}
 -------------------------

 ${FontColor_Green_Bold}1${FontColor_Suffix}. Install Cloudflare WARP Official Client
 ${FontColor_Green_Bold}2${FontColor_Suffix}. Auto-configure WARP SOCKS5 Proxy (legacy)
 ${FontColor_Green_Bold}3${FontColor_Suffix}. Manage WARP Official Client
 -
 ${FontColor_Green_Bold}4${FontColor_Suffix}. Install WireGuard Components
 ${FontColor_Green_Bold}5${FontColor_Suffix}. Configure WARP WireGuard IPv4 (Global, IPv4-only)
 ${FontColor_Green_Bold}6${FontColor_Suffix}. Configure WARP WireGuard IPv6 (Global)
 ${FontColor_Green_Bold}7${FontColor_Suffix}. Configure WARP WireGuard Dual Stack (Global)
 ${FontColor_Green_Bold}8${FontColor_Suffix}. Manage WARP WireGuard
"
    read -r -p "Enter option: " MenuNumber
    echo
    case ${MenuNumber} in
    1) Install_WARP_Client ;;
    2) Enable_WARP_Client_Proxy ;;
    3) Menu_WARP_Client ;;
    4) Install_WireGuard ;;
    5) Set_WARP_IPv4 ;;
    6) Set_WARP_IPv6 ;;
    7) Set_WARP_DualStack ;;
    8) Menu_WARP_WireGuard ;;
    *) log ERROR "Invalid input!"; sleep 1; Start_Menu ;;
    esac
}

Print_Usage() {
    echo -e "
Cloudflare WARP Installer [${shVersion}]

USAGE:
    warp [SUBCOMMAND]

SUBCOMMANDS:
    install         Install Cloudflare WARP Official Linux Client
    uninstall       Uninstall Cloudflare WARP Official Linux Client
    restart         Restart Cloudflare WARP Official Linux Client
    proxy           Enable WARP Client Proxy Mode (legacy)
    unproxy         Disable WARP Client Proxy Mode (legacy)
    wg              Install WireGuard and related components
    wg4             Configure WARP IPv4 Global Network (WireGuard, IPv4-only + systemd enforcement)
    wg6             Configure WARP IPv6 Global Network (WireGuard)
    wgd             Configure WARP Dual Stack Global Network (WireGuard)
    wgx             Configure WARP Non-Global Network (WireGuard)
    rwg             Restart WARP WireGuard service
    dwg             Disable WARP WireGuard service
    status          Print status information
    version         Print version information
    help            Print this message
    menu            Interactive menu
"
}

cat <<-'EOM'

Cloudflare WARP Installer (custom fixed)
Copyright (C) P3TERX.COM | https://github.com/P3TERX/warp.sh

EOM

if [[ $# -ge 1 ]]; then
    Get_System_Info
    case "$1" in
    install)   Install_WARP_Client ;;
    uninstall) Uninstall_WARP_Client ;;
    restart)   Restart_WARP_Client ;;
    proxy|socks5|s5)   Enable_WARP_Client_Proxy ;;
    unproxy|unsocks5|uns5) Disconnect_WARP ;;
    wg)  Install_WireGuard ;;
    wg4|4) Set_WARP_IPv4 ;;
    wg6|6) Set_WARP_IPv6 ;;
    wgd|d) Set_WARP_DualStack ;;
    wgx|x) Set_WARP_DualStack_nonGlobal ;;
    rwg) Restart_WireGuard ;;
    dwg) Disable_WireGuard ;;
    status) Print_ALL_Status ;;
    help) Print_Usage ;;
    version) echo "${shVersion}" ;;
    menu) Start_Menu ;;
    *)
        log ERROR "Invalid parameters: $*"
        Print_Usage
        exit 1
        ;;
    esac
else
    Print_Usage
fi
