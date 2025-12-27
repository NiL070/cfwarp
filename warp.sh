#!/usr/bin/env bash
set -euo pipefail

# Cloudflare WARP Installer + WARP WireGuard (wgcf) manager
# CUSTOM FIXED (FULL):
# - Debian/Ubuntu Cloudflare repo fallback codename
# - WARP proxy (new + legacy warp-cli)
# - wgcf installer ikut repo asal: NevermoreSSH/script (bukan git.io)
# - wireguard-go ikut repo asal: NevermoreSSH/script
# - Robust wgcf register+generate (tak mati senyap bila wgcf exit code pelik)
# - Pastikan /etc/warp/wgcf-profile.conf & /etc/wireguard/wgcf.conf memang dibuat
# - IPv4-only systemd drop-in (ExecStartPre patch config untuk wg4)
#
shVersion='1.0.41_Final_CUSTOM_FIXED_MERGED_REPO'

FontColor_Red="\033[31m"
FontColor_Green="\033[32m"
FontColor_Yellow="\033[33m"
FontColor_Suffix="\033[0m"

log() {
  local LEVEL="$1"
  local MSG="$2"
  case "${LEVEL}" in
    INFO)  echo -e "[${FontColor_Green}${LEVEL}${FontColor_Suffix}] ${MSG}" ;;
    WARN)  echo -e "[${FontColor_Yellow}${LEVEL}${FontColor_Suffix}] ${MSG}" ;;
    ERROR) echo -e "[${FontColor_Red}${LEVEL}${FontColor_Suffix}] ${MSG}" ;;
    *)     echo -e "[${LEVEL}] ${MSG}" ;;
  esac
}

need_root() {
  if [[ "$(id -u)" != "0" ]]; then
    log ERROR "Please run as root."
    exit 1
  fi
}

need_linux() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    log ERROR "This operating system is not supported."
    exit 1
  fi
}

need_cmd() {
  local c="$1"
  if ! command -v "$c" >/dev/null 2>&1; then
    log ERROR "Required command not found: $c"
    exit 1
  fi
}

Ensure_DNS_Resolver() {
  # Fix broken /etc/resolv.conf symlink (common in minimal VPS)
  if [[ -L /etc/resolv.conf ]]; then
    local target
    target="$(readlink -f /etc/resolv.conf || true)"
    if [[ -z "${target}" || ! -f "${target}" ]]; then
      log WARN "/etc/resolv.conf is a broken symlink. Replacing with a static resolv.conf."
      rm -f /etc/resolv.conf
      cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
EOF
    fi
  elif [[ ! -f /etc/resolv.conf ]]; then
    log WARN "/etc/resolv.conf missing. Creating a static resolv.conf."
    cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
EOF
  fi
}

# -----------------------------
# Paths / constants
# -----------------------------
WGCF_Profile='wgcf-profile.conf'
WGCF_ProfileDir="/etc/warp"
WGCF_ProfilePath="${WGCF_ProfileDir}/${WGCF_Profile}"
WGCF_AccountPath="${WGCF_ProfileDir}/wgcf-account.toml"

WireGuard_Interface='wgcf'
WireGuard_ConfPath="/etc/wireguard/${WireGuard_Interface}.conf"

WG_SYSTEMD_DROPIN_DIR="/etc/systemd/system/wg-quick@${WireGuard_Interface}.service.d"
WG_SYSTEMD_IPV4_ONLY_DROPIN="${WG_SYSTEMD_DROPIN_DIR}/10-warp-ipv4-only.conf"
WG_IPV4_ONLY_HELPER="/usr/local/bin/warp-wgcf-ipv4-only"

# DNS defaults
WireGuard_Interface_DNS_IPv4='1.1.1.1,1.0.0.1'
WireGuard_Interface_DNS_IPv6='2606:4700:4700::1111,2606:4700:4700::1001'
WireGuard_Interface_DNS_46="${WireGuard_Interface_DNS_IPv4},${WireGuard_Interface_DNS_IPv6}"
WireGuard_Interface_DNS_64="${WireGuard_Interface_DNS_IPv6},${WireGuard_Interface_DNS_IPv4}"

WireGuard_Interface_Rule_table='51888'
WireGuard_Interface_Rule_fwmark='51888'

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

# -----------------------------
# System info
# -----------------------------
Get_System_Info() {
  # shellcheck disable=SC1091
  source /etc/os-release

  SysInfo_OS_Name_lowercase="${ID:-linux}"
  SysInfo_OS_Name_Full="${PRETTY_NAME:-Linux}"
  SysInfo_RelatedOS="${ID_LIKE:-}"
  SysInfo_Kernel="$(uname -r)"
  SysInfo_Kernel_Ver_major="$(uname -r | awk -F . '{print $1}')"
  SysInfo_Kernel_Ver_minor="$(uname -r | awk -F . '{print $2}')"
  SysInfo_Arch="$(uname -m)"
  SysInfo_Virt="$(command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt || echo unknown)"

  SysInfo_OS_CodeName="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
  if [[ -z "${SysInfo_OS_CodeName}" ]] && command -v lsb_release >/dev/null 2>&1; then
    SysInfo_OS_CodeName="$(lsb_release -cs 2>/dev/null || true)"
  fi
  SysInfo_OS_CodeName="${SysInfo_OS_CodeName:-unknown}"

  SysInfo_OS_Ver_major="$(echo "${VERSION_ID:-0}" | cut -d. -f1 | tr -dc '0-9')"
  SysInfo_OS_Ver_major="${SysInfo_OS_Ver_major:-0}"
}

Print_System_Info() {
  echo -e "
System Information
---------------------------------------------------
  Operating System: ${SysInfo_OS_Name_Full}
      Linux Kernel: ${SysInfo_Kernel}
      Architecture: ${SysInfo_Arch}
    Virtualization: ${SysInfo_Virt}
        Codename  : ${SysInfo_OS_CodeName}
---------------------------------------------------
"
}

# -----------------------------
# Cloudflare WARP client install (Debian/Ubuntu)
# -----------------------------
Install_Requirements_Debian() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg lsb-release apt-transport-https
}

_cloudflare_repo_try_codename() {
  local codename="$1"
  local arch
  arch="$(dpkg --print-architecture)"

  mkdir -p /usr/share/keyrings
  curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
    | gpg --dearmor --yes --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg

  cat > /etc/apt/sources.list.d/cloudflare-client.list <<EOF
deb [arch=${arch} signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ ${codename} main
EOF

  apt-get update -y >/dev/null 2>&1
}

Install_WARP_Client_DebianUbuntu() {
  Install_Requirements_Debian

  local codename="${SysInfo_OS_CodeName}"
  log INFO "Configuring Cloudflare repo codename: ${codename}"

  if ! _cloudflare_repo_try_codename "${codename}"; then
    log WARN "Repo for '${codename}' failed. Trying fallback codenames..."

    local fallbacks=()
    if [[ "${SysInfo_OS_Name_lowercase}" == "ubuntu" ]]; then
      fallbacks=(noble jammy focal bionic)
    else
      fallbacks=(trixie bookworm bullseye buster)
    fi

    local ok=0
    for fb in "${fallbacks[@]}"; do
      if _cloudflare_repo_try_codename "${fb}"; then
        log INFO "Using fallback codename: ${fb}"
        ok=1
        break
      fi
    done
    if [[ "${ok}" != "1" ]]; then
      log ERROR "Failed to configure Cloudflare repo for this OS/codename."
      exit 1
    fi
  fi

  apt-get install -y cloudflare-warp
}

Check_WARP_Client() {
  WARP_Client_Status="$(systemctl is-active warp-svc 2>/dev/null || true)"
  WARP_Client_SelfStart="$(systemctl is-enabled warp-svc 2>/dev/null || true)"
}

Install_WARP_Client() {
  Print_System_Info
  log INFO "Installing Cloudflare WARP Client..."

  if [[ "${SysInfo_Arch}" != "x86_64" && "${SysInfo_Arch}" != "amd64" ]]; then
    log ERROR "Unsupported CPU architecture for official cloudflare-warp package: ${SysInfo_Arch}"
    exit 1
  fi

  case "${SysInfo_OS_Name_lowercase}" in
    debian|ubuntu)
      Install_WARP_Client_DebianUbuntu
      ;;
    *)
      log ERROR "WARP client install supported for Debian/Ubuntu only."
      exit 1
      ;;
  esac

  systemctl enable --now warp-svc >/dev/null 2>&1 || true
  Check_WARP_Client

  if [[ "${WARP_Client_Status}" == "active" ]]; then
    log INFO "Cloudflare WARP Client installed and running."
  else
    log ERROR "warp-svc failed to run."
    journalctl -u warp-svc --no-pager | tail -n 120 || true
    exit 1
  fi
}

Uninstall_WARP_Client() {
  log INFO "Uninstalling Cloudflare WARP Client..."
  case "${SysInfo_OS_Name_lowercase}" in
    debian|ubuntu)
      apt-get purge -y cloudflare-warp || true
      rm -f /etc/apt/sources.list.d/cloudflare-client.list /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
      apt-get update -y || true
      ;;
    *)
      log ERROR "Unsupported OS for uninstall."
      exit 1
      ;;
  esac
}

Restart_WARP_Client() {
  log INFO "Restarting Cloudflare WARP Client..."
  systemctl restart warp-svc
  Check_WARP_Client
  if [[ "${WARP_Client_Status}" == "active" ]]; then
    log INFO "warp-svc restarted."
  else
    log ERROR "warp-svc failed after restart."
    journalctl -u warp-svc --no-pager | tail -n 120 || true
    exit 1
  fi
}

# -----------------------------
# warp-cli proxy helpers (legacy + new)
# -----------------------------
warp_cli_has_new_syntax() {
  warp-cli --help 2>/dev/null | grep -qE '^\s*mode\s' && warp-cli --help 2>/dev/null | grep -qE '^\s*proxy\s'
}

warp_proxy_enable() {
  log INFO "Setting up WARP Proxy Mode (SOCKS5:40000)..."
  if warp_cli_has_new_syntax; then
    warp-cli --accept-tos registration show >/dev/null 2>&1 || warp-cli --accept-tos registration new >/dev/null
    warp-cli --accept-tos mode proxy
    warp-cli --accept-tos proxy port 40000
    warp-cli --accept-tos connect
  else
    warp-cli --accept-tos set-mode proxy
    warp-cli --accept-tos connect
    warp-cli --accept-tos enable-always-on || true
  fi
}

warp_proxy_disable() {
  log INFO "Disabling WARP Proxy Mode..."
  if warp_cli_has_new_syntax; then
    warp-cli --accept-tos disconnect || true
    warp-cli --accept-tos mode warp || true
  else
    warp-cli --accept-tos disable-always-on || true
    warp-cli --accept-tos disconnect || true
  fi
}

Init_WARP_Client() {
  Check_WARP_Client
  if [[ "${WARP_Client_SelfStart}" != "enabled" || "${WARP_Client_Status}" != "active" ]]; then
    Install_WARP_Client
  fi
}

Enable_WARP_Client_Proxy() {
  Init_WARP_Client
  warp_proxy_enable
  Print_WARP_Client_Status
}

Disconnect_WARP() {
  Init_WARP_Client
  warp_proxy_disable
  Print_WARP_Client_Status
}

Get_WARP_Proxy_Port() { WARP_Proxy_Port='40000'; }

# -----------------------------
# wgcf install + profile (MERGED REPO + FIXED)
# -----------------------------
Install_wgcf() {
  # ikut repo/script asal yang kau bagi (NevermoreSSH)
  log INFO "Installing wgcf via NevermoreSSH installer..."
  curl -fsSL https://raw.githubusercontent.com/NevermoreSSH/script/master/wgcf.sh | bash
}

Uninstall_wgcf() {
  # installer biasanya letak di /usr/local/bin/wgcf
  rm -f /usr/local/bin/wgcf /usr/bin/wgcf /usr/sbin/wgcf 2>/dev/null || true
}

Generate_WGCF_Profile() {
  mkdir -p "${WGCF_ProfileDir}"
  local tmp
  tmp="$(mktemp -d)"

  # Jalankan dalam subshell supaya kalau fail, kita boleh print error jelas
  (
    set -euo pipefail
    cd "${tmp}"

    Install_wgcf

    log INFO "Cloudflare WARP account registration (wgcf)..."

    # wgcf kadang return rc != 0 walaupun 'nampak' berjaya, jadi jangan mati senyap
    set +e
    yes | wgcf register
    rc=$?
    set -e

    if [[ ! -f "wgcf-account.toml" ]]; then
      log ERROR "wgcf register FAILED (rc=${rc}). Cuba run semula untuk output penuh."
      yes | wgcf register || true
      ls -la || true
      exit 1
    fi

    log INFO "Generating wgcf profile..."

    set +e
    wgcf generate
    rc=$?
    set -e

    if [[ ! -f "wgcf-profile.conf" ]]; then
      log ERROR "wgcf generate FAILED (rc=${rc}). Output penuh dah dipaparkan."
      ls -la || true
      exit 1
    fi

    install -m 0600 "wgcf-profile.conf" "${WGCF_ProfilePath}"
    install -m 0600 "wgcf-account.toml" "${WGCF_AccountPath}" || true
  )

  rm -rf "${tmp}"
  Uninstall_wgcf || true

  log INFO "Saved: ${WGCF_ProfilePath}"
}

Read_WGCF_Profile() {
  local profile="${WGCF_ProfilePath}"
  [[ -f "${profile}" ]] || { log ERROR "Missing profile: ${profile}"; exit 1; }

  WireGuard_Interface_PrivateKey="$(grep -m1 '^PrivateKey' "${profile}" | cut -d= -f2- | tr -d '\r' | xargs)"
  WireGuard_Peer_PublicKey="$(grep -m1 '^PublicKey' "${profile}" | cut -d= -f2- | tr -d '\r' | xargs)"

  local addr_raw addr
  addr_raw="$(grep -m1 '^Address' "${profile}" | cut -d= -f2- | tr -d '\r')"
  addr="$(echo "${addr_raw}" | sed -E 's/[[:space:]]+//g')"

  WireGuard_Interface_Address="${addr}"

  WireGuard_Interface_Address_IPv4_CIDR=""
  WireGuard_Interface_Address_IPv6_CIDR=""
  IFS=',' read -r WireGuard_Interface_Address_IPv4_CIDR WireGuard_Interface_Address_IPv6_CIDR <<< "${addr}"

  WireGuard_Interface_Address_IPv4="$(echo "${WireGuard_Interface_Address_IPv4_CIDR}" | cut -d/ -f1)"
  WireGuard_Interface_Address_IPv6="$(echo "${WireGuard_Interface_Address_IPv6_CIDR}" | cut -d/ -f1)"

  if [[ -z "${WireGuard_Interface_PrivateKey}" || -z "${WireGuard_Peer_PublicKey}" || -z "${WireGuard_Interface_Address_IPv4_CIDR}" ]]; then
    log ERROR "Failed to parse wgcf profile (PrivateKey/PublicKey/Address)."
    log ERROR "Profile content:"
    sed -n '1,160p' "${profile}" || true
    exit 1
  fi
}

Load_WGCF_Profile() {
  if [[ ! -f "${WGCF_ProfilePath}" ]]; then
    Generate_WGCF_Profile
  fi
  Read_WGCF_Profile
}

# -----------------------------
# WireGuard install / control
# -----------------------------
Install_WireGuardTools_DebianUbuntu() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y iproute2 openresolv wireguard-tools
}

Install_WireGuardGo() {
  # ikut repo/script asal (NevermoreSSH)
  case "${SysInfo_Virt}" in
    openvz|lxc*)
      curl -fsSL https://raw.githubusercontent.com/NevermoreSSH/script/master/wireguard-go.sh | bash
      ;;
    *)
      # kernel lama -> try wireguard-go
      if [[ "${SysInfo_Kernel_Ver_major}" -lt 5 || "${SysInfo_Kernel_Ver_minor}" -lt 6 ]]; then
        curl -fsSL https://raw.githubusercontent.com/NevermoreSSH/script/master/wireguard-go.sh | bash
      fi
      ;;
  esac
}

Check_WireGuard() {
  WireGuard_Status="$(systemctl is-active wg-quick@${WireGuard_Interface} 2>/dev/null || true)"
  WireGuard_SelfStart="$(systemctl is-enabled wg-quick@${WireGuard_Interface} 2>/dev/null || true)"
}

Install_WireGuard() {
  Print_System_Info
  if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
    log INFO "wireguard-tools already installed."
    return 0
  fi

  log INFO "Installing wireguard-tools..."
  case "${SysInfo_OS_Name_lowercase}" in
    debian|ubuntu) Install_WireGuardTools_DebianUbuntu ;;
    *) log ERROR "WireGuard install supported for Debian/Ubuntu only."; exit 1 ;;
  esac

  Install_WireGuardGo || true
}

Disable_WG_Systemd_IPv4Only() {
  rm -f "${WG_SYSTEMD_IPV4_ONLY_DROPIN}" "${WG_IPV4_ONLY_HELPER}" || true
  rmdir --ignore-fail-on-non-empty "${WG_SYSTEMD_DROPIN_DIR}" 2>/dev/null || true
  systemctl daemon-reload >/dev/null 2>&1 || true
}

Enable_WG_Systemd_IPv4Only() {
  mkdir -p "${WG_SYSTEMD_DROPIN_DIR}"

  cat > "${WG_IPV4_ONLY_HELPER}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/wireguard/wgcf.conf"
PROFILE="/etc/warp/wgcf-profile.conf"
[[ -f "$CONF" ]] || exit 0
[[ -f "$PROFILE" ]] || exit 0

addr_raw="$(grep -m1 '^Address' "$PROFILE" | cut -d= -f2- | tr -d '\r' | sed -E 's/[[:space:]]+//g')"
addr4="$(echo "$addr_raw" | cut -d, -f1)"

dns="1.1.1.1,1.0.0.1"
allowed="0.0.0.0/0"

tmp="$(mktemp)"
awk -v addr="$addr4" -v dns="$dns" -v allowed="$allowed" '
  BEGIN{iniface=0}
  /^\[Interface\]/{iniface=1; print; next}
  /^\[/{iniface=0; print; next}

  {
    if (iniface && $0 ~ /^Address[[:space:]]*=/) { print "Address = " addr; next }
    if (iniface && $0 ~ /^DNS[[:space:]]*=/)     { print "DNS = " dns; next }
    if ($0 ~ /^AllowedIPs[[:space:]]*=/)         { print "AllowedIPs = " allowed; next }
    print
  }
' "$CONF" > "$tmp"
cat "$tmp" > "$CONF"
rm -f "$tmp"
EOF
  chmod 0755 "${WG_IPV4_ONLY_HELPER}"

  cat > "${WG_SYSTEMD_IPV4_ONLY_DROPIN}" <<EOF
[Unit]
Wants=network-online.target
After=network-online.target

[Service]
ExecStartPre=${WG_IPV4_ONLY_HELPER}
EOF

  systemctl daemon-reload
}

Start_WireGuard() {
  Check_WARP_Client
  log INFO "Starting WireGuard (${WireGuard_Interface})..."

  if [[ ! -f "${WireGuard_ConfPath}" ]]; then
    log ERROR "Missing WireGuard config: ${WireGuard_ConfPath}"
    log ERROR "Run: warp2 wg4 / wg6 / wgd / wgx"
    exit 1
  fi

  if [[ "${WARP_Client_Status}" == "active" ]]; then
    systemctl stop warp-svc || true
    systemctl enable --now wg-quick@${WireGuard_Interface}
    systemctl start warp-svc || true
  else
    systemctl enable --now wg-quick@${WireGuard_Interface}
  fi

  Check_WireGuard
  if [[ "${WireGuard_Status}" == "active" ]]; then
    log INFO "WireGuard is running."
  else
    log ERROR "WireGuard failed to run!"
    journalctl -u wg-quick@${WireGuard_Interface} --no-pager | tail -n 160 || true
    exit 1
  fi
}

Restart_WireGuard() {
  Check_WARP_Client
  log INFO "Restarting WireGuard (${WireGuard_Interface})..."

  if [[ "${WARP_Client_Status}" == "active" ]]; then
    systemctl stop warp-svc || true
    systemctl restart wg-quick@${WireGuard_Interface}
    systemctl start warp-svc || true
  else
    systemctl restart wg-quick@${WireGuard_Interface}
  fi

  Check_WireGuard
  if [[ "${WireGuard_Status}" == "active" ]]; then
    log INFO "WireGuard restarted."
  else
    log ERROR "WireGuard restart failed!"
    journalctl -u wg-quick@${WireGuard_Interface} --no-pager | tail -n 160 || true
    exit 1
  fi
}

Stop_WireGuard() {
  Check_WARP_Client
  Check_WireGuard
  if [[ "${WireGuard_Status}" == "active" ]]; then
    log INFO "Stopping WireGuard..."
    if [[ "${WARP_Client_Status}" == "active" ]]; then
      systemctl stop warp-svc || true
      systemctl stop wg-quick@${WireGuard_Interface} || true
      systemctl start warp-svc || true
    else
      systemctl stop wg-quick@${WireGuard_Interface} || true
    fi
  else
    log INFO "WireGuard already stopped."
  fi
}

Disable_WireGuard() {
  Check_WARP_Client
  Check_WireGuard
  if [[ "${WireGuard_SelfStart}" == "enabled" || "${WireGuard_Status}" == "active" ]]; then
    log INFO "Disabling WireGuard..."
    if [[ "${WARP_Client_Status}" == "active" ]]; then
      systemctl stop warp-svc || true
      systemctl disable --now wg-quick@${WireGuard_Interface} || true
      systemctl start warp-svc || true
    else
      systemctl disable --now wg-quick@${WireGuard_Interface} || true
    fi
    Check_WireGuard
    log INFO "WireGuard disabled."
  else
    log INFO "WireGuard already disabled."
  fi
}

# -----------------------------
# Network checks
# -----------------------------
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

Check_IPv4_addr() {
  IPv4_addr="$(
    ip route get "${TestIPv4_1}" 2>/dev/null | grep -oP 'src \K\S+' ||
    ip route get "${TestIPv4_2}" 2>/dev/null | grep -oP 'src \K\S+' || true
  )"
}

Check_IPv6_addr() {
  IPv6_addr="$(
    ip route get "${TestIPv6_1}" 2>/dev/null | grep -oP 'src \K\S+' ||
    ip route get "${TestIPv6_2}" 2>/dev/null | grep -oP 'src \K\S+' || true
  )"
}

Get_IP_addr() {
  Check_Network_Status_IPv4
  Check_Network_Status_IPv6
  [[ "${IPv4Status}" == "on" ]] && Check_IPv4_addr || true
  [[ "${IPv6Status}" == "on" ]] && Check_IPv6_addr || true
}

Get_WireGuard_Interface_MTU() {
  WireGuard_Interface_MTU="1420"
}

# -----------------------------
# WireGuard config generation
# -----------------------------
Generate_WireGuardProfile_Interface() {
  Get_WireGuard_Interface_MTU
  log INFO "Generating WireGuard profile: ${WireGuard_ConfPath}"
  mkdir -p /etc/wireguard

  cat <<EOF >"${WireGuard_ConfPath}"
# Generated by custom warp script (${shVersion})

[Interface]
PrivateKey = ${WireGuard_Interface_PrivateKey}
Address = ${WireGuard_Interface_Address}
DNS = ${WireGuard_Interface_DNS}
MTU = ${WireGuard_Interface_MTU}
EOF
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

Generate_WireGuardProfile_Interface_Rule_DualStack_nonGlobal() {
  cat <<EOF >>"${WireGuard_ConfPath}"
Table = off
PostUp = ip -4 route add default dev ${WireGuard_Interface} table ${WireGuard_Interface_Rule_table}
PostUp = ip -4 rule add from ${WireGuard_Interface_Address_IPv4} lookup ${WireGuard_Interface_Rule_table}
PostDown = ip -4 rule delete from ${WireGuard_Interface_Address_IPv4} lookup ${WireGuard_Interface_Rule_table}
PostUp = ip -4 rule add fwmark ${WireGuard_Interface_Rule_fwmark} lookup ${WireGuard_Interface_Rule_table}
PostDown = ip -4 rule delete fwmark ${WireGuard_Interface_Rule_fwmark} lookup ${WireGuard_Interface_Rule_table}
PostUp = ip -4 rule add table main suppress_prefixlength 0
PostDown = ip -4 rule delete table main suppress_prefixlength 0

PostUp = ip -6 route add default dev ${WireGuard_Interface} table ${WireGuard_Interface_Rule_table}
PostUp = ip -6 rule add from ${WireGuard_Interface_Address_IPv6} lookup ${WireGuard_Interface_Rule_table}
PostDown = ip -6 rule delete from ${WireGuard_Interface_Address_IPv6} lookup ${WireGuard_Interface_Rule_table}
PostUp = ip -6 rule add fwmark ${WireGuard_Interface_Rule_fwmark} lookup ${WireGuard_Interface_Rule_table}
PostDown = ip -6 rule delete fwmark ${WireGuard_Interface_Rule_fwmark} lookup ${WireGuard_Interface_Rule_table}
PostUp = ip -6 rule add table main suppress_prefixlength 0
PostDown = ip -6 rule delete table main suppress_prefixlength 0
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

View_WireGuard_Profile() {
  echo "============================================================================================================================"
  sed -n '1,200p' "${WireGuard_ConfPath}" || true
  echo "============================================================================================================================"
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

# -----------------------------
# Status output
# -----------------------------
Check_WARP_Client_Status() {
  Check_WARP_Client
  if [[ "${WARP_Client_Status}" == "active" ]]; then
    WARP_Client_Status_en="Running"
  else
    WARP_Client_Status_en="Stopped"
  fi
}

Check_WARP_Proxy_Status() {
  Check_WARP_Client
  if [[ "${WARP_Client_Status}" == "active" ]]; then
    Get_WARP_Proxy_Port
    WARP_Proxy_Status="$(curl -sx "socks5h://127.0.0.1:${WARP_Proxy_Port}" "${CF_Trace_URL}" --connect-timeout 2 2>/dev/null | grep -m1 '^warp=' | cut -d= -f2 || true)"
  else
    WARP_Proxy_Status=""
  fi

  case "${WARP_Proxy_Status}" in
    on)   WARP_Proxy_Status_en="${WARP_Proxy_Port}" ;;
    plus) WARP_Proxy_Status_en="${WARP_Proxy_Port}(WARP+)" ;;
    *)    WARP_Proxy_Status_en="Off" ;;
  esac
}

Check_WireGuard_Status() {
  Check_WireGuard
  if [[ "${WireGuard_Status}" == "active" ]]; then
    WireGuard_Status_en="Running"
  else
    WireGuard_Status_en="Stopped"
  fi
}

Check_WARP_WireGuard_Status() {
  Check_Network_Status_IPv4
  Check_Network_Status_IPv6

  if [[ "${IPv4Status}" == "on" ]]; then
    WARP_IPv4_Status="$(curl -s4 "${CF_Trace_URL}" --connect-timeout 2 2>/dev/null | grep -m1 '^warp=' | cut -d= -f2 || true)"
  else
    WARP_IPv4_Status=""
  fi

  case "${WARP_IPv4_Status}" in
    on)   WARP_IPv4_Status_en="WARP" ;;
    plus) WARP_IPv4_Status_en="WARP+" ;;
    off)  WARP_IPv4_Status_en="Normal" ;;
    *)    WARP_IPv4_Status_en=$([[ "${IPv4Status}" == "on" ]] && echo "Normal" || echo "Unconnected") ;;
  esac

  if [[ "${IPv6Status}" == "on" ]]; then
    WARP_IPv6_Status="$(curl -s6 "${CF_Trace_URL}" --connect-timeout 2 2>/dev/null | grep -m1 '^warp=' | cut -d= -f2 || true)"
  else
    WARP_IPv6_Status=""
  fi

  case "${WARP_IPv6_Status}" in
    on)   WARP_IPv6_Status_en="WARP" ;;
    plus) WARP_IPv6_Status_en="WARP+" ;;
    off)  WARP_IPv6_Status_en="Normal" ;;
    *)    WARP_IPv6_Status_en=$([[ "${IPv6Status}" == "on" ]] && echo "Normal" || echo "Unconnected") ;;
  esac
}

Check_ALL_Status() {
  Check_WARP_Client_Status
  Check_WARP_Proxy_Status
  Check_WireGuard_Status
  Check_WARP_WireGuard_Status
}

Print_WARP_Client_Status() {
  Check_WARP_Client_Status
  Check_WARP_Proxy_Status
  echo -e "
 ----------------------------
 WARP Client    : ${WARP_Client_Status_en}
 SOCKS5 Port    : ${WARP_Proxy_Status_en}
 ----------------------------
"
}

Print_WARP_WireGuard_Status() {
  Check_WireGuard_Status
  Check_WARP_WireGuard_Status
  echo -e "
 ----------------------------
 WireGuard      : ${WireGuard_Status_en}
 IPv4 Network   : ${WARP_IPv4_Status_en}
 IPv6 Network   : ${WARP_IPv6_Status_en}
 ----------------------------
"
}

Print_ALL_Status() {
  Check_ALL_Status
  echo -e "
 ----------------------------
 WARP Client    : ${WARP_Client_Status_en}
 SOCKS5 Port    : ${WARP_Proxy_Status_en}
 ----------------------------
 WireGuard      : ${WireGuard_Status_en}
 IPv4 Network   : ${WARP_IPv4_Status_en}
 IPv6 Network   : ${WARP_IPv6_Status_en}
 ----------------------------
"
}

# -----------------------------
# Main actions
# -----------------------------
Set_WARP_IPv4() {
  Install_WireGuard
  Get_IP_addr
  Load_WGCF_Profile

  Disable_WG_Systemd_IPv4Only
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
  Start_WireGuard
  Print_WARP_WireGuard_Status
}

Set_WARP_IPv6() {
  Install_WireGuard
  Get_IP_addr
  Load_WGCF_Profile

  Disable_WG_Systemd_IPv4Only
  WireGuard_Interface_Address="${WireGuard_Interface_Address_IPv6_CIDR}"
  WireGuard_Interface_DNS="${WireGuard_Interface_DNS_46}"
  WireGuard_Peer_AllowedIPs="${WireGuard_Peer_AllowedIPs_IPv6}"

  Check_WireGuard_Peer_Endpoint
  Generate_WireGuardProfile_Interface
  if [[ -n "${IPv6_addr:-}" ]]; then
    Generate_WireGuardProfile_Interface_Rule_IPv6_Global_srcIP
  fi
  Generate_WireGuardProfile_Peer
  View_WireGuard_Profile

  Start_WireGuard
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

  Start_WireGuard
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

  Start_WireGuard
  Print_WARP_WireGuard_Status
}

Print_Usage() {
  echo -e "
Cloudflare WARP Installer [${shVersion}]

USAGE:
    warp2 [SUBCOMMAND]

SUBCOMMANDS:
    install         Install Cloudflare WARP Official Linux Client (Debian/Ubuntu)
    uninstall       Uninstall Cloudflare WARP Official Linux Client
    restart         Restart Cloudflare WARP Official Linux Client
    proxy           Enable WARP Client Proxy Mode (SOCKS5 port: 40000)
    unproxy         Disable WARP Client Proxy Mode
    wg              Install WireGuard components
    wg4             Configure WARP IPv4 (WireGuard)  [IPv4-only + systemd drop-in]
    wg6             Configure WARP IPv6 (WireGuard)
    wgd             Configure WARP Dual Stack (WireGuard)
    wgx             Configure WARP Non-Global (WireGuard)
    rwg             Restart WARP WireGuard service
    dwg             Disable WARP WireGuard service
    status          Print status information
    version         Print version
    help            Show this message
"
}

main() {
  need_linux
  need_root
  need_cmd curl
  Ensure_DNS_Resolver
  Get_System_Info

  if [[ $# -ge 1 ]]; then
    case "$1" in
      install)   Install_WARP_Client ;;
      uninstall) Uninstall_WARP_Client ;;
      restart)   Restart_WARP_Client ;;
      proxy|socks5|s5) Enable_WARP_Client_Proxy ;;
      unproxy|unsocks5|uns5) Disconnect_WARP ;;
      wg)        Install_WireGuard ;;
      wg4|4)     Set_WARP_IPv4 ;;
      wg6|6)     Set_WARP_IPv6 ;;
      wgd|d)     Set_WARP_DualStack ;;
      wgx|x)     Set_WARP_DualStack_nonGlobal ;;
      rwg)       Restart_WireGuard ;;
      dwg)       Disable_WireGuard ;;
      status)    Print_ALL_Status ;;
      version)   echo "${shVersion}" ;;
      help|-h|--help) Print_Usage ;;
      *)
        log ERROR "Invalid parameters: $*"
        Print_Usage
        exit 1
        ;;
    esac
  else
    Print_Usage
  fi
}

main "$@"
