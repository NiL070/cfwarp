#!/usr/bin/env bash
set -euo pipefail

shVersion='1.0.44_Final_CUSTOM_PATCHED_WGGO'

FontColor_Red="\033[31m"
FontColor_Green="\033[32m"
FontColor_Yellow="\033[33m"
FontColor_Suffix="\033[0m"

log() {
  local LEVEL="$1"; shift
  local MSG="$*"
  case "${LEVEL}" in
    INFO)  echo -e "[${FontColor_Green}${LEVEL}${FontColor_Suffix}] ${MSG}" ;;
    WARN)  echo -e "[${FontColor_Yellow}${LEVEL}${FontColor_Suffix}] ${MSG}" ;;
    ERROR) echo -e "[${FontColor_Red}${LEVEL}${FontColor_Suffix}] ${MSG}" ;;
    *)     echo -e "[${LEVEL}] ${MSG}" ;;
  esac
}

need_root() { [[ "$(id -u)" == "0" ]] || { log ERROR "Please run as root."; exit 1; }; }
need_linux(){ [[ "$(uname -s)" == "Linux" ]] || { log ERROR "Linux only."; exit 1; }; }
need_cmd()  { command -v "$1" >/dev/null 2>&1 || { log ERROR "Required command not found: $1"; exit 1; }; }

WireGuard_Interface='wgcf'
WireGuard_ConfPath="/etc/wireguard/${WireGuard_Interface}.conf"
WGCF_ProfileDir="/etc/warp"
WGCF_ProfilePath="${WGCF_ProfileDir}/wgcf-profile.conf"
WGCF_AccountPath="${WGCF_ProfileDir}/wgcf-account.toml"

CF_Trace_URL='https://www.cloudflare.com/cdn-cgi/trace'
TestIPv4_1='1.0.0.1'
TestIPv4_2='9.9.9.9'
TestIPv6_1='2606:4700:4700::1001'
TestIPv6_2='2620:fe::fe'

DNS4='1.1.1.1,1.0.0.1'
DNS6='2606:4700:4700::1111,2606:4700:4700::1001'
DNS46="${DNS4},${DNS6}"

WG_PEER_PUBKEY_DEFAULT="bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
WG_ENDPOINT_V4="162.159.192.1:2408"
WG_ENDPOINT_V6="[2606:4700:d0::a29f:c001]:2408"
WG_ENDPOINT_DOMAIN="engage.cloudflareclient.com:2408"

WGCF_VERSION="${WGCF_VERSION:-2.2.29}"

Ensure_DNS_Resolver() {
  mkdir -p /etc >/dev/null 2>&1 || true
  if [[ -d /etc/resolv.conf ]]; then
    log WARN "/etc/resolv.conf is a directory. Fixing to regular file."
    rm -rf /etc/resolv.conf
  fi
  if [[ -L /etc/resolv.conf ]]; then
    local target=""
    target="$(readlink -f /etc/resolv.conf 2>/dev/null || true)"
    if [[ -z "${target}" || ! -f "${target}" ]]; then
      log WARN "/etc/resolv.conf is a broken symlink. Replacing with static resolv.conf."
      rm -f /etc/resolv.conf
      cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
EOF
    fi
  fi
  if [[ ! -f /etc/resolv.conf ]]; then
    log WARN "/etc/resolv.conf missing. Creating static resolv.conf."
    cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
EOF
  fi
}

Get_System_Info() {
  source /etc/os-release 2>/dev/null || true
  SysInfo_OS_Name_lowercase="${ID:-linux}"
  SysInfo_OS_Name_Full="${PRETTY_NAME:-Linux}"
  SysInfo_OS_CodeName="${VERSION_CODENAME:-${UBUNTU_CODENAME:-unknown}}"
  SysInfo_Kernel="$(uname -r)"
  SysInfo_Arch="$(uname -m)"
  SysInfo_Virt="$(command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt || echo unknown)"
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

IPv6_Is_Disabled() {
  local v1 v2
  v1="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)"
  v2="$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo 0)"
  [[ "$v1" == "1" || "$v2" == "1" ]]
}

Check_Network_Status_IPv4() {
  if curl -4 -fsS --connect-timeout 2 --max-time 3 "${CF_Trace_URL}" >/dev/null 2>&1; then IPv4Status='on'; else IPv4Status='off'; fi
}
Check_Network_Status_IPv6() {
  if IPv6_Is_Disabled; then IPv6Status='off'; return 0; fi
  if curl -6 -fsS --connect-timeout 2 --max-time 3 "${CF_Trace_URL}" >/dev/null 2>&1; then IPv6Status='on'; else IPv6Status='off'; fi
}

Check_IPv4_addr() {
  IPv4_addr="$(
    ip route get "${TestIPv4_1}" 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' ||
    ip route get "${TestIPv4_2}" 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true
  )"
}
Check_IPv6_addr() {
  IPv6_addr="$(
    ip -6 route get "${TestIPv6_1}" 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' ||
    ip -6 route get "${TestIPv6_2}" 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true
  )"
}
Get_IP_addr() {
  Check_Network_Status_IPv4
  Check_Network_Status_IPv6
  [[ "${IPv4Status}" == "on" ]] && Check_IPv4_addr || true
  [[ "${IPv6Status}" == "on" ]] && Check_IPv6_addr || true
}

_download_file() { curl -fL --retry 4 --retry-all-errors --connect-timeout 10 --max-time 180 -o "$2" "$1"; }

wgcf_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7) echo "armv7" ;;
    i386|i686) echo "386" ;;
    *) echo "" ;;
  esac
}

Install_wgcf() {
  if command -v wgcf >/dev/null 2>&1; then return 0; fi
  local a; a="$(wgcf_arch)"
  [[ -n "$a" ]] || { log ERROR "Unsupported arch for wgcf: $(uname -m)"; exit 1; }
  local url="https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VERSION}/wgcf_${WGCF_VERSION}_linux_${a}"
  log INFO "Installing wgcf (${WGCF_VERSION})..."
  _download_file "$url" "/usr/local/bin/wgcf"
  chmod +x /usr/local/bin/wgcf
  command -v wgcf >/dev/null 2>&1 || { log ERROR "wgcf install failed."; exit 1; }
}

Generate_WGCF_Profile() {
  mkdir -p "${WGCF_ProfileDir}"
  local tmp; tmp="$(mktemp -d)"
  pushd "${tmp}" >/dev/null

  Install_wgcf
  log INFO "Cloudflare WARP account registration (wgcf)..."
  yes | wgcf register >/dev/null 2>&1 || true

  log INFO "Generating wgcf profile..."
  wgcf generate >/dev/null 2>&1

  [[ -f "wgcf-profile.conf" ]] || { log ERROR "wgcf-profile.conf not generated."; popd >/dev/null; rm -rf "${tmp}"; exit 1; }

  install -m 0600 "wgcf-profile.conf" "${WGCF_ProfilePath}"
  [[ -f "wgcf-account.toml" ]] && install -m 0600 "wgcf-account.toml" "${WGCF_AccountPath}" || true

  popd >/dev/null
  rm -rf "${tmp}"
  log INFO "Saved: ${WGCF_ProfilePath}"
}

Load_WGCF_Profile() {
  [[ -f "${WGCF_ProfilePath}" ]] || Generate_WGCF_Profile

  WG_PRIVKEY="$(grep -m1 '^PrivateKey' "${WGCF_ProfilePath}" | cut -d= -f2- | tr -d '\r' | xargs || true)"
  WG_PEER_PUBKEY="$(grep -m1 '^PublicKey' "${WGCF_ProfilePath}" | cut -d= -f2- | tr -d '\r' | xargs || true)"
  [[ -n "${WG_PEER_PUBKEY}" ]] || WG_PEER_PUBKEY="${WG_PEER_PUBKEY_DEFAULT}"

  local addr_raw norm
  addr_raw="$(grep -m1 '^Address' "${WGCF_ProfilePath}" | cut -d= -f2- | tr -d '\r' || true)"
  norm="$(echo "${addr_raw}" | sed -E 's/[[:space:]]+//g')"

  WG_ADDR4_CIDR=""; WG_ADDR6_CIDR=""
  IFS=',' read -r -a parts <<< "${norm}"
  for p in "${parts[@]:-}"; do
    [[ -n "${p}" ]] || continue
    if echo "$p" | grep -q ":"; then WG_ADDR6_CIDR="$p"; else WG_ADDR4_CIDR="$p"; fi
  done

  [[ -n "${WG_PRIVKEY}" ]] || { log ERROR "Failed parse PrivateKey from wgcf-profile."; exit 1; }
}

Install_WireGuard() {
  Print_System_Info
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y iproute2 openresolv wireguard-tools >/dev/null 2>&1 || true
  mkdir -p /etc/wireguard "${WGCF_ProfileDir}"
  command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1 || {
    log ERROR "wireguard-tools install failed."
    exit 1
  }
  log INFO "wireguard-tools already installed."
}

Pick_WG_Endpoint() {
  if [[ "${IPv4Status:-off}" == "on" ]]; then WG_ENDPOINT="${WG_ENDPOINT_V4}"; return 0; fi
  if [[ "${IPv6Status:-off}" == "on" && ! $(IPv6_Is_Disabled && echo true || echo false) ]]; then WG_ENDPOINT="${WG_ENDPOINT_V6}"; return 0; fi
  WG_ENDPOINT="${WG_ENDPOINT_DOMAIN}"
}

Write_WG_Config() {
  local address="$1" dns="$2" allowed="$3"
  local postup="" postdown=""
  mkdir -p /etc/wireguard

  if [[ -n "${IPv4_addr:-}" ]]; then
    postup+="PostUp = ip -4 rule add from ${IPv4_addr} lookup main prio 18 2>/dev/null || true"$'\n'
    postdown+="PostDown = ip -4 rule delete from ${IPv4_addr} lookup main prio 18 2>/dev/null || true"$'\n'
  fi

  cat > "${WireGuard_ConfPath}" <<EOF
# Generated by custom warp script (${shVersion})

[Interface]
PrivateKey = ${WG_PRIVKEY}
Address = ${address}
DNS = ${dns}
MTU = 1420
${postup}${postdown}
[Peer]
PublicKey = ${WG_PEER_PUBKEY}
AllowedIPs = ${allowed}
Endpoint = ${WG_ENDPOINT}
EOF

  sed -i 's/[[:space:]]\+$//' "${WireGuard_ConfPath}"
}

View_WG_Config() {
  echo "============================================================================================================================"
  sed -n '1,200p' "${WireGuard_ConfPath}" || true
  echo "============================================================================================================================"
}

Check_WireGuard() {
  WireGuard_Status="$(systemctl is-active wg-quick@${WireGuard_Interface} 2>/dev/null || true)"
}

# -----------------------------
# NEW: WireGuard kernel check + wireguard-go fallback
# -----------------------------
WG_DROPIN_DIR="/etc/systemd/system/wg-quick@${WireGuard_Interface}.service.d"
WG_DROPIN_FILE="${WG_DROPIN_DIR}/10-userspace-wireguard-go.conf"

_kernel_wg_supported() {
  # try create temporary interface
  if ip link add wgtest type wireguard >/dev/null 2>&1; then
    ip link delete wgtest >/dev/null 2>&1 || true
    return 0
  fi
  return 1
}

_enable_wireguard_go_for_wgquick() {
  mkdir -p "${WG_DROPIN_DIR}"
  cat > "${WG_DROPIN_FILE}" <<EOF
[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
Environment=WG_SUDO=1
EOF
  systemctl daemon-reload >/dev/null 2>&1 || true
}

_disable_wireguard_go_dropin_if_any() {
  rm -f "${WG_DROPIN_FILE}" >/dev/null 2>&1 || true
  rmdir --ignore-fail-on-non-empty "${WG_DROPIN_DIR}" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
}

Ensure_WireGuard_Runtime() {
  # 1) try kernel module first
  modprobe wireguard >/dev/null 2>&1 || true

  if _kernel_wg_supported; then
    # kernel ok -> ensure we don't force userspace
    _disable_wireguard_go_dropin_if_any
    return 0
  fi

  # 2) kernel not supported -> userspace fallback
  log WARN "Kernel WireGuard not supported (ip link add type wireguard failed). Using wireguard-go fallback..."

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y wireguard-go >/dev/null 2>&1 || true

  if ! command -v wireguard-go >/dev/null 2>&1; then
    log ERROR "wireguard-go not found after install. VPS/kernel restriction is too hard."
    log ERROR "If this is container VPS: make sure TUN enabled + CAP_NET_ADMIN allowed by provider."
    exit 1
  fi

  _enable_wireguard_go_for_wgquick
}

Start_WireGuard() {
  [[ -f "${WireGuard_ConfPath}" ]] || { log ERROR "Missing config: ${WireGuard_ConfPath}"; exit 1; }

  # IMPORTANT: ensure runtime support before start
  Ensure_WireGuard_Runtime

  log INFO "Starting WireGuard (${WireGuard_Interface})..."
  systemctl enable --now "wg-quick@${WireGuard_Interface}" >/dev/null 2>&1 || true

  Check_WireGuard
  if [[ "${WireGuard_Status}" == "active" ]]; then
    log INFO "WireGuard is running."
  else
    log ERROR "WireGuard failed to run!"
    systemctl status "wg-quick@${WireGuard_Interface}" --no-pager || true
    journalctl -u "wg-quick@${WireGuard_Interface}" --no-pager -n 200 || true
    exit 1
  fi
}

Restart_WireGuard() {
  Ensure_WireGuard_Runtime
  log INFO "Restarting WireGuard (${WireGuard_Interface})..."
  systemctl restart "wg-quick@${WireGuard_Interface}" >/dev/null 2>&1 || true
  Check_WireGuard
  [[ "${WireGuard_Status}" == "active" ]] || { log ERROR "Restart failed."; journalctl -u "wg-quick@${WireGuard_Interface}" --no-pager -n 200 || true; exit 1; }
  log INFO "WireGuard restarted."
}

Disable_WireGuard() {
  log INFO "Disabling WireGuard..."
  systemctl disable --now "wg-quick@${WireGuard_Interface}" >/dev/null 2>&1 || true
  Check_WireGuard
  log INFO "WireGuard disabled."
}

Check_Status() {
  Check_Network_Status_IPv4
  Check_Network_Status_IPv6
  Check_WireGuard

  WG_State=$([[ "${WireGuard_Status}" == "active" ]] && echo "Running" || echo "Stopped")

  local v4warp=""
  if [[ "${IPv4Status}" == "on" ]]; then
    v4warp="$(curl -s4 "${CF_Trace_URL}" --connect-timeout 2 2>/dev/null | awk -F= '/^warp=/{print $2; exit}' || true)"
  fi

  case "${v4warp:-}" in
    on) IPv4_Net="WARP" ;;
    plus) IPv4_Net="WARP+" ;;
    *) IPv4_Net=$([[ "${IPv4Status}" == "on" ]] && echo "Normal" || echo "Unconnected") ;;
  esac

  if IPv6_Is_Disabled; then
    IPv6_Net="Unconnected"
  else
    local v6warp=""
    if [[ "${IPv6Status}" == "on" ]]; then
      v6warp="$(curl -s6 "${CF_Trace_URL}" --connect-timeout 2 2>/dev/null | awk -F= '/^warp=/{print $2; exit}' || true)"
    fi
    case "${v6warp:-}" in
      on) IPv6_Net="WARP" ;;
      plus) IPv6_Net="WARP+" ;;
      *) IPv6_Net=$([[ "${IPv6Status}" == "on" ]] && echo "Normal" || echo "Unconnected") ;;
    esac
  fi
}

Print_Status() {
  Check_Status
  echo -e "
 ----------------------------
 WireGuard      : ${WG_State}
 IPv4 Network   : ${IPv4_Net}
 IPv6 Network   : ${IPv6_Net}
 ----------------------------
"
}

Set_WARP_IPv4() {
  Install_WireGuard
  Ensure_DNS_Resolver
  Get_IP_addr
  Load_WGCF_Profile
  Pick_WG_Endpoint

  [[ -n "${WG_ADDR4_CIDR}" ]] || { log ERROR "wgcf profile has no IPv4 address. Can't do wg4."; exit 1; }

  log INFO "Generating WireGuard profile: ${WireGuard_ConfPath}"
  Write_WG_Config "${WG_ADDR4_CIDR}" "${DNS4}" "0.0.0.0/0"
  View_WG_Config
  Start_WireGuard
  Print_Status
}

Set_WARP_IPv6() {
  Install_WireGuard
  Ensure_DNS_Resolver
  Get_IP_addr
  Load_WGCF_Profile
  Pick_WG_Endpoint

  if IPv6_Is_Disabled; then
    log ERROR "IPv6 is disabled on this device (sysctl disable_ipv6=1)."
    log ERROR "Enable IPv6 first, then retry wg6."
    exit 1
  fi
  if [[ "${IPv6Status:-off}" != "on" ]]; then
    log ERROR "Host IPv6 connectivity not available. Use wg4 or wgd."
    exit 1
  fi
  [[ -n "${WG_ADDR6_CIDR}" ]] || { log ERROR "wgcf profile has no IPv6 address. Can't do wg6."; exit 1; }

  log INFO "Generating WireGuard profile: ${WireGuard_ConfPath}"
  Write_WG_Config "${WG_ADDR6_CIDR}" "${DNS46}" "::/0"
  View_WG_Config
  Start_WireGuard
  Print_Status
}

Set_WARP_DualStack() {
  Install_WireGuard
  Ensure_DNS_Resolver
  Get_IP_addr
  Load_WGCF_Profile
  Pick_WG_Endpoint

  if IPv6_Is_Disabled || [[ "${IPv6Status:-off}" != "on" || -z "${WG_ADDR6_CIDR:-}" ]]; then
    log WARN "Host IPv6 not available/disabled. Falling back to IPv4-only (wgd -> wg4)."
    [[ -n "${WG_ADDR4_CIDR}" ]] || { log ERROR "No IPv4 address in wgcf profile. Can't fallback."; exit 1; }
    Write_WG_Config "${WG_ADDR4_CIDR}" "${DNS4}" "0.0.0.0/0"
  else
    [[ -n "${WG_ADDR4_CIDR}" ]] || { log ERROR "No IPv4 address in wgcf profile. Can't dualstack."; exit 1; }
    Write_WG_Config "${WG_ADDR4_CIDR},${WG_ADDR6_CIDR}" "${DNS46}" "0.0.0.0/0,::/0"
  fi

  View_WG_Config
  Start_WireGuard
  Print_Status
}

Print_Usage() {
  cat <<EOF

Cloudflare WARP WireGuard Manager [${shVersion}]

USAGE:
  warp2 [SUBCOMMAND]

SUBCOMMANDS:
  wg        Install WireGuard components
  wg4       Configure WARP IPv4 (WireGuard)
  wg6       Configure WARP IPv6 (WireGuard) [guard]
  wgd       Configure WARP Dual Stack [auto fallback IPv4-only]
  rwg       Restart WireGuard service
  dwg       Disable WireGuard service
  status    Print status
  version   Print version
  help      Show help

EOF
}

main() {
  need_linux
  need_root
  need_cmd curl
  need_cmd ip

  Ensure_DNS_Resolver
  Get_System_Info

  [[ $# -ge 1 ]] || { Print_Usage; exit 0; }

  case "$1" in
    wg)        Install_WireGuard ;;
    wg4|4)     Set_WARP_IPv4 ;;
    wg6|6)     Set_WARP_IPv6 ;;
    wgd|d)     Set_WARP_DualStack ;;
    rwg)       Restart_WireGuard ;;
    dwg)       Disable_WireGuard ;;
    status)    Print_Status ;;
    version)   echo "${shVersion}" ;;
    help|-h|--help) Print_Usage ;;
    *)
      log ERROR "Invalid parameters: $*"
      Print_Usage
      exit 1
      ;;
  esac
}

main "$@"
