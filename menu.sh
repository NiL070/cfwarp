#!/bin/bash
clear

# ===== ANSI COLORS (SAFE / ASCII ONLY) =====
NC='\e[0m'
BOLD='\e[1m'
DIM='\e[2m'

RB='\e[31;1m'
GB='\e[32;1m'
YB='\e[33;1m'
BB='\e[34;1m'
MB='\e[35;1m'
CB='\e[36;1m'
WB='\e[37;1m'

pause() {
  echo
  read -r -p "Press ENTER to go back menu..." _
}

# ===== WIDTH CONTROL (NOT TOO WIDE) =====
MAX_COLS=80
MIN_COLS=60

term_cols="$(tput cols 2>/dev/null || echo $MAX_COLS)"
case "$term_cols" in
  ''|*[!0-9]*) term_cols=$MAX_COLS ;;
esac
(( term_cols < MIN_COLS )) && term_cols=$MIN_COLS
(( term_cols > MAX_COLS )) && term_cols=$MAX_COLS

repeat_chr() { local ch="$1" n="$2"; printf "%*s" "$n" "" | tr " " "$ch"; }
line()    { echo -e "${MB}$(repeat_chr "=" "$term_cols")${NC}"; }
subline() { echo -e "${BB}$(repeat_chr "-" "$term_cols")${NC}"; }

center_text() {
  local text="$1"
  local len=${#text}
  local pad=$(( (term_cols - len) / 2 ))
  (( pad < 0 )) && pad=0
  printf "%*s%s\n" "$pad" "" "$text"
}

menu_item() {
  local n="$1"; shift
  local t="$*"
  printf "  ${YB}%2s${NC} ${CB}>${NC} ${WB}%s${NC}\n" "$n" "$t"
}

menu_item_tag() {
  local n="$1"; shift
  local t="$1"; shift
  local tag="$1"; shift
  local color="$1"

  local tagc="${WB}"
  case "$color" in
    GREEN) tagc="${GB}" ;;
    YELLOW) tagc="${YB}" ;;
    RED) tagc="${RB}" ;;
    BLUE) tagc="${BB}" ;;
    PURPLE) tagc="${MB}" ;;
    CYAN) tagc="${CB}" ;;
  esac

  printf "  ${YB}%2s${NC} ${CB}>${NC} ${WB}%s ${tagc}${BOLD}[ %s ]${NC}\n" "$n" "$t" "$tag"
}

# ===== FIX: Install wg + wg-quick (Debian 10) =====
install_wg_tools_debian10() {
  clear
  line
  echo -e "${YB}${BOLD}Debian 10 Fix: Install wg + wg-quick${NC}"
  line
  echo

  if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
    echo -e "${GB}[OK] wg and wg-quick already installed.${NC}"
    echo " - wg      : $(command -v wg)"
    echo " - wg-quick: $(command -v wg-quick)"
    echo
    wg --version 2>/dev/null || true
    pause
    return 0
  fi

  echo -e "${WB}[1/4] Install dependencies...${NC}"
  apt update -y
  apt install -y curl ca-certificates tar xz-utils gzip iproute2 openresolv

  if ! command -v make >/dev/null 2>&1 || ! command -v gcc >/dev/null 2>&1; then
    echo -e "${WB}[+] Installing build tools (build-essential)...${NC}"
    apt install -y build-essential
  fi

  echo -e "${WB}[2/4] Download wireguard-tools source...${NC}"
  VER="v1.0.20210914"
  TMP="/tmp/wgtools"
  rm -rf "$TMP"
  mkdir -p "$TMP"
  cd "$TMP" || { echo -e "${RB}[ERR] Cannot cd to $TMP${NC}"; pause; return 1; }

  # try zx2c4 snapshot first
  ok=0
  curl -fL --retry 4 --retry-all-errors -o wireguard-tools.tar.xz \
    "https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-${VER}.tar.xz" >/dev/null 2>&1 || ok=1

  if [[ $ok -ne 0 ]] || [[ ! -s wireguard-tools.tar.xz ]] || [[ "$(stat -c%s wireguard-tools.tar.xz)" -lt 50000 ]]; then
    echo -e "${YB}[WARN] zx2c4 download failed/broken. Trying GitHub fallback...${NC}"
    curl -fL --retry 4 --retry-all-errors -o wireguard-tools.tar.gz \
      "https://github.com/WireGuard/wireguard-tools/archive/refs/tags/${VER}.tar.gz" || {
        echo -e "${RB}[ERR] Download failed (GitHub fallback).${NC}"
        pause
        return 1
      }
    echo -e "${WB}[3/4] Extract + build + install...${NC}"
    tar -xzf wireguard-tools.tar.gz || { echo -e "${RB}[ERR] Extract failed.${NC}"; pause; return 1; }
  else
    # validate xz then extract
    xz -t wireguard-tools.tar.xz >/dev/null 2>&1 || {
      echo -e "${RB}[ERR] Downloaded xz is invalid. Try again later.${NC}"
      pause
      return 1
    }
    echo -e "${WB}[3/4] Extract + build + install...${NC}"
    tar -xf wireguard-tools.tar.xz || { echo -e "${RB}[ERR] Extract failed.${NC}"; pause; return 1; }
  fi

  cd wireguard-tools-* || { echo -e "${RB}[ERR] Source folder not found.${NC}"; pause; return 1; }

  # IMPORTANT FIX:
  # In this version, wg-quick is installed by "make -C src install".
  # There's NO "contrib/wg-quick" directory -> remove that call.
  make -C src -j"$(nproc)" && make -C src install || {
    echo -e "${RB}[ERR] Build/install wg & wg-quick failed.${NC}"
    pause
    return 1
  }

  echo -e "${WB}[4/4] Verify...${NC}"
  if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
    echo -e "${GB}[OK] Installed successfully!${NC}"
    echo " - wg      : $(command -v wg)"
    echo " - wg-quick: $(command -v wg-quick)"
    echo
    wg --version 2>/dev/null || true
  else
    echo -e "${RB}[ERR] Install finished but commands not found.${NC}"
  fi

  pause
}

# ===== Status Box (warp2) =====
get_status_box() {
  local out box
  box=$' ----------------------------\n WireGuard      : Stopped\n IPv4 Network   : Normal\n IPv6 Network   : Unconnected\n ----------------------------\n'

  out="$(warp2 status 2>/dev/null || true)"
  if [[ -n "${out// /}" ]]; then
    box="$(printf "%s\n" "$out" | sed -r 's/\x1B\[[0-9;]*[mK]//g')"
  fi

  [[ -z "${box// /}" ]] && box=$' ----------------------------\n WireGuard      : Stopped\n IPv4 Network   : Normal\n IPv6 Network   : Unconnected\n ----------------------------\n'
  printf "%s\n" "$box"
}

print_status_box_colored() {
  local plain
  plain="$(get_status_box)"
  printf "%s\n" "$plain" | awk '
    function esc(c){ return sprintf("%c[%sm",27,c) }
    function reset(){ return sprintf("%c[0m",27) }
    function trim(s){ sub(/^[ \t]+/,"",s); sub(/[ \t]+$/,"",s); return s }
    /^[ \t-]*-+[ \t-]*$/ { print; next }
    /^[[:space:]]*$/ { print; next }
    {
      line=$0
      if (index(line,":")>0) {
        split(line,a,":")
        left=a[1]
        val=substr(line,length(left)+2)
        val=trim(val)
        l=tolower(val)
        color=esc("37;1")
        if (l ~ /(stopped|off|unconnected|disconnected|not|fail)/) color=esc("31;1")
        if (l ~ /(running|warp\+|warp|plus|on|connected)/)          color=esc("32;1")
        if (l ~ /(normal)/)                                         color=esc("33;1")
        printf "%s: %s%s%s\n", left, color, val, reset()
        next
      }
      print
    }
  '
}

# ===== MAIN LOOP =====
while true; do
  clear

  IPVPS=$(curl -s ipv4.icanhazip.com || curl -s ipinfo.io/ip || curl -s ifconfig.me)
  uptime="$(uptime -p 2>/dev/null | cut -d ' ' -f2-)"
  [[ -z "$uptime" ]] && uptime="-"
  tram=$(free -m 2>/dev/null | awk 'NR==2{print $2}')
  uram=$(free -m 2>/dev/null | awk 'NR==2{print $3}')
  [[ -z "$tram" ]] && tram="0"
  [[ -z "$uram" ]] && uram="0"

  OS_NAME="$(lsb_release -ds 2>/dev/null || echo "Unknown OS")"
  KERNEL="$(uname -r 2>/dev/null || echo "-")"
  NOW="$(date 2>/dev/null || echo "-")"

  line
  echo -e "${CB}${BOLD}$(center_text "WARP CLOUDFLARE CONTROL PANEL")${NC}"
  echo -e "${DIM}$(center_text "(Simple Menu - By NiLphreakz)")${NC}"
  line

  echo -e "${WB}${BOLD}Server Information${NC}"
  subline
  echo -e "  ${YB}OS     ${NC}: ${WB}${OS_NAME}${NC}"
  echo -e "  ${YB}KERNEL ${NC}: ${WB}${KERNEL}${NC}"
  echo -e "  ${YB}UPTIME ${NC}: ${WB}${uptime}${NC}"
  echo -e "  ${YB}DATE   ${NC}: ${WB}${NOW}${NC}"
  echo -e "  ${YB}RAM    ${NC}: ${WB}${uram} MB / ${tram} MB${NC}"
  echo -e "  ${YB}IPVPS  ${NC}: ${WB}${IPVPS}${NC}"
  line

  echo -e "${WB}${BOLD}Status${NC}"
  subline
  print_status_box_colored
  line

  echo -e "${WB}${BOLD}Menu Options${NC}"
  subline
  menu_item "1"  "Install Cloudflare WARP Official"
  menu_item "2"  "Uninstall Cloudflare WARP Official"
  menu_item "3"  "Restart Cloudflare WARP Official"
  menu_item "6"  "Install WireGuard components"
  menu_item "7"  "Configuration WARP IPv4"
  menu_item "8"  "Configuration WARP IPv6"
  menu_item "9"  "Configuration WARP Dual Stack"
  menu_item "10" "Configuration WARP Non-Global"
  menu_item "11" "Restart WARP WireGuard service"
  menu_item "12" "Disable WARP WireGuard service"
  menu_item "13" "Status information"
  menu_item "14" "Version information"
  menu_item "15" "Help information"
  menu_item "16" "Reboot"
  menu_item "17" "FIX Debian10 (or old OS): Install wg + wg-quick"
  echo -e "  ${YB} 0${NC} ${CB}>${NC} ${RB}${BOLD}Exit${NC}"
  line

  read -r -p "Select From Options [ 0 - 17 ] : " menu
  case "$menu" in
    1)  clear; warp2 install;   pause ;;
    2)  clear; warp2 uninstall; pause ;;
    3)  clear; warp2 restart;   pause ;;
    6)  clear; warp2 wg;        pause ;;
    7)  clear; warp2 wg4;       pause ;;
    8)  clear; warp2 wg6;       pause ;;
    9)  clear; warp2 wgd;       pause ;;
    10) clear; warp2 wgx;       pause ;;
    11) clear; warp2 rwg;       pause ;;
    12) clear; warp2 dwg;       pause ;;
    13) clear; warp2 status;    pause ;;
    14) clear; warp2 version;   pause ;;
    15) clear; warp2 help;      pause ;;
    16) clear; reboot ;;
    17) install_wg_tools_debian10 ;;
    0|q|Q|exit|EXIT) clear; exit 0 ;;
    *) clear; echo -e "${RB}Invalid option!${NC}"; pause ;;
  esac
done
