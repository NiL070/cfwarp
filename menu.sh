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
MAX_COLS=80   # kalau nak lebih kecil: 72
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

# ===== SOCKS5 V2 (warp-cli 2024+ / 2025+) =====
enable_socks_40000_v2() {
  clear
  line
  echo -e "${GB}${BOLD}Enable SOCKS5 :40000 (NEW warp-cli)${NC}"
  line
  echo

  if ! command -v warp-cli >/dev/null 2>&1; then
    echo -e "${RB}[ERR] warp-cli not found. Install Cloudflare WARP first.${NC}"
    pause
    return 1
  fi

  systemctl enable --now warp-svc >/dev/null 2>&1 || true

  echo -e "${WB}[1/4] Registration check...${NC}"
  if ! warp-cli --accept-tos registration show >/dev/null 2>&1; then
    echo -e "${WB}[+] Registering device...${NC}"
    warp-cli --accept-tos registration new || {
      echo -e "${RB}[ERR] Registration failed.${NC}"
      pause
      return 1
    }
  else
    echo -e "${GB}[OK] Registration exists.${NC}"
  fi

  echo -e "${WB}[2/4] Set mode: proxy${NC}"
  warp-cli --accept-tos mode proxy || { echo -e "${RB}[ERR] Failed to set proxy mode.${NC}"; pause; return 1; }

  echo -e "${WB}[3/4] Set SOCKS5 port: 40000${NC}"
  warp-cli --accept-tos proxy port 40000 || { echo -e "${RB}[ERR] Failed to set proxy port 40000.${NC}"; pause; return 1; }

  echo -e "${WB}[4/4] Connect...${NC}"
  warp-cli --accept-tos connect || { echo -e "${RB}[ERR] Connect failed.${NC}"; pause; return 1; }

  echo
  warp-cli --accept-tos status || true
  echo
  ss -lntp 2>/dev/null | grep -q ":40000" \
    && echo -e "${GB}[OK] SOCKS5 listening on 127.0.0.1:40000${NC}" \
    || echo -e "${RB}[WARN] SOCKS5 port not listening.${NC}"

  pause
}

disable_socks_40000_v2() {
  clear
  line
  echo -e "${YB}${BOLD}Disable SOCKS5 :40000 (NEW warp-cli)${NC}"
  line
  echo

  if ! command -v warp-cli >/dev/null 2>&1; then
    echo -e "${RB}[ERR] warp-cli not found.${NC}"
    pause
    return 1
  fi

  warp-cli --accept-tos disconnect >/dev/null 2>&1 || true
  warp-cli --accept-tos mode warp >/dev/null 2>&1 || true

  echo
  warp-cli --accept-tos status || true
  echo
  ss -lntp 2>/dev/null | grep -q ":40000" \
    && echo -e "${RB}[WARN] Port 40000 still listening (try restart warp-svc).${NC}" \
    || echo -e "${GB}[OK] SOCKS5 port 40000 disabled.${NC}"

  pause
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
  apt install -y curl ca-certificates tar xz-utils iproute2 openresolv

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

  curl -L -o wireguard-tools.tar.xz \
    "https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-${VER}.tar.xz" || {
      echo -e "${RB}[ERR] Download failed.${NC}"
      pause
      return 1
    }

  echo -e "${WB}[3/4] Extract + build + install...${NC}"
  tar -xf wireguard-tools.tar.xz || { echo -e "${RB}[ERR] Extract failed.${NC}"; pause; return 1; }
  cd wireguard-tools-* || { echo -e "${RB}[ERR] Source folder not found.${NC}"; pause; return 1; }

  make -C src -j"$(nproc)" && make -C src install || { echo -e "${RB}[ERR] Build/install wg failed.${NC}"; pause; return 1; }
  make -C contrib/wg-quick -j"$(nproc)" && make -C contrib/wg-quick install || { echo -e "${RB}[ERR] Build/install wg-quick failed.${NC}"; pause; return 1; }

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

# ===== Status Box (WARP2) =====
get_status_box() {
  local out box

  box=$' ----------------------------\n WARP Client    : Stopped\n SOCKS5 Port    : Off\n ----------------------------\n WireGuard      : Stopped\n IPv4 Network   : Normal\n IPv6 Network   : Unconnected\n ----------------------------\n'

  out="$(bash warp2 status 2>/dev/null || true)"

  if [[ -n "${out// /}" ]]; then
    box="$(printf "%s\n" "$out" \
      | sed -r 's/\x1B\[[0-9;]*[mK]//g' \
      | awk '
          BEGIN{p=0; dash=0}
          /----------------------------/{
            dash++
            if(dash==1){p=1}
          }
          p==1{print}
          (dash>=3){exit}
        ' \
    )"
  fi

  [[ -z "${box// /}" ]] && box=$' ----------------------------\n WARP Client    : Stopped\n SOCKS5 Port    : Off\n ----------------------------\n WireGuard      : Stopped\n IPv4 Network   : Normal\n IPv6 Network   : Unconnected\n ----------------------------\n'
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
  menu_item_tag "4" "Enable WARP Client Proxy Mode (SOCKS5 port:40000)" "NEW" "GREEN"
  menu_item_tag "5" "Disable WARP Client Proxy Mode" "NEW" "GREEN"
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
    1)  clear; bash warp2 install;   pause ;;
    2)  clear; bash warp2 uninstall; pause ;;
    3)  clear; bash warp2 restart;   pause ;;
    4)  enable_socks_40000_v2 ;;
    5)  disable_socks_40000_v2 ;;
    6)  clear; bash warp2 wg;        pause ;;
    7)  clear; bash warp2 wg4;       pause ;;
    8)  clear; bash warp2 wg6;       pause ;;
    9)  clear; bash warp2 wgd;       pause ;;
    10) clear; bash warp2 wgx;       pause ;;
    11) clear; bash warp2 rwg;       pause ;;
    12) clear; bash warp2 dwg;       pause ;;
    13) clear; bash warp2 status;    pause ;;
    14) clear; bash warp2 version;   pause ;;
    15) clear; bash warp2 help;      pause ;;
    16) clear; reboot ;;
    17) install_wg_tools_debian10 ;;
    0|q|Q|exit|EXIT) clear; exit 0 ;;
    *) clear; echo -e "${RB}Invalid option!${NC}"; pause ;;
  esac
done
