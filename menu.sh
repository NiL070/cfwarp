#!/bin/bash
clear

y="\033[0;1;37m"
wh="\033[0m"
RB='\e[31;1m'
GB='\e[32;1m'
YB='\e[33;1m'
BB='\e[34;1m'
WB='\e[37;1m'
NC='\e[0m'

pause() {
  echo
  read -r -p "👉 Press ENTER to back menu..." _
}

# ===== SOCKS5 V2 (warp-cli 2024+ / 2025+) =====
enable_socks_40000_v2() {
  clear
  echo -e "${YB}[*] Enable SOCKS5 :40000 (V2 - NEW warp-cli)${NC}"
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
    warp-cli --accept-tos registration new >/dev/null 2>&1 || warp-cli --accept-tos register || {
      echo -e "${RB}[ERR] Registration failed.${NC}"
      pause
      return 1
    }
  else
    echo -e "${GB}[OK] Registration exists.${NC}"
  fi

  echo -e "${WB}[2/4] Set mode: proxy${NC}"
  warp-cli --accept-tos mode proxy >/dev/null 2>&1 || warp-cli --accept-tos set-mode proxy || {
    echo -e "${RB}[ERR] Failed to set proxy mode.${NC}"
    pause
    return 1
  }

  echo -e "${WB}[3/4] Set SOCKS5 port: 40000${NC}"
  warp-cli --accept-tos proxy port 40000 >/dev/null 2>&1 || true

  echo -e "${WB}[4/4] Connect...${NC}"
  warp-cli --accept-tos connect || {
    echo -e "${RB}[ERR] Connect failed.${NC}"
    pause
    return 1
  }

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
  echo -e "${YB}[*] Disable SOCKS5 :40000 (V2 - NEW warp-cli)${NC}"
  echo

  if ! command -v warp-cli >/dev/null 2>&1; then
    echo -e "${RB}[ERR] warp-cli not found.${NC}"
    pause
    return 1
  fi

  warp-cli --accept-tos disconnect >/dev/null 2>&1 || true
  warp-cli --accept-tos mode warp >/dev/null 2>&1 || warp-cli --accept-tos set-mode warp >/dev/null 2>&1 || true

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
  echo -e "${YB}[*] Debian 10 Fix: Install wg + wg-quick (wireguard-tools userspace)${NC}"
  echo

  if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
    echo -e "${GB}[OK] wg and wg-quick already installed:${NC}"
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

  echo -e "${WB}[3/4] Extract + build + install (wg + wg-quick)...${NC}"
  tar -xf wireguard-tools.tar.xz || { echo -e "${RB}[ERR] Extract failed.${NC}"; pause; return 1; }
  cd wireguard-tools-* || { echo -e "${RB}[ERR] Source folder not found.${NC}"; pause; return 1; }

  make -C src -j"$(nproc)" && make -C src install || {
    echo -e "${RB}[ERR] Build/install wg failed.${NC}"
    pause
    return 1
  }

  make -C contrib/wg-quick -j"$(nproc)" && make -C contrib/wg-quick install || {
    echo -e "${RB}[ERR] Build/install wg-quick failed.${NC}"
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

# Ambil status box dari output "bash warp2 status"
get_status_box() {
  local out box

  box=$' ----------------------------\n WARP Client    : Stopped\n SOCKS5 Port    : Off\n ----------------------------\n WireGuard      : Stopped\n IPv4 Network   : Normal\n IPv6 Network   : Unconnected\n ----------------------------\n'

  out="$(bash warp2 status 2>/dev/null || true)"

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

  if [[ -z "${box// /}" ]]; then
    box=$' ----------------------------\n WARP Client    : Stopped\n SOCKS5 Port    : Off\n ----------------------------\n WireGuard      : Stopped\n IPv4 Network   : Normal\n IPv6 Network   : Unconnected\n ----------------------------\n'
  fi

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

        if (l ~ /(stopped|off|unconnected|disconnected|not|fail)/)
          color=esc("31;1")

        if (l ~ /(running|warp\+|warp|plus|on)/)
          color=esc("32;1")

        if (l ~ /(normal)/)
          color=esc("33;1")

        printf "%s: %s%s%s\n", left, color, val, reset()
        next
      }
      print
    }
  '
}

while true; do
  clear

  IPVPS=$(curl -s ipv4.icanhazip.com || curl -s ipinfo.io/ip || curl -s ifconfig.me)
  uptime="$(uptime -p 2>/dev/null | cut -d ' ' -f2-)"
  [[ -z "$uptime" ]] && uptime="-"
  tram=$(free -m 2>/dev/null | awk 'NR==2{print $2}')
  uram=$(free -m 2>/dev/null | awk 'NR==2{print $3}')
  [[ -z "$tram" ]] && tram="0"
  [[ -z "$uram" ]] && uram="0"

  echo ""
  echo -e "$y                        MAIN MENU $wh"
  echo -e "$y                Simple menu WARP Cloudflare $wh"
  echo -e "${BB}--------------------------------------------------------${NC}"
  echo -e "                ${WB}  Server Information "
  echo -e "${BB}--------------------------------------------------------${NC}"
  echo -e "  ${YB}OS      :${NC} $(lsb_release -ds)"
  echo -e "  ${YB}KERNEL  :${NC} $(uname -r 2>/dev/null)"
  echo -e "  ${YB}UPTIME  :${NC} $uptime"
  echo -e "  ${YB}DATE    :${NC} $(date 2>/dev/null)"
  echo -e "  ${YB}RAM     :${NC} $uram MB / $tram MB"
  echo -e "  ${YB}IPVPS   :${NC} $IPVPS"
  echo -e "${BB}--------------------------------------------------------${NC}"

  echo
  print_status_box_colored
  echo

  echo -e "${BB}--------------------------------------------------------${NC}"
  echo -e "$YB 1$y.   Install Cloudflare WARP Official $wh"
  echo -e "$YB 2$y.   Uninstall Cloudflare WARP Official  $wh"
  echo -e "$YB 3$y.   Restart Cloudflare WARP Official  $wh"
  echo -e "$YB 4$y.   Enable WARP Client Proxy Mode (SOCKS5 port:40000) ${GB}[NEW]${NC} $wh"
  echo -e "$YB 5$y.   Disable WARP Client Proxy Mode ${GB}[NEW]${NC} $wh"
  echo -e "$YB 6$y.   Install WireGuard components $wh"
  echo -e "$YB 7$y.   Configuration WARP IPv4 $wh"
  echo -e "$YB 8$y.   Configuration WARP IPv6 $wh"
  echo -e "$YB 9$y.   Configuration WARP Dual Stack $wh"
  echo -e "$YB 10$y.  Configuration WARP Non-Global $wh"
  echo -e "$YB 11$y.  Restart WARP WireGuard service $wh"
  echo -e "$YB 12$y.  Disable WARP WireGuard service $wh"
  echo -e "$YB 13$y.  Status information $wh"
  echo -e "$YB 14$y.  Version information $wh"
  echo -e "$YB 15$y.  Help information $wh"
  echo -e "$YB 16$y.  Reboot $wh"
  echo -e "$YB 17$y.  FIX Debian10 (or old OS): Install wg + wg-quick $wh"
  echo -e "$YB 0$y.   Exit $wh"
  echo -e "${BB}--------------------------------------------------------${NC}"

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
