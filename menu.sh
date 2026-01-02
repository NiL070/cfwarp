#!/bin/bash
clear

# ============================================================
#  WARP MENU - FINAL (NO CACAT BOX + RAINBOW LINES)
#  - Max width 80 cols (auto cap)
#  - UTF-8 border if available, else ASCII fallback
#  - Safe truncate (never breaks ANSI)
#  - Live status: iface detect + mode + cache
# ============================================================

# ---------- Locale / UTF detect ----------
CHARMAP="$(locale charmap 2>/dev/null || echo "")"
if [[ "${CHARMAP}" == "UTF-8" || "${CHARMAP}" == "utf8" ]]; then
  USE_UTF=1
else
  USE_UTF=0
fi

# ---------- Colors ----------
RST="\e[0m"; BOLD="\e[1m"; DIM="\e[2m"
RED="\e[31;1m"; GRN="\e[32;1m"; YLW="\e[33;1m"; BLU="\e[34;1m"; MAG="\e[35;1m"; CYN="\e[36;1m"
WHT="\e[37;1m"

ACC1="$CYN"; ACC2="$MAG"; ACC3="$YLW"; ACC4="$GRN"; ACC5="$BLU"

# legacy compatibility
RB="$RED"; GB="$GRN"; YB="$YLW"; BB="$BLU"; WB="$WHT"; NC="$RST"

# ---------- Width cap ----------
MAX_W=80
term_cols() {
  local c
  c="$(tput cols 2>/dev/null || echo 80)"
  (( c > MAX_W )) && c=$MAX_W
  (( c < 60 )) && c=60
  echo "$c"
}

# ---------- Box characters ----------
if [[ $USE_UTF -eq 1 ]]; then
  TL="╔"; TR="╗"; BL="╚"; BR="╝"; H="═"; V="║"; ML="╠"; MR="╣"; MH="═"
  ELL="…"
else
  TL="+"; TR="+"; BL="+"; BR="+"; H="-"; V="|"; ML="+"; MR="+"; MH="-"
  ELL="..."
fi

# ---------- Rainbow border helpers ----------
RAINBOW=("$RED" "$YLW" "$GRN" "$CYN" "$BLU" "$MAG")
RB_N=${#RAINBOW[@]}
rb_hline() {
  # rb_hline LEN CHAR  (prints exactly LEN chars, each colored)
  local len="$1" ch="$2" i
  for ((i=0; i<len; i++)); do
    printf -- "%b%s%b" "${RAINBOW[$((i % RB_N))]}" "$ch" "$RST"
  done
}
rb_v() {
  # returns 1 colored vertical char (rotating)
  local c="${RAINBOW[$(( (RANDOM % 100000) % RB_N ))]}"
  printf -- "%b%s%b" "$c" "$V" "$RST"
}
rb_corner() {
  # colored corner symbol
  local sym="$1"
  local c="${RAINBOW[$(( (RANDOM % 100000) % RB_N ))]}"
  printf -- "%b%s%b" "$c" "$sym" "$RST"
}
rb_div() {
  # colored middle divider '|'
  local c="${RAINBOW[$(( (RANDOM % 100000) % RB_N ))]}"
  printf -- "%b|%b" "$c" "$RST"
}

# ---------- Utils ----------
strip_ansi() { sed -r 's/\x1B\[[0-9;]*[mK]//g'; }

truncate_plain() {
  # truncate_plain "TEXT" maxlen -> prints truncated
  local s="$1" max="$2"
  local len=${#s}
  if (( len <= max )); then
    printf -- "%s" "$s"
  else
    if (( max <= ${#ELL} )); then
      printf -- "%s" "${s:0:max}"
    else
      printf -- "%s%s" "${s:0:$((max-${#ELL}))}" "$ELL"
    fi
  fi
}

pause() { echo; read -r -p "Press ENTER to back menu..." _; }

badge() { # badge TEXT COLOR
  local t="$1" c="$2"
  printf -- "%b[%s]%b" "${c}${BOLD}" "$t" "${RST}"
}

status_badge() {
  local v="$1" lv
  lv="$(printf "%s" "$v" | tr 'A-Z' 'a-z')"
  if [[ "$lv" =~ (running|on|warp\+|warp|plus|listening) ]]; then
    badge "$v" "$GRN"
  elif [[ "$lv" =~ (stopped|off|fail|error|nov6|no) ]]; then
    badge "$v" "$RED"
  elif [[ "$lv" =~ (normal) ]]; then
    badge "$v" "$YLW"
  else
    badge "$v" "$WHT"
  fi
}

# ---------- Box drawing (FIXED WIDTH, NO CACAT) ----------
# Rule: every content row prints EXACT: V + inner chars + V

box_border_line() {
  # box_border_line CORNER_L FILL_CHAR CORNER_R
  local cl="$1" fill="$2" cr="$3"
  local w inner
  w="$(term_cols)"; inner=$((w-2))
  rb_corner "$cl"; rb_hline "$inner" "$fill"; rb_corner "$cr"
  printf -- "\n"
}

box_top() {
  local title="$1"
  local w inner plain len padL padR
  w="$(term_cols)"; inner=$((w-2))

  plain="$(printf "%b" "$title" | strip_ansi)"
  len=${#plain}
  if (( len > inner )); then
    title="$(truncate_plain "$plain" "$inner")"
    plain="$title"
    len=${#plain}
  fi

  padL=$(( (inner - len) / 2 ))
  padR=$(( inner - len - padL ))

  box_border_line "$TL" "$H" "$TR"

  # EXACT inner chars: padL + title + padR = inner
  printf -- "%s" "$(rb_v)"
  printf -- "%*s" "$padL" ""
  printf -- "%b%s%b" "${ACC1}${BOLD}" "$title" "$RST"
  printf -- "%*s" "$padR" ""
  printf -- "%s\n" "$(rb_v)"
}

box_mid()    { box_border_line "$ML" "$MH" "$MR"; }
box_bottom() { box_border_line "$BL" "$H"  "$BR"; }

box_line() {
  # 1 leading space included in width calc: " " + content
  local content="$1"
  local w inner plain len pad
  w="$(term_cols)"; inner=$((w-2))

  plain="$(printf "%b" "$content" | strip_ansi)"
  # inside = " " + plain
  if (( ${#plain} > inner-1 )); then
    plain="$(truncate_plain "$plain" "$((inner-1))")"
    content="$plain"  # drop ANSI if truncated (safe)
  fi

  len=$(( 1 + ${#plain} )) # 1 for leading space
  pad=$(( inner - len ))
  (( pad < 0 )) && pad=0

  printf -- "%s" "$(rb_v)"
  printf -- " %b" "$(printf "%b" "$content")"
  printf -- "%*s" "$pad" ""
  printf -- "%s\n" "$(rb_v)"
}

# ---------- Menu row 2 columns (EXACT width, NO CACAT) ----------
menu_row_2col() {
  # FINAL: odd-width safe + colored numbers (no sed, no broken \e)
  local lno="$1" ltxt="$2" rno="$3" rtxt="$4"

  local w inner left_w right_w
  w="$(term_cols)"
  inner=$((w - 2))

  # divider " | " = 3 chars
  left_w=$(( (inner - 3) / 2 ))
  right_w=$(( (inner - 3) - left_w ))

  # Prefix: " " + "%3s)" + " "  => 1 + 4 + 1 = 6
  local prefix_w=6
  local l_textw=$((left_w - prefix_w))
  local r_textw=$((right_w - prefix_w))
  (( l_textw < 8 )) && l_textw=8
  (( r_textw < 8 )) && r_textw=8

  # Truncate plain titles
  local Ltxt Rtxt
  Ltxt="$(truncate_plain "$ltxt" "$l_textw")"
  Rtxt="$(truncate_plain "$rtxt" "$r_textw")"

  # Build columns with colored number part directly (printf will interpret ANSI)
  local left_col right_col
  left_col="$(printf " %b%3s)%b %-*s" "${ACC3}${BOLD}" "$lno" "$RST" "$l_textw" "$Ltxt")"
  left_col="$(printf "%-*s" "$left_w" "$left_col")"   # exact width visually

  if [[ -n "$rno" ]]; then
    right_col="$(printf " %b%3s)%b %-*s" "${ACC3}${BOLD}" "$rno" "$RST" "$r_textw" "$Rtxt")"
    right_col="$(printf "%-*s" "$right_w" "$right_col")"
  else
    right_col="$(printf "%-*s" "$right_w" "")"
  fi

  # Print exact row
  printf -- "%s" "$(rb_v)"
  printf -- "%b" "$left_col"
  printf -- " %s " "$(rb_div)"
  printf -- "%b" "$right_col"
  printf -- "%s\n" "$(rb_v)"
}

# ============================================================
# SOCKS5 V2 (warp-cli)
# ============================================================
enable_socks_40000_v2() {
  clear
  box_top "SOCKS5 PROXY"
  box_line "${DIM}Enable SOCKS5 port 40000 (warp-cli new)${RST}"
  box_mid

  if ! command -v warp-cli >/dev/null 2>&1; then
    box_line "$(badge "ERR" "$RED") warp-cli not found. Install Cloudflare WARP first."
    box_bottom
    pause
    return 1
  fi

  systemctl enable --now warp-svc >/dev/null 2>&1 || true

  box_line "${ACC5}${BOLD}Step 1:${RST} Registration check..."
  if ! warp-cli --accept-tos registration show >/dev/null 2>&1; then
    box_line "${DIM}Registering device...${RST}"
    warp-cli --accept-tos registration new >/dev/null 2>&1 || warp-cli --accept-tos register || {
      box_line "$(badge "ERR" "$RED") Registration failed."
      box_bottom
      pause
      return 1
    }
  else
    box_line "$(badge "OK" "$GRN") Registration exists."
  fi

  box_line "${ACC5}${BOLD}Step 2:${RST} Set mode: proxy"
  warp-cli --accept-tos mode proxy >/dev/null 2>&1 || warp-cli --accept-tos set-mode proxy || {
    box_line "$(badge "ERR" "$RED") Failed to set proxy mode."
    box_bottom
    pause
    return 1
  }

  box_line "${ACC5}${BOLD}Step 3:${RST} Set port: 40000"
  warp-cli --accept-tos proxy port 40000 >/dev/null 2>&1 || true

  box_line "${ACC5}${BOLD}Step 4:${RST} Connect"
  warp-cli --accept-tos connect >/dev/null 2>&1 || {
    box_line "$(badge "ERR" "$RED") Connect failed."
    box_bottom
    pause
    return 1
  }

  box_mid
  if ss -lntp 2>/dev/null | grep -q ":40000"; then
    box_line "$(badge "OK" "$GRN") SOCKS5 listening on 127.0.0.1:40000"
  else
    box_line "$(badge "WARN" "$YLW") Port 40000 not listening."
  fi
  box_bottom
  pause
}

disable_socks_40000_v2() {
  clear
  box_top "SOCKS5 PROXY"
  box_line "${DIM}Disable SOCKS5 port 40000 (warp-cli new)${RST}"
  box_mid

  if ! command -v warp-cli >/dev/null 2>&1; then
    box_line "$(badge "ERR" "$RED") warp-cli not found."
    box_bottom
    pause
    return 1
  fi

  warp-cli --accept-tos disconnect >/dev/null 2>&1 || true
  warp-cli --accept-tos mode warp >/dev/null 2>&1 || warp-cli --accept-tos set-mode warp >/dev/null 2>&1 || true

  box_mid
  if ss -lntp 2>/dev/null | grep -q ":40000"; then
    box_line "$(badge "WARN" "$YLW") Port 40000 still listening (restart warp-svc)."
  else
    box_line "$(badge "OK" "$GRN") SOCKS5 disabled."
  fi
  box_bottom
  pause
}

# ============================================================
# Debian10 Fix: build wg + wg-quick
# ============================================================
install_wg_tools_debian10() {
  clear
  box_top "DEBIAN10 FIX"
  box_line "${DIM}Install wg + wg-quick (wireguard-tools userspace)${RST}"
  box_mid

  if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
    box_line "$(badge "OK" "$GRN") wg & wg-quick already installed."
    box_bottom
    pause
    return 0
  fi

  box_line "${ACC5}${BOLD}[1/4]${RST} Install dependencies..."
  apt update -y
  apt install -y curl ca-certificates tar xz-utils iproute2 openresolv

  if ! command -v make >/dev/null 2>&1 || ! command -v gcc >/dev/null 2>&1; then
    box_line "${DIM}Installing build-essential...${RST}"
    apt install -y build-essential
  fi

  box_line "${ACC5}${BOLD}[2/4]${RST} Download wireguard-tools source..."
  VER="v1.0.20210914"
  TMP="/tmp/wgtools"
  rm -rf "$TMP"
  mkdir -p "$TMP"
  cd "$TMP" || { box_line "$(badge "ERR" "$RED") Cannot cd to $TMP"; box_bottom; pause; return 1; }

  curl -L -o wireguard-tools.tar.xz \
    "https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-${VER}.tar.xz" || {
      box_line "$(badge "ERR" "$RED") Download failed."
      box_bottom
      pause
      return 1
    }

  box_line "${ACC5}${BOLD}[3/4]${RST} Extract + build + install..."
  tar -xf wireguard-tools.tar.xz || { box_line "$(badge "ERR" "$RED") Extract failed."; box_bottom; pause; return 1; }
  cd wireguard-tools-* || { box_line "$(badge "ERR" "$RED") Source folder not found."; box_bottom; pause; return 1; }

  make -C src -j"$(nproc)" && make -C src install || {
    box_line "$(badge "ERR" "$RED") Build/install wg failed."
    box_bottom
    pause
    return 1
  }

  if ! command -v wg-quick >/dev/null 2>&1; then
    if [[ -d contrib/wg-quick ]]; then
      make -C contrib/wg-quick -j"$(nproc)" && make -C contrib/wg-quick install || {
        box_line "$(badge "ERR" "$RED") Build/install wg-quick failed."
        box_bottom
        pause
        return 1
      }
    elif [[ -d src/wg-quick ]]; then
      make -C src/wg-quick -j"$(nproc)" && make -C src/wg-quick install || {
        box_line "$(badge "ERR" "$RED") Build/install wg-quick failed."
        box_bottom
        pause
        return 1
      }
    else
      box_line "$(badge "ERR" "$RED") wg-quick not found in snapshot dirs."
      box_bottom
      pause
      return 1
    fi
  fi

  box_line "${ACC5}${BOLD}[4/4]${RST} Verify..."
  if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
    box_line "$(badge "OK" "$GRN") Installed successfully."
  else
    box_line "$(badge "ERR" "$RED") Finished but commands not found."
  fi

  box_bottom
  pause
}

# ============================================================
# STATUS (detect iface + mode + cache)
# ============================================================
detect_active_wg_iface() {
  local ifaces=("wgcf4" "wgcf6" "wgcfd" "wgcfng")
  local i
  for i in "${ifaces[@]}"; do
    if systemctl is-active "wg-quick@${i}" >/dev/null 2>&1; then
      echo "$i"; return 0
    fi
  done
  echo "-"; return 1
}

cf_trace_warp_v4() {
  curl -s4 --connect-timeout 2 --max-time 3 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null \
    | awk -F= '/^warp=/{print $2; exit}'
}
cf_trace_warp_v6() {
  curl -s6 --connect-timeout 2 --max-time 3 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null \
    | awk -F= '/^warp=/{print $2; exit}'
}

detect_socks5_port_40000() {
  if ss -lntp 2>/dev/null | grep -qE '127\.0\.0\.1:40000|:40000'; then
    local r
    r=$(curl -sx "socks5h://127.0.0.1:40000" --connect-timeout 2 --max-time 3 -s https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null \
      | awk -F= '/^warp=/{print $2; exit}')
    if [[ "$r" == "on" || "$r" == "plus" ]]; then
      echo "On(:40000)"; return 0
    fi
    echo "Listening(:40000)"; return 0
  fi
  echo "Off"; return 1
}

CACHE_TTL=4
__cache_v4_ts=0; __cache_v6_ts=0; __cache_s5_ts=0
__cache_v4_val=""; __cache_v6_val=""; __cache_s5_val=""
now_ts() { date +%s; }

cached_cf_trace_warp_v4() {
  local now; now="$(now_ts)"
  if (( now - __cache_v4_ts < CACHE_TTL )) && [[ -n "$__cache_v4_val" ]]; then echo "$__cache_v4_val"; return 0; fi
  __cache_v4_val="$(cf_trace_warp_v4)"; __cache_v4_ts="$now"; echo "$__cache_v4_val"
}
cached_cf_trace_warp_v6() {
  local now; now="$(now_ts)"
  if (( now - __cache_v6_ts < CACHE_TTL )) && [[ -n "$__cache_v6_val" ]]; then echo "$__cache_v6_val"; return 0; fi
  __cache_v6_val="$(cf_trace_warp_v6)"; __cache_v6_ts="$now"; echo "$__cache_v6_val"
}
cached_detect_socks5_port_40000() {
  local now; now="$(now_ts)"
  if (( now - __cache_s5_ts < CACHE_TTL )) && [[ -n "$__cache_s5_val" ]]; then echo "$__cache_s5_val"; return 0; fi
  __cache_s5_val="$(detect_socks5_port_40000)"; __cache_s5_ts="$now"; echo "$__cache_s5_val"
}

get_live_status_compact() {
  local warp_svc socks wg_iface wg_stat mode v4 v6

  if systemctl is-active warp-svc >/dev/null 2>&1; then warp_svc="Running"; else warp_svc="Stopped"; fi
  socks="$(cached_detect_socks5_port_40000)"
  wg_iface="$(detect_active_wg_iface)"

  mode=$(case "$wg_iface" in
    wgcf4) echo "IPv4" ;;
    wgcf6) echo "IPv6" ;;
    wgcfd) echo "Dual" ;;
    wgcfng) echo "Non-Global" ;;
    *) echo "-" ;;
  esac)

  if [[ "$wg_iface" != "-" ]]; then wg_stat="Running($wg_iface)"; else wg_stat="Stopped"; fi

  v4="$(cached_cf_trace_warp_v4)"
  v6="$(cached_cf_trace_warp_v6)"

  case "$v4" in on) v4="WARP";; plus) v4="WARP+";; off|"") v4="Normal";; *) v4="Normal";; esac
  case "$v6" in on) v6="WARP";; plus) v6="WARP+";; off|"") v6="NoV6";; *) v6="NoV6";; esac

  echo "WARP Client|$warp_svc"
  echo "SOCKS5 Port|$socks"
  echo "WireGuard  |$wg_stat"
  echo "WG Mode    |$mode"
  echo "IPv4 Net   |$v4"
  echo "IPv6 Net   |$v6"
}

# ============================================================
# MAIN LOOP
# ============================================================
while true; do
  clear

  IPVPS=$(curl -s4 ipv4.icanhazip.com 2>/dev/null || curl -s4 ipinfo.io/ip 2>/dev/null || curl -s4 ifconfig.me 2>/dev/null)
  uptime_str="$(uptime -p 2>/dev/null | cut -d ' ' -f2-)"
  [[ -z "$uptime_str" ]] && uptime_str="-"
  tram=$(free -m 2>/dev/null | awk 'NR==2{print $2}'); uram=$(free -m 2>/dev/null | awk 'NR==2{print $3}')
  [[ -z "$tram" ]] && tram="0"; [[ -z "$uram" ]] && uram="0"

  OSNAME="$(lsb_release -ds 2>/dev/null)"
  [[ -z "$OSNAME" ]] && OSNAME="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Unknown}")"
  KERNEL="$(uname -r 2>/dev/null)"
  DATE_NOW="$(date 2>/dev/null)"

  box_top "CLOUDFLARE WARP CONTROL PANEL (Simple Menu By NiLphreakz)"
  box_mid

  box_line "${ACC5}${BOLD}SERVER${RST}"
  box_line "OS     : ${WHT}${OSNAME}${RST}"
  box_line "Kernel : ${WHT}${KERNEL}${RST}"
  box_line "Uptime : ${WHT}${uptime_str}${RST}"
  box_line "RAM    : ${WHT}${uram}MB${RST}/${WHT}${tram}MB${RST}"
  box_line "IPv4   : ${WHT}${IPVPS}${RST}"
  box_line "Date   : ${WHT}${DATE_NOW}${RST}"
  box_mid

  box_line "${ACC4}${BOLD}LIVE STATUS${RST}  ${DIM}(cached ${CACHE_TTL}s)${RST}"
  while IFS='|' read -r k v; do
    box_line "  ${ACC3}${k}${RST} : $(status_badge "$v")"
  done < <(get_live_status_compact)
  box_mid

  box_line "${ACC2}${BOLD}MAIN MENU${RST}  ${DIM}Choose 0-17${RST}"
  menu_row_2col "1"  "Install WARP Official"           "10" "WARP Non-Global (wgcfng)"
  menu_row_2col "2"  "Uninstall WARP Official"         "11" "Restart WireGuard (wgcf*)"
  menu_row_2col "3"  "Restart WARP Official"           "12" "Disable WireGuard (wgcf*)"
  box_mid
  menu_row_2col "4"  "Enable SOCKS5 Proxy :40000"      "13" "Status information"
  menu_row_2col "5"  "Disable SOCKS5 Proxy"            "14" "Version information"
  menu_row_2col "6"  "Install WireGuard tools"         "15" "Help information"
  box_mid
  menu_row_2col "7"  "WARP IPv4 (wgcf4)"               "16" "Reboot VPS"
  menu_row_2col "8"  "WARP IPv6 (wgcf6)"               "17" "Fix Debian10 wg/wg-quick"
  menu_row_2col "9"  "WARP Dual (wgcfd)"               "0"  "Exit"
  box_bottom

  echo -ne "  ${ACC1}${BOLD}Select${RST} ${DIM}[0-17]${RST} > "
  read -r menu

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
    *)  clear; echo -e "${RED}${BOLD}Invalid option!${RST}"; pause ;;
  esac
done
