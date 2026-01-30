#!/bin/bash
# DieAuth Installer (authorized / educational use only)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
NC='\033[0m'

PAD="     "   # 5 spaces

# Root check
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Please run as root: sudo ./install.sh${NC}"
    exit 1
fi

# Trap Ctrl+C
trap 'echo -e "\n${RED}[!] Installation interrupted.${NC}"; exit 1' INT TERM

clear
echo -e "\n\n\n"

# ASCII banner
echo -e "${PAD}${RED}▓█████▄  ██▓▓█████${NC} ▄▄▄       █    ██ ▄▄▄█████▓ ██░ ██ "
echo -e "${PAD}${RED}▒██▀ ██▌▓██ ▓█   ▀${NC}▒████▄     ██  ▓██▒▓  ██▒ ▓▒▓██░ ██▒"
echo -e "${PAD}${RED}░██   █▌▒██ ▒███  ${NC}▒██  ▀█▄  ▓██  ▒██░▒ ▓██░ ▒░▒██▀▀██░"
echo -e "${PAD}${RED}░▓█▄   ▌░██ ▒▓█  ▄${NC}░██▄▄▄▄██ ▓▓█  ░██░░ ▓██▓ ░ ░▓█ ░██ "
echo -e "${PAD}${RED}░▒████▓ ░██ ░▒████${NC}▒▓█   ▓██▒▒▒█████▓   ▒██▒ ░ ░▓█▒░██▓"
echo ""
echo -e "               ${YELLOW}Wi-Fi Deauth Research Tool${NC}"
echo ""

echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  Authorized use only. You are solely responsible for compliance. ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${GREEN}[*] Updating package lists...${NC}"
apt update -y >/dev/null

echo -e "${GREEN}[*] Installing dependencies...${NC}"
apt install -y \
    aircrack-ng \
    iw \
    iproute2 \
    rfkill \
    net-tools \
    nmap \
    curl \
    >/dev/null

echo ""
echo -e "${GREEN}[+] Installation complete.${NC}"
echo -e "${YELLOW}    Run with: sudo ./run.sh${NC}"
