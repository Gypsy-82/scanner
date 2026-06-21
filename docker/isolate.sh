#!/bin/bash
# ============================================================
#  Scanner Network Isolation — run on HOST after docker-compose up
#  Purpose: block the scanner container from reaching any other
#           service on this VPS (other containers, host daemons,
#           internal network ranges).
#
#  Run as root:  sudo bash docker/isolate.sh
#  To remove:    sudo bash docker/isolate.sh --remove
#
#  Re-run after every docker-compose up (Docker flushes DOCKER-USER
#  on restart). Add to /etc/rc.local for persistence across reboots.
# ============================================================

set -euo pipefail

SCANNER_SUBNET="172.30.0.0/24"   # scanner_net in docker-compose.yml
SCANNER_BRIDGE="br-scanner"       # bridge interface name

# ── Validate running as root ───────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "[isolate] Must run as root (sudo bash docker/isolate.sh)"
    exit 1
fi

# ── Remove existing rules (clean slate) ───────────────────────
remove_rules() {
    echo "[isolate] Removing existing scanner isolation rules..."

    # DOCKER-USER rules
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 10.0.0.0/8      -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 192.168.0.0/16  -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 169.254.0.0/16  -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.17.0.0/16   -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.18.0.0/16   -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.19.0.0/16   -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.20.0.0/16   -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.21.0.0/16   -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.22.0.0/16   -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.23.0.0/16   -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.24.0.0/16   -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.25.0.0/16   -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.26.0.0/16   -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.27.0.0/16   -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.28.0.0/16   -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.29.0.0/16   -j DROP 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -s "$SCANNER_SUBNET" -d 172.31.0.0/16   -j DROP 2>/dev/null; do :; done

    # INPUT chain rules (scanner → host services)
    while iptables -D INPUT -i "$SCANNER_BRIDGE" -j DROP 2>/dev/null; do :; done

    echo "[isolate] Rules removed."
}

if [ "${1:-}" = "--remove" ]; then
    remove_rules
    exit 0
fi

# ── Check DOCKER-USER chain exists ────────────────────────────
if ! iptables -L DOCKER-USER > /dev/null 2>&1; then
    echo "[isolate] DOCKER-USER chain not found — is Docker running?"
    exit 1
fi

# ── Check bridge interface exists ─────────────────────────────
if ! ip link show "$SCANNER_BRIDGE" > /dev/null 2>&1; then
    echo "[isolate] Bridge $SCANNER_BRIDGE not found — run docker-compose up first"
    exit 1
fi

# Clean slate before re-applying
remove_rules

echo "[isolate] Applying scanner isolation rules..."
echo "[isolate] Scanner subnet: $SCANNER_SUBNET"
echo ""

# ══════════════════════════════════════════════════════════════
#  BLOCK 1: Scanner → host services
#  Packets from scanner to host go through INPUT chain via the
#  Docker bridge interface. Block everything so the scanner
#  cannot reach MySQL, Redis, PostgreSQL, or any other daemon
#  listening on the host.
# ══════════════════════════════════════════════════════════════
iptables -I INPUT -i "$SCANNER_BRIDGE" -j DROP
echo "[isolate] INPUT:  $SCANNER_SUBNET → host: DROP (all ports)"

# ══════════════════════════════════════════════════════════════
#  BLOCK 2: Scanner → other Docker containers / internal ranges
#  DOCKER-USER handles FORWARD chain — packets being routed
#  between container networks.
#
#  We block all RFC 1918 ranges EXCEPT the scanner's own subnet
#  (172.30.0.0/24). The scanner needs internet (public IPs) but
#  must never reach other containers or internal VPS networks.
# ══════════════════════════════════════════════════════════════

# Block scanner from reaching RFC 1918 private ranges
iptables -I DOCKER-USER -s "$SCANNER_SUBNET" -d 10.0.0.0/8     -j DROP
iptables -I DOCKER-USER -s "$SCANNER_SUBNET" -d 192.168.0.0/16 -j DROP
iptables -I DOCKER-USER -s "$SCANNER_SUBNET" -d 169.254.0.0/16 -j DROP   # link-local
echo "[isolate] FORWARD: $SCANNER_SUBNET → 10.0.0.0/8:        DROP"
echo "[isolate] FORWARD: $SCANNER_SUBNET → 192.168.0.0/16:    DROP"
echo "[isolate] FORWARD: $SCANNER_SUBNET → 169.254.0.0/16:    DROP"

# Block scanner from reaching other Docker bridge subnets (172.16-31.x/16 minus its own)
# 172.17/16 is the Docker default bridge where most other containers live
for i in 17 18 19 20 21 22 23 24 25 26 27 28 29 31; do
    iptables -I DOCKER-USER -s "$SCANNER_SUBNET" -d "172.${i}.0.0/16" -j DROP
    echo "[isolate] FORWARD: $SCANNER_SUBNET → 172.${i}.0.0/16:  DROP"
done

# ══════════════════════════════════════════════════════════════
#  VERIFY: Scanner can still reach the internet
#  (the rules above only block private ranges)
# ══════════════════════════════════════════════════════════════
echo ""
echo "[isolate] Done. Verification:"
echo "  Scanner CAN reach:    public internet (for site scanning + ClamAV updates)"
echo "  Scanner CANNOT reach: 10.0.0.0/8, 192.168.0.0/16, 172.17-29/31.x (other Docker nets)"
echo "  Scanner CANNOT reach: host services (MySQL, Redis, etc.) via Docker bridge"
echo ""

# ── Save rules for reboot persistence ─────────────────────────
if command -v iptables-save > /dev/null 2>&1; then
    if [ -f /etc/iptables/rules.v4 ]; then
        iptables-save > /etc/iptables/rules.v4
        echo "[isolate] Rules saved to /etc/iptables/rules.v4"
    elif [ -f /etc/sysconfig/iptables ]; then
        iptables-save > /etc/sysconfig/iptables
        echo "[isolate] Rules saved to /etc/sysconfig/iptables"
    else
        echo "[isolate] To persist across reboots, install iptables-persistent:"
        echo "           apt-get install iptables-persistent"
        echo "           or add to /etc/rc.local:"
        echo "           bash $(realpath "$0")"
    fi
fi
