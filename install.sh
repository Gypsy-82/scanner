#!/bin/bash
# ============================================================
#  Security Scanner — Docker Deployment Script
#  Run as root on Ubuntu/Debian VPS
#  Usage: sudo bash install.sh scanner.yourdomain.com
# ============================================================

set -euo pipefail

DOMAIN="${1:-scanner.yourdomain.com}"
CONFIG_DIR="/opt/scanner"
SCANNER_PORT="8080"

echo ""
echo "=============================================="
echo "  Security Scanner — Docker Deploy"
echo "  Domain: $DOMAIN"
echo "=============================================="
echo ""

# ── Check root ────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root: sudo bash install.sh $DOMAIN"
    exit 1
fi

# ── Install Docker ────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "[*] Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
else
    echo "[*] Docker already installed"
fi

# ── Install Docker Compose plugin ─────────────────────────────
if ! docker compose version &>/dev/null; then
    echo "[*] Installing Docker Compose plugin..."
    apt-get install -y docker-compose-plugin
else
    echo "[*] Docker Compose already installed"
fi

# ── Install nginx and certbot ─────────────────────────────────
echo "[*] Installing nginx and certbot..."
apt-get update -qq
apt-get install -y nginx certbot python3-certbot-nginx iptables-persistent

# ── Create config directory (above webroot, root-owned) ───────
echo "[*] Creating config directory at $CONFIG_DIR..."
mkdir -p "$CONFIG_DIR/logs"
chmod 750 "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR/logs"

# ── Initialize rate_limits.json ───────────────────────────────
if [ ! -f "$CONFIG_DIR/rate_limits.json" ]; then
    echo '{}' > "$CONFIG_DIR/rate_limits.json"
    chmod 660 "$CONFIG_DIR/rate_limits.json"
fi

# ── Run setup.php to generate config.php ──────────────────────
if [ ! -f "$CONFIG_DIR/config.php" ]; then
    if command -v php &>/dev/null; then
        echo ""
        echo "[*] Running setup.php to generate credentials..."
        php setup.php
        # setup.php writes to ./config.php by default — move it
        if [ -f "./config.php" ]; then
            mv ./config.php "$CONFIG_DIR/config.php"
            chmod 640 "$CONFIG_DIR/config.php"
            echo "[*] Config moved to $CONFIG_DIR/config.php"
        fi
    else
        echo "[!] PHP not found — install it and run: php setup.php"
        echo "[!] Then move config.php to $CONFIG_DIR/config.php"
        echo "[!] Continue install after config is in place."
    fi
else
    echo "[*] Config already exists at $CONFIG_DIR/config.php"
fi

# ── Build and start the container ─────────────────────────────
echo ""
echo "[*] Building scanner image..."
docker compose build

echo "[*] Starting container..."
docker compose up -d

# Wait for container to be ready
sleep 5
if docker ps --filter "name=scanner" --filter "status=running" | grep -q scanner; then
    echo "[*] Container running"
else
    echo "[!] Container failed to start — check: docker compose logs"
    exit 1
fi

# ── Apply iptables isolation ───────────────────────────────────
echo ""
echo "[*] Applying network isolation rules..."
bash docker/isolate.sh

# ── Configure nginx ───────────────────────────────────────────
echo "[*] Installing nginx config..."
NGINX_CONF="/etc/nginx/sites-available/scanner.conf"
sed "s/scanner.yourdomain.com/$DOMAIN/g" docker/nginx-proxy.conf > "$NGINX_CONF"

# Temporarily use HTTP-only config for certbot to get cert
cat > /etc/nginx/sites-available/scanner-temp.conf << EOF
server {
    listen 80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF

ln -sf /etc/nginx/sites-available/scanner-temp.conf /etc/nginx/sites-enabled/scanner.conf
nginx -t && systemctl reload nginx

# ── Get SSL certificate ───────────────────────────────────────
echo "[*] Obtaining Let's Encrypt certificate for $DOMAIN..."
certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN" || {
    echo "[!] certbot failed — ensure $DOMAIN DNS points to this server"
    echo "[!] Run manually: certbot --nginx -d $DOMAIN"
}

# ── Enable full nginx config with SSL ────────────────────────
rm -f /etc/nginx/sites-enabled/scanner.conf
rm -f /etc/nginx/sites-available/scanner-temp.conf
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/scanner.conf
nginx -t && systemctl reload nginx

# ── Make isolation persistent across reboots ──────────────────
RC_LOCAL="/etc/rc.local"
ISOLATE_LINE="bash $(pwd)/docker/isolate.sh"
if [ -f "$RC_LOCAL" ] && ! grep -q "isolate.sh" "$RC_LOCAL"; then
    sed -i "s|^exit 0|$ISOLATE_LINE\nexit 0|" "$RC_LOCAL"
    echo "[*] isolate.sh added to $RC_LOCAL"
fi

# Save current iptables rules
iptables-save > /etc/iptables/rules.v4

echo ""
echo "=============================================="
echo "  Deployment complete"
echo "=============================================="
echo ""
echo "  URL:        https://$DOMAIN"
echo "  Container:  docker compose logs -f"
echo "  Config:     $CONFIG_DIR/config.php"
echo "  Logs:       $CONFIG_DIR/logs/"
echo ""
echo "  Security:"
echo "  - Container port 8080 bound to 127.0.0.1 only"
echo "  - Scanner cannot reach other containers or host DBs"
echo "  - Filesystem read-only inside container"
echo "  - Session data wiped on logout / 2h inactivity"
echo ""
echo "  !! DELETE setup.php if it still exists:"
echo "     rm setup.php"
echo ""
