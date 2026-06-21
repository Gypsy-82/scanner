#!/bin/bash
# Container entrypoint — run freshclam then start Apache

set -e

# ── Verify config is mounted ───────────────────────────────────
if [ ! -f /var/www/scanner/config.php ]; then
    echo "[scanner] FATAL: config.php not mounted."
    echo "[scanner] On the host, run: php /opt/scanner/setup.php"
    echo "[scanner] Then start the container with config.php bind-mounted."
    exit 1
fi

# ── Update ClamAV definitions if missing or >24h old ──────────
CLAMAV_DB="/var/lib/clamav/main.cvd"
CLAMAV_DB2="/var/lib/clamav/main.cld"

needs_update() {
    [ ! -f "$CLAMAV_DB" ] && [ ! -f "$CLAMAV_DB2" ] && return 0
    local db="${CLAMAV_DB2:-$CLAMAV_DB}"
    [ -f "$CLAMAV_DB" ] && db="$CLAMAV_DB"
    [ -f "$CLAMAV_DB2" ] && db="$CLAMAV_DB2"
    local age=$(( $(date +%s) - $(stat -c %Y "$db") ))
    [ $age -gt 86400 ]
}

if needs_update; then
    echo "[scanner] Updating ClamAV definitions..."
    freshclam --quiet || echo "[scanner] freshclam update failed — file scanning may use stale definitions"
else
    echo "[scanner] ClamAV definitions are current"
fi

# ── Runtime dir permissions (tmpfs mounts start empty) ────────
mkdir -p /tmp/scanner_uploads /tmp/php_sessions
chown www-data:www-data /tmp/scanner_uploads /tmp/php_sessions
chmod 750 /tmp/scanner_uploads /tmp/php_sessions

mkdir -p /var/www/scanner/logs
chown www-data:www-data /var/www/scanner/logs
chmod 750 /var/www/scanner/logs

# ── Start Apache ───────────────────────────────────────────────
exec apache2-foreground
