FROM php:8.2-apache

# ── System packages ────────────────────────────────────────────
# clamav: file scanning
# python3: pdfid.py
# unzip/wget: fetch pdfid at build time
RUN apt-get update && apt-get install -y --no-install-recommends \
        clamav \
        python3 \
        unzip \
        wget \
    && rm -rf /var/lib/apt/lists/*

# ── pdfid (Didier Stevens) ─────────────────────────────────────
RUN wget -q "https://didierstevens.com/files/software/pdfid_V0_2_8.zip" \
        -O /tmp/pdfid.zip \
    && unzip -q /tmp/pdfid.zip pdfid.py -d /opt/pdfid \
    && rm /tmp/pdfid.zip \
    && chmod 755 /opt/pdfid/pdfid.py \
    && chown root:root /opt/pdfid/pdfid.py

# ── PHP extensions ─────────────────────────────────────────────
RUN docker-php-ext-install opcache

# ── Apache modules ─────────────────────────────────────────────
RUN a2enmod rewrite headers

# ── Harden global Apache config ────────────────────────────────
RUN printf '\nTraceEnable Off\nServerSignature Off\nServerTokens Prod\n' \
    >> /etc/apache2/conf-available/security.conf \
    && a2enconf security

# ── Apache virtual host ────────────────────────────────────────
COPY docker/apache-scanner.conf /etc/apache2/sites-available/scanner.conf
RUN a2dissite 000-default.conf && a2ensite scanner.conf

# ── PHP hardening ──────────────────────────────────────────────
COPY docker/php-hardened.ini /usr/local/etc/php/conf.d/99-scanner.ini

# ── Application files (webroot only — config stays on host) ───
COPY public_html/ /var/www/scanner/public_html/

# ── Permissions ────────────────────────────────────────────────
RUN chown -R www-data:www-data /var/www/scanner \
    && chmod 750 /var/www/scanner \
    && chmod 755 /var/www/scanner/public_html \
    && find /var/www/scanner/public_html -type d -exec chmod 755 {} \; \
    && find /var/www/scanner/public_html -name "*.php" -exec chmod 640 {} \; \
    && find /var/www/scanner/public_html/assets -type f -exec chmod 644 {} \;

# ── ClamAV signature directory (will be a named volume) ───────
RUN mkdir -p /var/lib/clamav \
    && chown clamav:clamav /var/lib/clamav \
    && chmod 750 /var/lib/clamav

# ── Runtime dirs (will be tmpfs — pre-create so Docker ────────
# accepts read_only: true without missing paths at startup)
RUN mkdir -p /tmp/scanner_uploads \
              /tmp/php_sessions \
              /var/lock/apache2 \
              /var/run/apache2 \
    && chown www-data:www-data /tmp/scanner_uploads /tmp/php_sessions \
    && chmod 750 /tmp/scanner_uploads /tmp/php_sessions

# ── Entrypoint ─────────────────────────────────────────────────
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
