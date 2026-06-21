# Web Security Scanner

A self-hosted security auditing tool for any website or domain. Scan response headers, detect hardcoded credentials, outdated libraries, DOM XSS sinks, exposed source maps, misconfigured cookies, and 19 other vulnerability categories — all from your own server, with nothing sent to third parties.

Built for authorized security testing only. Always obtain written permission before scanning a site you do not own.

---

## What's inside

| Module | What it does |
|---|---|
| **File Scanner** | Upload a PDF/doc — ClamAV + pdfid analysis for malware |
| **URL Scanner** | Check a URL against URLhaus, VirusTotal, Google Safe Browsing |
| **Site Audit** | Full site audit: security headers, SSL, open directories, sensitive paths, CMS detection (includes WordPress-specific checks when detected) |
| **OSINT** | DNS records, subdomains, reverse IP, certificate transparency |
| **Crawl** | Spider a site for hidden paths, sensitive probes, broken links |
| **Inspector** | Burp Suite-style response analysis — headers, credentials, JS secrets, DOM XSS, mixed content, SRI, and 13 more |

---

## Security model (read this first)

Your credentials never touch this repository or the Docker image. Here is exactly what happens:

1. You run one CLI command on your server — `php setup.php`
2. It asks for your email and password **interactively in your terminal**
3. It generates a random pepper, HMAC-hashes your email, and bcrypt-hashes your password (cost-13, ~1 second per attempt)
4. It writes `config.php` with the hashed values — **no plain-text credentials stored anywhere**
5. `config.php` lives on your server only, above the web root, never inside the Docker image
6. If an attacker somehow gets the hash without the pepper they cannot crack it — hashcat is useless without both

The scanner itself:
- Runs in a read-only Docker container
- Bound to `127.0.0.1` only — unreachable from the internet without going through your nginx
- Isolated from all other containers and host services via iptables
- Session data lives in RAM only — wiped on logout or after 2 hours of inactivity
- Every login generates new obfuscated route tokens — URLs change on every session

---

## Prerequisites

### Your server needs:
- Ubuntu 22.04 / Debian 12 (or similar)
- Docker + Docker Compose
- nginx
- PHP 8.x CLI (for running setup.php — not needed after that)
- A domain or subdomain pointed at your server's IP
- Port 80 and 443 open in your firewall

### Optional (scanner works without them, just skips those checks):
- VirusTotal API key — [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) (free)
- AbuseIPDB API key — [abuseipdb.com/register](https://www.abuseipdb.com/register) (free)
- Shodan API key — [account.shodan.io](https://account.shodan.io) (free tier available)

---

## Installation

### Step 1 — Get the code onto your server

```bash
git clone https://github.com/Gypsy-82/scanner.git
cd scanner
docker compose build
```

---

### Step 2 — Create the config directory

This directory lives **above the web root** and is never served publicly.

```bash
sudo mkdir -p /opt/scanner/logs
sudo chmod 750 /opt/scanner
```

---

### Step 3 — Set your email and password

> **This is where your login credentials are created.**
> You will type your email and password directly into the terminal.
> They are never stored in plain text — only a salted, peppered bcrypt hash is written to `config.php`.

```bash
# Navigate to where you cloned/downloaded the repo
cd wp-scanner/scanner

sudo php setup.php
```

You will be prompted for:
- Your admin email address
- A password (minimum 16 characters — use a passphrase like `correct-horse-battery-staple-99`)
- Optional API keys (press Enter to skip any)

`setup.php` writes `config.php` to the current directory. Move it to the secure location:

```bash
sudo mv config.php /opt/scanner/config.php
sudo chmod 640 /opt/scanner/config.php
```

Then create the rate limiting file:
```bash
echo '{}' | sudo tee /opt/scanner/rate_limits.json > /dev/null
sudo chmod 660 /opt/scanner/rate_limits.json
```

**Delete setup.php immediately after running it:**
```bash
sudo rm setup.php
```

---

### Step 4 — Start the container

```bash
docker compose up -d
```

Verify it started:
```bash
docker ps
# You should see: scanner   Up X seconds
```

Check the logs:
```bash
docker compose logs -f
# ClamAV will update its definitions on first start — this takes 1-2 minutes
```

---

### Step 5 — Apply network isolation

This script adds iptables rules that block the scanner container from reaching any other service on your server (databases, other containers, internal network). **Run it every time after `docker compose up`.**

```bash
sudo bash docker/isolate.sh
```

What it blocks:
- Scanner → your MySQL / Redis / PostgreSQL / any host service
- Scanner → other Docker containers on the server
- Scanner → AWS/GCP/Azure metadata API (credential theft vector)
- Scanner → any private IP range (10.x, 192.168.x, 172.16-31.x)

What it allows:
- Scanner → public internet (needed to scan target sites and update ClamAV)

To make it permanent across reboots:
```bash
sudo apt-get install iptables-persistent
sudo iptables-save > /etc/iptables/rules.v4
```

---

### Step 6 — Configure nginx as SSL proxy

Install the nginx config:
```bash
sudo cp docker/nginx-proxy.conf /etc/nginx/sites-available/scanner.conf
```

Open the file and replace `scanner.yourdomain.com` with your actual domain:
```bash
sudo nano /etc/nginx/sites-available/scanner.conf
# Replace every instance of scanner.yourdomain.com with your domain
```

Enable it:
```bash
sudo ln -s /etc/nginx/sites-available/scanner.conf /etc/nginx/sites-enabled/scanner.conf
sudo nginx -t
sudo systemctl reload nginx
```

Get your SSL certificate:
```bash
sudo certbot --nginx -d your.domain.com
```

---

### Step 7 — Log in

Open `https://your.domain.com` in your browser.

Enter the email and password you set in Step 3. That's it.

> Every time you log in, the scanner generates 6 new random URL tokens for the scan modules. The URLs change on every session — there are no predictable paths for an attacker to probe.

---

## Automatic deployment

If you prefer to run everything in one command:

```bash
sudo bash install.sh your.domain.com
```

This runs Steps 1-6 automatically. You will still be prompted to enter your email and password interactively during the process.

---

## Updating

```bash
# Pull latest code
git pull

# Rebuild and restart container (your config.php is untouched — it's on the host)
docker compose down
docker compose build
docker compose up -d

# Re-apply network isolation
sudo bash docker/isolate.sh
```

Your credentials and logs are stored in `/opt/scanner/` on the host — they survive container updates.

---

## Changing your password

Re-run setup.php and overwrite `config.php`:

```bash
php setup.php
sudo mv config.php /opt/scanner/config.php
sudo chmod 640 /opt/scanner/config.php
rm setup.php

# Restart so the new config is loaded
docker compose restart
```

---

## File layout

```
scanner/
├── docker/
│   ├── Dockerfile            # Container build
│   ├── apache-scanner.conf   # Apache vhost (hardened)
│   ├── php-hardened.ini      # PHP security settings
│   ├── entrypoint.sh         # Startup: freshclam → Apache
│   ├── isolate.sh            # Host iptables isolation rules
│   └── nginx-proxy.conf      # nginx SSL reverse proxy template
├── public_html/              # Webroot (inside container)
│   ├── index.php             # Router + login + dashboard
│   └── api/                  # Scan handlers (not HTTP-accessible directly)
├── docker-compose.yml        # Container definition
├── config.example.php        # Template — shows all available settings
├── setup.php                 # One-time credential setup (delete after use)
└── install.sh                # Full automated deployment script
```

Files that **never** appear in this repo or the Docker image:
- `config.php` — your hashed credentials and API keys
- `rate_limits.json` — login attempt tracking
- `logs/` — access and error logs

---

## Hardening summary

| Layer | What's enforced |
|---|---|
| Network | Container bound to `127.0.0.1:8080` — not reachable from internet |
| Network | iptables blocks scanner from all other VPS services and containers |
| Network | Container uses public DNS (8.8.8.8) — cannot resolve internal hostnames |
| Container | Read-only filesystem — no writes except explicit volume mounts |
| Container | All Linux capabilities dropped except minimum for Apache |
| Container | `no-new-privileges` — no escalation possible inside container |
| Container | 512 MB RAM / 1 CPU limit — scan jobs can't starve other services |
| PHP | `open_basedir` — PHP cannot read files outside `/var/www/scanner` and `/tmp` |
| PHP | Dangerous functions disabled (`shell_exec`, `system`, `phpinfo`, etc.) |
| PHP | Sessions in RAM (`/tmp`) — nothing written to disk, wiped on logout |
| Auth | Email + password both peppered with HMAC-SHA256 before bcrypt (cost-13) |
| Auth | Route tokens rotate on every login — no predictable URL paths |
| Auth | 5 failed login attempts → 15-minute IP lockout |
| Auth | 2-hour inactivity → automatic logout + token destruction |
| SSL | TLS 1.2/1.3 only, HSTS, OCSP stapling via nginx |

---

## Troubleshooting

**Container won't start**
```bash
docker compose logs
# Most common cause: config.php not found at /opt/scanner/config.php
```

**ClamAV definitions missing on first start**
```bash
# Normal — freshclam downloads ~300 MB on first boot. Wait 2-3 minutes.
docker compose logs -f
```

**Login page shows but login fails**
- Make sure you ran `setup.php` and the output `config.php` is at `/opt/scanner/config.php`
- Check file permissions: `ls -la /opt/scanner/config.php` should show `-rw-r-----`

**Scanner can't reach a target site**
```bash
# Test internet access from inside the container
docker exec scanner curl -s --max-time 5 https://example.com
```

**Isolation rules lost after reboot**
```bash
sudo bash docker/isolate.sh
# Then save: sudo iptables-save > /etc/iptables/rules.v4
```

---

## Legal

This tool is for authorized security testing only. Scanning any domain or website without explicit written permission from the owner may be illegal in your jurisdiction. The authors accept no liability for misuse.
