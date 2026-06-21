<?php
// ── Config ────────────────────────────────────────────────────
$config_path = __DIR__ . '/../../config.php';
if (file_exists($config_path)) require_once $config_path;
else {
    define('AUTH_PEPPER',          '');
    define('AUTH_EMAIL_HMAC',      '');
    define('SCANNER_PASSWORD_HASH','');
    define('SESSION_TIMEOUT',      7200);
    define('SESSION_NAME',         'scanner_sess');
    define('RATE_LIMIT_FILE',      sys_get_temp_dir() . '/scanner_rl.json');
    define('SRC_DIR',              __DIR__ . '/api/');
}

// ── Session hardening ─────────────────────────────────────────
ini_set('session.cookie_httponly',   1);
ini_set('session.cookie_secure',     1);
ini_set('session.cookie_samesite',  'Strict');
ini_set('session.use_strict_mode',   1);
ini_set('session.use_only_cookies',  1);
ini_set('session.name',              SESSION_NAME);
ini_set('session.gc_maxlifetime',    SESSION_TIMEOUT);
session_start();

// ── CSRF token ────────────────────────────────────────────────
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

// Pepper-based credential verification:
// HMAC-SHA256(value, pepper) pre-processes both email and password
// before bcrypt. Without the pepper, the hash is uncrackable offline
// because an attacker cannot reconstruct the bcrypt input.
function verify_login(string $email, string $password): bool {
    if (!AUTH_PEPPER || !AUTH_EMAIL_HMAC || !SCANNER_PASSWORD_HASH) return false;
    $email_ok = hash_equals(
        AUTH_EMAIL_HMAC,
        hash_hmac('sha256', strtolower(trim($email)), AUTH_PEPPER)
    );
    // Timing-safe: always run password_verify even if email fails
    $pass_ok = password_verify(
        hash_hmac('sha256', $password, AUTH_PEPPER),
        SCANNER_PASSWORD_HASH
    );
    return $email_ok && $pass_ok;
}

// 5 attempts per IP per 15 minutes, tracked above webroot.
function rate_limit_ok(string $ip): bool {
    $file = RATE_LIMIT_FILE;
    $data = [];
    if (file_exists($file)) {
        $raw  = @file_get_contents($file);
        $data = $raw ? (json_decode($raw, true) ?? []) : [];
    }
    $now = time();
    // Purge entries older than 15 minutes
    foreach ($data as $k => $v) {
        if ($now - ($v['first'] ?? 0) > 900) unset($data[$k]);
    }
    $key = md5($ip); // store hashed IP — avoid logging raw IPs in a JSON file
    if (!isset($data[$key])) $data[$key] = ['count' => 0, 'first' => $now];
    $data[$key]['count']++;
    file_put_contents($file, json_encode($data), LOCK_EX);
    return $data[$key]['count'] <= 5;
}

// Fresh random token per route, per session.
// Tokens are 16 hex chars (64-bit entropy) — not guessable.
function make_routes(): array {
    return [
        'file'    => bin2hex(random_bytes(8)),
        'url'     => bin2hex(random_bytes(8)),
        'site'    => bin2hex(random_bytes(8)),
        'osint'   => bin2hex(random_bytes(8)),
        'crawl'   => bin2hex(random_bytes(8)),
        'inspect' => bin2hex(random_bytes(8)),
    ];
}

function auth_log(string $event, string $ip): void {
    if (!defined('LOG_DIR')) return;
    $line = date('Y-m-d H:i:s') . ' | ' . str_pad($event, 10) . ' | ' . $ip . PHP_EOL;
    @file_put_contents(LOG_DIR . 'auth.log', $line, FILE_APPEND | LOCK_EX);
}

// ─────────────────────────────────────────────────────────────
// Router — dispatch POST requests via per-session tokens
// All API endpoints are unreachable via any predictable URL.
// Tokens are regenerated on every login and destroyed on logout.
// ─────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_SESSION['authenticated']) && !empty($_SESSION['routes'])) {
    $req_path = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
    $handler  = array_search($req_path, $_SESSION['routes'], true);

    if ($handler !== false) {
        $src_map = [
            'file'    => SRC_DIR . 'scan_file.php',
            'url'     => SRC_DIR . 'scan_url.php',
            'site'    => SRC_DIR . 'scan_site.php',
            'osint'   => SRC_DIR . 'osint.php',
            'crawl'   => SRC_DIR . 'crawl.php',
            'inspect' => SRC_DIR . 'inspect.php',
        ];
        if (isset($src_map[$handler]) && file_exists($src_map[$handler])) {
            require $src_map[$handler];
            exit;
        }
    }

    // Unknown token POST — return generic 404, no info leakage
    if (!empty($req_path)) {
        http_response_code(404);
        exit;
    }
}

// ── Login ─────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email'], $_POST['password'])) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    if (!rate_limit_ok($ip)) {
        $login_error = 'Too many failed attempts. Try again in 15 minutes.';
        auth_log('RATELIMIT', $ip);
    } elseif (verify_login($_POST['email'], $_POST['password'])) {
        session_regenerate_id(true);
        $_SESSION['authenticated'] = true;
        $_SESSION['last_active']   = time();
        $_SESSION['routes']        = make_routes(); // fresh tokens every login
        auth_log('LOGIN_OK', $ip);
        header('Location: /');
        exit;
    } else {
        $login_error = 'Invalid credentials'; // never reveal which field failed
        auth_log('LOGIN_FAIL', $ip);
    }
}

// ── Logout ────────────────────────────────────────────────────
if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    setcookie(SESSION_NAME, '', [
        'expires'  => 1,
        'path'     => '/',
        'httponly' => true,
        'secure'   => true,
        'samesite' => 'Strict',
    ]);
    header('Location: /');
    exit;
}

// ── Auth check / inactivity timeout ──────────────────────────
$authenticated = !empty($_SESSION['authenticated']) &&
                 !empty($_SESSION['last_active'])    &&
                 (time() - $_SESSION['last_active'] < SESSION_TIMEOUT);

if ($authenticated) {
    $_SESSION['last_active'] = time();
} elseif (!empty($_SESSION['authenticated'])) {
    // Session timed out — wipe everything including route tokens
    $_SESSION = [];
    session_destroy();
    setcookie(SESSION_NAME, '', ['expires' => 1, 'path' => '/', 'httponly' => true, 'secure' => true, 'samesite' => 'Strict']);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Scanner</title>
<link rel="stylesheet" href="/assets/css/app.css">
<?php if ($authenticated): ?>
<script>
// Route tokens are per-session, regenerated on every login,
// destroyed on logout or 2-hour inactivity timeout.
window.ROUTES = <?= json_encode($_SESSION['routes'], JSON_HEX_TAG | JSON_HEX_QUOT) ?>;
</script>
<?php endif; ?>
</head>
<body>

<?php if (!$authenticated): ?>
<!-- ─────────────────── LOGIN PAGE ─────────────────────────── -->
<div class="login-wrap">
  <div class="login-box">
    <div class="login-logo">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#00ff88" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <span>Security Scanner</span>
    </div>
    <?php if (!empty($login_error)): ?>
      <div class="alert alert-danger"><?= htmlspecialchars($login_error) ?></div>
    <?php endif; ?>
    <?php if (!AUTH_PEPPER || !AUTH_EMAIL_HMAC || !SCANNER_PASSWORD_HASH): ?>
      <div class="alert alert-warn">Config not set up. Run <code>php setup.php</code> from the server CLI.</div>
    <?php endif; ?>
    <form method="POST">
      <label>Email</label>
      <input type="email" name="email" autofocus required placeholder="your@email.com" autocomplete="username">
      <label>Password</label>
      <input type="password" name="password" required placeholder="Enter scanner password" autocomplete="current-password">
      <button type="submit">Unlock</button>
    </form>
  </div>
</div>

<?php else: ?>
<!-- ─────────────────── DASHBOARD ──────────────────────────── -->
<div class="layout">

  <nav class="sidebar" id="sidebar">
    <div class="sidebar-logo">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#00ff88" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <span class="sidebar-logo-text">Scanner</span>
    </div>
    <ul class="nav-links">
      <li><a href="#" class="nav-link active" data-tab="file" data-label="File Scan">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/></svg>
        <span>File Scan</span>
      </a></li>
      <li><a href="#" class="nav-link" data-tab="url" data-label="URL Scan">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/></svg>
        <span>URL Scan</span>
      </a></li>
      <li><a href="#" class="nav-link" data-tab="site" data-label="Site Audit">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></svg>
        <span>Site Audit</span>
      </a></li>
      <li><a href="#" class="nav-link" data-tab="osint" data-label="OSINT">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <span>OSINT</span>
      </a></li>
      <li><a href="#" class="nav-link" data-tab="crawl" data-label="Crawl">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>
        <span>Crawl</span>
      </a></li>
      <li><a href="#" class="nav-link" data-tab="inspect" data-label="Inspector">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>
        <span>Inspector</span>
      </a></li>
      <li><a href="#" class="nav-link" data-tab="hash" data-label="Hash &amp; Encode">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg>
        <span>Hash &amp; Encode</span>
      </a></li>
      <li><a href="#" class="nav-link" data-tab="testlab" data-label="Test Lab">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 3h6M8 3v6l-4 9a1 1 0 00.9 1.5h14.2a1 1 0 00.9-1.5L16 9V3"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        <span>Test Lab</span>
      </a></li>
    </ul>
    <div class="sidebar-foot">
      <a href="?logout" class="logout-btn">Logout</a>
      <button class="sidebar-collapse-btn" id="sidebar-toggle" title="Collapse sidebar">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15,18 9,12 15,6"/></svg>
      </button>
    </div>
  </nav>

  <main class="content">
  <div class="content-wrap">

    <!-- FILE SCAN -->
    <section class="tab-panel active" id="tab-file">
      <div class="panel-header">
        <h2>File Scanner</h2>
        <p>ClamAV antivirus + pdfid PDF analysis + strings pattern scan + VirusTotal hash lookup</p>
      </div>
      <div class="panel-body">
        <form class="scan-form" id="form-file" enctype="multipart/form-data">
          <input type="hidden" name="csrf" value="<?= $csrf ?>">
          <div class="field-row">
            <label>Upload File <span class="hint">(PDF, MOBI, EPUB, ZIP, DOC — max 25 MB)</span></label>
            <div class="file-drop" id="file-drop">
              <!-- Input overlays the entire drop zone — no JS click routing needed -->
              <input type="file" name="file" id="file-input" class="file-input-overlay">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="32"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17,8 12,3 7,8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
              <span>Drop file here or <span class="link">browse</span></span>
              <div class="file-name" id="file-name"></div>
            </div>
          </div>
          <button type="submit" class="btn-scan">Scan File</button>
        </form>
        <div class="results-panel" id="results-file"></div>
      </div>
    </section>

    <!-- URL SCAN -->
    <section class="tab-panel" id="tab-url">
      <div class="panel-header">
        <h2>URL Scanner</h2>
        <p>URLhaus (no key) + VirusTotal + Google Safe Browsing + AbuseIPDB IP reputation</p>
      </div>
      <div class="panel-body">
        <form class="scan-form" id="form-url">
          <input type="hidden" name="csrf" value="<?= $csrf ?>">
          <div class="field-row">
            <label>URL to scan</label>
            <input type="url" name="url" placeholder="https://example.com/suspicious-file.pdf" required>
          </div>
          <button type="submit" class="btn-scan">Scan URL</button>
        </form>
        <div class="results-panel" id="results-url"></div>
      </div>
    </section>

    <!-- SITE AUDIT -->
    <section class="tab-panel" id="tab-site">
      <div class="panel-header">
        <h2>Site Audit</h2>
        <p>WordPress endpoint sweep · HTTP security headers · SSL certificate · version disclosure · exposed files</p>
      </div>
      <div class="panel-body">
        <form class="scan-form" id="form-site">
          <input type="hidden" name="csrf" value="<?= $csrf ?>">
          <div class="field-row">
            <label>Target URL</label>
            <input type="url" name="url" placeholder="https://example.com" required>
          </div>
          <button type="submit" class="btn-scan">Audit Site</button>
        </form>
        <div class="results-panel" id="results-site"></div>
      </div>
    </section>

    <!-- OSINT -->
    <section class="tab-panel" id="tab-osint">
      <div class="panel-header">
        <h2>OSINT</h2>
        <p>Reverse IP (osint.sh) · Subdomain enum (crt.sh + OTX + HackerTarget) · DNS records</p>
      </div>
      <div class="panel-body">
        <form class="scan-form" id="form-osint">
          <input type="hidden" name="csrf" value="<?= $csrf ?>">
          <div class="field-row">
            <label>Domain or IP</label>
            <input type="text" name="target" placeholder="example.com or 8.8.8.8" required>
          </div>
          <div class="field-row field-row--inline">
            <label>Lookup type</label>
            <select name="type">
              <option value="all">All (reverse IP + subdomains + DNS)</option>
              <option value="reverseip">Reverse IP only</option>
              <option value="subdomains">Subdomains only</option>
            </select>
          </div>
          <button type="submit" class="btn-scan">Run OSINT</button>
        </form>
        <div class="results-panel" id="results-osint"></div>
      </div>
    </section>

    <!-- CRAWL -->
    <section class="tab-panel" id="tab-crawl">
      <div class="panel-header">
        <h2>Link Crawler &amp; Endpoint Prober</h2>
        <p>Crawl mode: follows links recursively · Probe mode: hits 80+ known sensitive paths</p>
      </div>
      <div class="panel-body">
        <form class="scan-form" id="form-crawl">
          <input type="hidden" name="csrf" value="<?= $csrf ?>">
          <div class="field-row">
            <label>Target URL</label>
            <input type="url" name="url" placeholder="https://example.com" required>
          </div>
          <div class="field-row field-row--inline">
            <label>Mode</label>
            <select name="mode">
              <option value="probe">Probe (sensitive paths only — fast)</option>
              <option value="crawl">Crawl (spider all links — thorough)</option>
            </select>
            <label>Depth</label>
            <select name="depth">
              <option value="1">1 — Surface only</option>
              <option value="2" selected>2 — Standard</option>
              <option value="3">3 — Deep (slow)</option>
            </select>
          </div>
          <button type="submit" class="btn-scan">Start Scan</button>
        </form>
        <div class="results-panel" id="results-crawl"></div>
      </div>
    </section>

    <!-- INSPECTOR -->
    <section class="tab-panel" id="tab-inspect">
      <div class="panel-header">
        <h2>Response Inspector</h2>
        <p>Burp Suite-style analysis — response headers · hardcoded credentials · API keys · JS endpoint extraction · cookie security · CORS · info disclosure</p>
      </div>
      <div class="panel-body">
        <form class="scan-form" id="form-inspect">
          <input type="hidden" name="csrf" value="<?= $csrf ?>">
          <div class="field-row">
            <label>Target URL <span class="hint">(scans the page + all linked JS files)</span></label>
            <input type="url" name="url" placeholder="https://example.com" required>
          </div>
          <div class="field-row field-row--inline">
            <label>Scan depth</label>
            <select name="scan_js">
              <option value="1">Follow linked JS files (recommended)</option>
              <option value="0">Headers + body only (faster)</option>
            </select>
          </div>
          <button type="submit" class="btn-scan">Inspect</button>
        </form>
        <div class="results-panel" id="results-inspect"></div>
      </div>
    </section>

    <!-- TEST LAB -->
    <!-- ── Hash & Encode ──────────────────────────────────────── -->
    <section class="tab-panel" id="tab-hash">
      <div class="panel-header">
        <h2>Hash &amp; Encode</h2>
        <p>Generate hashes, encode/decode strings, identify hash types, and crack weak hashes — 100% local, no external requests</p>
      </div>
      <div class="panel-body">

        <!-- Mode selector -->
        <div class="hash-modes" id="hash-mode-bar">
          <button class="hash-mode-btn active" data-mode="hash">Hash</button>
          <button class="hash-mode-btn" data-mode="hmac">HMAC</button>
          <button class="hash-mode-btn" data-mode="encode">Encode</button>
          <button class="hash-mode-btn" data-mode="decode">Decode</button>
          <button class="hash-mode-btn" data-mode="identify">Identify</button>
          <button class="hash-mode-btn" data-mode="crack">Crack</button>
        </div>

        <div class="hash-workspace">
          <!-- Input -->
          <div class="field-row">
            <label id="hash-input-label">Input text</label>
            <textarea id="hash-input" rows="4" placeholder="Type or paste text / hash here..."></textarea>
          </div>

          <!-- Mode: Hash -->
          <div class="hash-panel active" id="hp-hash">
            <div class="hash-alg-strip" id="hash-alg-strip">
              <span class="hash-alg-label">Algorithm</span>
              <button class="hash-alg-btn active" data-alg="all">All</button>
              <button class="hash-alg-btn" data-alg="md5">MD5</button>
              <button class="hash-alg-btn" data-alg="sha1">SHA-1</button>
              <button class="hash-alg-btn" data-alg="sha256">SHA-256</button>
              <button class="hash-alg-btn" data-alg="sha384">SHA-384</button>
              <button class="hash-alg-btn" data-alg="sha512">SHA-512</button>
            </div>
            <button class="btn-scan" id="hash-go">Generate Hash</button>
          </div>

          <!-- Mode: HMAC -->
          <div class="hash-panel" id="hp-hmac">
            <div class="field-row">
              <label>Secret Key</label>
              <input type="text" id="hmac-key" placeholder="HMAC secret key..." style="font-family:var(--font-mono)">
            </div>
            <div class="hash-alg-strip">
              <span class="hash-alg-label">Algorithm</span>
              <button class="hash-alg-btn active" data-alg="sha256">HMAC-SHA256</button>
              <button class="hash-alg-btn" data-alg="sha512">HMAC-SHA512</button>
              <button class="hash-alg-btn" data-alg="sha1">HMAC-SHA1</button>
              <button class="hash-alg-btn" data-alg="md5">HMAC-MD5</button>
            </div>
            <button class="btn-scan" id="hmac-go">Generate HMAC</button>
          </div>

          <!-- Mode: Encode (client-side) -->
          <div class="hash-panel" id="hp-encode">
            <div class="hash-alg-strip">
              <span class="hash-alg-label">Format</span>
              <button class="hash-alg-btn active" data-enc="base64">Base64</button>
              <button class="hash-alg-btn" data-enc="base64url">Base64 URL</button>
              <button class="hash-alg-btn" data-enc="hex">Hex</button>
              <button class="hash-alg-btn" data-enc="url">URL</button>
              <button class="hash-alg-btn" data-enc="html">HTML Entities</button>
              <button class="hash-alg-btn" data-enc="binary">Binary</button>
              <button class="hash-alg-btn" data-enc="rot13">ROT13</button>
            </div>
            <button class="btn-scan" id="encode-go">Encode</button>
          </div>

          <!-- Mode: Decode (client-side) -->
          <div class="hash-panel" id="hp-decode">
            <div class="hash-alg-strip">
              <span class="hash-alg-label">Format</span>
              <button class="hash-alg-btn active" data-enc="base64">Base64</button>
              <button class="hash-alg-btn" data-enc="base64url">Base64 URL</button>
              <button class="hash-alg-btn" data-enc="hex">Hex</button>
              <button class="hash-alg-btn" data-enc="url">URL</button>
              <button class="hash-alg-btn" data-enc="html">HTML Entities</button>
              <button class="hash-alg-btn" data-enc="binary">Binary</button>
              <button class="hash-alg-btn" data-enc="rot13">ROT13</button>
            </div>
            <button class="btn-scan" id="decode-go">Decode</button>
          </div>

          <!-- Mode: Identify -->
          <div class="hash-panel" id="hp-identify">
            <p style="font-size:13px;color:var(--muted);margin-bottom:12px">Paste a hash above and we will identify the algorithm by length, format, and prefix patterns.</p>
            <button class="btn-scan" id="identify-go">Identify Hash</button>
          </div>

          <!-- Mode: Crack -->
          <div class="hash-panel" id="hp-crack">
            <div class="hash-alg-strip">
              <span class="hash-alg-label">Algorithm</span>
              <button class="hash-alg-btn active" data-alg="auto">Auto</button>
              <button class="hash-alg-btn" data-alg="md5">MD5</button>
              <button class="hash-alg-btn" data-alg="sha1">SHA-1</button>
              <button class="hash-alg-btn" data-alg="sha256">SHA-256</button>
              <button class="hash-alg-btn" data-alg="sha512">SHA-512</button>
            </div>
            <div id="crack-rt-status" style="margin-bottom:12px"></div>
            <button class="btn-scan" id="crack-go">Crack Hash</button>
          </div>

          <!-- Output -->
          <div id="hash-output" style="margin-top:20px"></div>
        </div>

      </div>
    </section>

    <section class="tab-panel" id="tab-testlab">
      <div class="panel-header">
        <h2>Test Lab</h2>
        <p>Embed detection signatures into a real file — then upload it to File Scanner to verify each detection category fires correctly</p>
      </div>
      <div class="panel-body">
        <div class="scan-form">

          <div class="field-row">
            <label>Base File <span class="hint">(your real file — modified in-browser only, never sent anywhere)</span></label>
            <div class="file-drop" id="inject-drop">
              <input type="file" id="inject-file-input" class="file-input-overlay">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="32"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17,8 12,3 7,8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
              <span>Drop your base file here or <span class="link">browse</span></span>
              <div class="file-name" id="inject-file-name"></div>
            </div>
          </div>

          <div class="field-row" id="inject-options" style="display:none">
            <label>Injection Payloads <span class="hint">(greyed = not applicable to detected file type)</span></label>
            <div class="inject-grid" id="inject-grid"></div>
          </div>

          <div class="field-row field-row--inline" id="inject-spoof-row" style="display:none">
            <label>Extension Spoof</label>
            <select id="inject-spoof-ext">
              <option value="">None — keep original extension</option>
              <option value=".pdf">Rename → .pdf</option>
              <option value=".doc">Rename → .doc</option>
              <option value=".txt">Rename → .txt</option>
              <option value=".jpg">Rename → .jpg</option>
              <option value=".png">Rename → .png</option>
            </select>
          </div>

          <button class="btn-scan" id="btn-inject" style="display:none">Inject &amp; Download</button>
        </div>

        <div id="inject-status"></div>
      </div>
    </section>

  </div><!-- .content-wrap -->
  </main>
</div>
<?php endif; ?>

<script src="/assets/js/app.js"></script>
</body>
</html>
