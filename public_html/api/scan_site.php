<?php
require_once __DIR__ . '/auth.php';
require_auth();
verify_csrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    json_out(['error' => 'POST required']);
}

$raw = trim($_POST['url'] ?? '');
if (!$raw) json_out(['error' => 'URL required']);
if (!filter_var($raw, FILTER_VALIDATE_URL)) json_out(['error' => 'Invalid URL']);

$parts  = parse_url($raw);
$base   = $parts['scheme'] . '://' . $parts['host'];
$domain = $parts['host'];

$results = [
    'target'     => $base,
    'domain'     => $domain,
    'wordpress'  => [],
    'headers'    => [],
    'ssl'        => null,
    'exposed'    => [],
    'missing'    => [],
    'findings'   => [],
    'score'      => 100,
];

// ── Helper: probe a path ──────────────────────────────────────
function probe(string $base, string $path): array {
    $url = rtrim($base, '/') . $path;
    $ch  = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => HTTP_TIMEOUT,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT      => 'SecurityScanner/1.0',
        CURLOPT_HEADER         => true,
        CURLOPT_NOBODY         => false,
        CURLOPT_HTTPHEADER     => ['Accept: text/html,application/json'],
    ]);
    $resp   = curl_exec($ch);
    $code   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hsize  = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    $headers_raw = substr($resp, 0, $hsize);
    $body        = substr($resp, $hsize);
    return ['url' => $url, 'code' => $code, 'headers' => $headers_raw, 'body' => substr($body, 0, 2000)];
}

// ── WordPress endpoints ───────────────────────────────────────
$wp_checks = [
    ['path' => '/wp-json/',                       'label' => 'REST API root',            'risk' => 'info',   'msg' => 'Plugin fingerprint exposed via REST API namespaces'],
    ['path' => '/wp-json/wp/v2/users',            'label' => 'User enumeration',         'risk' => 'high',   'msg' => 'User list publicly readable — exposes usernames'],
    ['path' => '/wp-json/wp/v2/posts',            'label' => 'Posts endpoint',           'risk' => 'info',   'msg' => 'Post metadata publicly readable'],
    ['path' => '/wp-json/wp/v2/media',            'label' => 'Media endpoint',           'risk' => 'low',    'msg' => 'Media files + EXIF metadata exposed'],
    ['path' => '/wp-json/wp/v2/settings',         'label' => 'Settings endpoint',        'risk' => 'high',   'msg' => 'Site settings exposed (admin email may be visible)'],
    ['path' => '/wp-json/wc/v3/products',         'label' => 'WooCommerce products',     'risk' => 'medium', 'msg' => 'WooCommerce product data accessible'],
    ['path' => '/wp-json/wc/v3/customers',        'label' => 'WooCommerce customers',    'risk' => 'critical','msg' => 'Customer PII potentially exposed'],
    ['path' => '/wp-json/wc/v3/orders',           'label' => 'WooCommerce orders',       'risk' => 'critical','msg' => 'Order data potentially exposed'],
    ['path' => '/wp-admin/',                      'label' => 'wp-admin accessible',      'risk' => 'medium', 'msg' => 'Admin panel reachable publicly'],
    ['path' => '/wp-login.php',                   'label' => 'Login page exposed',       'risk' => 'medium', 'msg' => 'Login endpoint reachable — brute force target'],
    ['path' => '/xmlrpc.php',                     'label' => 'XML-RPC enabled',          'risk' => 'high',   'msg' => 'XML-RPC is a brute force and DDoS amplification vector'],
    ['path' => '/readme.html',                    'label' => 'readme.html exposed',      'risk' => 'medium', 'msg' => 'WordPress version number disclosed'],
    ['path' => '/license.txt',                    'label' => 'license.txt exposed',      'risk' => 'low',    'msg' => 'Minor version info disclosed'],
    ['path' => '/wp-content/debug.log',           'label' => 'debug.log exposed',        'risk' => 'critical','msg' => 'PHP error log publicly readable — may contain paths, credentials'],
    ['path' => '/wp-content/uploads/',            'label' => 'Uploads dir listing',      'risk' => 'medium', 'msg' => 'Directory listing on uploads folder'],
    ['path' => '/wp-config.php',                  'label' => 'wp-config.php',            'risk' => 'critical','msg' => 'Config file — if readable contains DB credentials'],
    ['path' => '/wp-config.php.bak',              'label' => 'wp-config.php.bak',        'risk' => 'critical','msg' => 'Config backup exposed'],
    ['path' => '/wp-config.php.old',              'label' => 'wp-config.php.old',        'risk' => 'critical','msg' => 'Config backup exposed'],
    ['path' => '/.env',                           'label' => '.env file',                'risk' => 'critical','msg' => 'Environment file may contain secrets/credentials'],
    ['path' => '/.git/config',                    'label' => '.git/config exposed',      'risk' => 'critical','msg' => 'Git repo config accessible — source code extraction possible'],
    ['path' => '/backup.zip',                     'label' => 'backup.zip',               'risk' => 'critical','msg' => 'Backup archive potentially downloadable'],
    ['path' => '/backup.sql',                     'label' => 'backup.sql',               'risk' => 'critical','msg' => 'SQL dump potentially downloadable'],
    ['path' => '/phpmyadmin/',                    'label' => 'phpMyAdmin',               'risk' => 'high',   'msg' => 'Database admin panel exposed publicly'],
    ['path' => '/adminer.php',                    'label' => 'Adminer exposed',          'risk' => 'high',   'msg' => 'Database admin tool exposed publicly'],
    ['path' => '/robots.txt',                     'label' => 'robots.txt',               'risk' => 'info',   'msg' => 'Check for hidden paths listed in Disallow'],
    ['path' => '/sitemap.xml',                    'label' => 'Sitemap',                  'risk' => 'info',   'msg' => 'All indexed URLs listed'],
    ['path' => '/?author=1',                      'label' => 'Author enum (?author=1)',  'risk' => 'medium', 'msg' => 'Username leakage via author parameter redirect'],
];

$score_deductions = ['critical' => 25, 'high' => 15, 'medium' => 8, 'low' => 3, 'info' => 0];

foreach ($wp_checks as $check) {
    $r = probe($base, $check['path']);
    $open = in_array($r['code'], [200, 301, 302]) && $r['code'] !== 403 && $r['code'] !== 404;

    // Special case: author redirect leaks username
    if ($check['path'] === '/?author=1' && $r['code'] === 301) {
        preg_match('/Location:\s*(.*)/i', $r['headers'], $loc);
        $open = !empty($loc[1]) && strpos($loc[1], '/author/') !== false;
    }
    // XML-RPC: 200 or 405 = enabled
    if ($check['path'] === '/xmlrpc.php') {
        $open = in_array($r['code'], [200, 405]);
    }

    $entry = [
        'path'   => $check['path'],
        'label'  => $check['label'],
        'code'   => $r['code'],
        'open'   => $open,
        'risk'   => $check['risk'],
        'msg'    => $check['msg'],
        'url'    => $r['url'],
    ];

    // Sniff WP version from body if readme is open
    if ($check['path'] === '/readme.html' && $open) {
        preg_match('/Version\s+([\d.]+)/i', $r['body'], $v);
        if (!empty($v[1])) $entry['version_disclosed'] = $v[1];
    }
    // Sniff REST API namespaces
    if ($check['path'] === '/wp-json/' && $open) {
        $api = json_decode($r['body'], true);
        $entry['namespaces'] = $api['namespaces'] ?? [];
        $entry['site_name']  = $api['name'] ?? null;
    }

    $results['wordpress'][] = $entry;

    if ($open && $check['risk'] !== 'info') {
        $results['findings'][] = ['type' => 'wordpress', 'detail' => "{$check['label']}: {$check['msg']}", 'severity' => $check['risk'], 'url' => $r['url']];
        $results['score'] -= $score_deductions[$check['risk']] ?? 0;
    }
}
$results['score'] = max(0, $results['score']);

// ── HTTP security headers ─────────────────────────────────────
$head = probe($base, '/');
$raw_headers = strtolower($head['headers']);
$header_checks = [
    'strict-transport-security' => ['name' => 'HSTS',                  'risk' => 'medium'],
    'x-frame-options'           => ['name' => 'X-Frame-Options',       'risk' => 'medium'],
    'x-content-type-options'    => ['name' => 'X-Content-Type-Options', 'risk' => 'low'],
    'content-security-policy'   => ['name' => 'Content-Security-Policy','risk' => 'medium'],
    'referrer-policy'           => ['name' => 'Referrer-Policy',        'risk' => 'low'],
    'permissions-policy'        => ['name' => 'Permissions-Policy',     'risk' => 'low'],
];

// Server/version headers that should NOT be present
$leaky_headers = ['server', 'x-powered-by', 'x-generator', 'x-wordpress-cache'];
foreach ($leaky_headers as $h) {
    if (preg_match("/$h:\s*([^\r\n]+)/i", $head['headers'], $m)) {
        $results['headers'][] = ['header' => $h, 'value' => trim($m[1]), 'present' => true, 'risk' => 'low', 'note' => 'Version info leaks server fingerprint'];
        $results['findings'][] = ['type' => 'headers', 'detail' => "Server leaks: $h: " . trim($m[1]), 'severity' => 'low'];
    }
}

foreach ($header_checks as $hdr => $info) {
    $present = strpos($raw_headers, $hdr . ':') !== false;
    $results['headers'][] = ['header' => $hdr, 'name' => $info['name'], 'present' => $present, 'risk' => $present ? 'none' : $info['risk']];
    if (!$present) {
        $results['missing'][]  = $info['name'];
        $results['findings'][] = ['type' => 'headers', 'detail' => "Missing security header: {$info['name']}", 'severity' => $info['risk']];
        $results['score'] -= $score_deductions[$info['risk']] ?? 0;
    }
}
$results['score'] = max(0, $results['score']);

// ── SSL certificate info ──────────────────────────────────────
if ($parts['scheme'] === 'https') {
    $ssl_ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'verify_peer' => true, 'verify_peer_name' => true]]);
    $ssl_sock = @stream_socket_client("ssl://$domain:443", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ssl_ctx);
    if ($ssl_sock) {
        $cert_info = stream_context_get_params($ssl_sock);
        $cert = openssl_x509_parse($cert_info['options']['ssl']['peer_certificate'] ?? '');
        if ($cert) {
            $expires    = $cert['validTo_time_t'] ?? 0;
            $days_left  = (int)(($expires - time()) / 86400);
            $results['ssl'] = [
                'valid'       => $days_left > 0,
                'days_left'   => $days_left,
                'issuer'      => $cert['issuer']['O'] ?? 'Unknown',
                'subject'     => $cert['subject']['CN'] ?? $domain,
                'expires'     => date('Y-m-d', $expires),
                'san'         => $cert['extensions']['subjectAltName'] ?? '',
            ];
            if ($days_left < 14) {
                $results['findings'][] = ['type' => 'ssl', 'detail' => "SSL certificate expires in $days_left days!", 'severity' => 'high'];
            }
        }
        fclose($ssl_sock);
    }
}

// ── Log ───────────────────────────────────────────────────────
$log = date('Y-m-d H:i:s') . ' | SITE | ' . $base . ' | score=' . $results['score'] . ' | findings=' . count($results['findings']) . PHP_EOL;
@file_put_contents(LOG_DIR . 'scans.log', $log, FILE_APPEND | LOCK_EX);

json_out($results);
