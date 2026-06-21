<?php
require_once __DIR__ . '/auth.php';
require_auth();
verify_csrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    json_out(['error' => 'POST required']);
}

$start_url = trim($_POST['url']   ?? '');
$depth     = min((int)($_POST['depth'] ?? 2), MAX_CRAWL_DEPTH);
$mode      = trim($_POST['mode']  ?? 'crawl'); // crawl | probe

if (!$start_url) json_out(['error' => 'URL required']);
if (!filter_var($start_url, FILTER_VALIDATE_URL)) json_out(['error' => 'Invalid URL']);

$parts   = parse_url($start_url);
$base    = $parts['scheme'] . '://' . $parts['host'];
$domain  = $parts['host'];

$results = [
    'target'    => $start_url,
    'base'      => $base,
    'crawled'   => [],
    'probed'    => [],
    'findings'  => [],
    'endpoints' => [],
    'stats'     => ['total' => 0, 'ok' => 0, 'redirect' => 0, 'forbidden' => 0, 'not_found' => 0, 'error' => 0],
];

// ── Common sensitive/interesting paths to probe ───────────────
$probe_paths = [
    // Credentials & config
    '/.env', '/.env.local', '/.env.production', '/.env.backup',
    '/config.php', '/config.yml', '/config.json', '/configuration.php',
    '/settings.php', '/wp-config.php', '/wp-config.php.bak',
    '/web.config', '/appsettings.json',
    // Backups
    '/backup.zip', '/backup.tar.gz', '/backup.sql', '/dump.sql',
    '/db.sql', '/database.sql', '/site.zip', '/www.zip',
    // Admin panels
    '/admin/', '/admin/login', '/admin/index.php', '/administrator/',
    '/wp-admin/', '/wp-login.php', '/phpmyadmin/', '/pma/',
    '/adminer.php', '/adminer/', '/manager/', '/cpanel/',
    // Dev/debug
    '/.git/config', '/.git/HEAD', '/.git/index',
    '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
    '/wp-content/debug.log', '/error_log', '/php_errorlog',
    // Exposed files
    '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
    '/readme.html', '/readme.txt', '/changelog.txt', '/license.txt',
    '/crossdomain.xml', '/clientaccesspolicy.xml',
    // API endpoints
    '/api/', '/api/v1/', '/api/v2/', '/api/v3/',
    '/graphql', '/graphiql', '/__graphql',
    '/swagger.json', '/swagger.yaml', '/openapi.json', '/api-docs',
    // WordPress specific
    '/xmlrpc.php', '/wp-json/', '/wp-cron.php',
    '/wp-content/uploads/', '/wp-includes/',
    '/?author=1', '/?author=2',
    // Laravel / common frameworks
    '/.env', '/storage/logs/laravel.log', '/storage/logs/',
    '/_profiler/', '/app_dev.php',
    // Server files
    '/.htaccess', '/.htpasswd', '/web.config',
    '/server-status', '/server-info',
];

// ── Fetch a URL and return metadata ──────────────────────────
function fetch_url(string $url): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => HTTP_TIMEOUT,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HEADER         => true,
        CURLOPT_USERAGENT      => 'SecurityScanner/1.0',
    ]);
    $resp   = curl_exec($ch);
    $code   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hsize  = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $type   = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $size   = curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD);
    curl_close($ch);
    $body   = substr($resp, $hsize);
    $hdrs   = substr($resp, 0, $hsize);
    return ['code' => $code, 'type' => $type, 'size' => $size, 'body' => substr($body, 0, 5000), 'headers' => $hdrs];
}

// ── Extract links from HTML body ─────────────────────────────
function extract_links(string $body, string $base): array {
    $links = [];
    $base_parts = parse_url($base);
    $base_origin = $base_parts['scheme'] . '://' . $base_parts['host'];

    preg_match_all('/(href|src|action|data-url)\s*=\s*["\']([^"\']+)["\']/', $body, $m);
    foreach ($m[2] as $href) {
        $href = trim($href);
        if (!$href || $href[0] === '#' || substr($href, 0, 7) === 'mailto:' || substr($href, 0, 11) === 'javascript:') continue;
        if (substr($href, 0, 2) === '//') $href = $base_parts['scheme'] . ':' . $href;
        if ($href[0] === '/') $href = $base_origin . $href;
        if (substr($href, 0, 4) !== 'http') $href = $base . '/' . ltrim($href, '/');
        if (parse_url($href, PHP_URL_HOST) !== $base_parts['host']) continue; // stay on domain
        $links[] = strtok($href, '#');
    }

    // Also extract from JS fetch/axios/XMLHttpRequest patterns
    preg_match_all('/["\']((\/[a-zA-Z0-9_\-\/]+|https?:\/\/[^\s"\']+))["\']/', $body, $js);
    foreach ($js[1] as $jsurl) {
        if (substr($jsurl, 0, 1) === '/') $jsurl = $base_origin . $jsurl;
        if (parse_url($jsurl, PHP_URL_HOST) !== $base_parts['host']) continue;
        $links[] = $jsurl;
    }

    return array_unique($links);
}

// ── Classify findings ─────────────────────────────────────────
function classify_finding(string $path, int $code): ?array {
    $critical = ['/.env', '/.git/config', '/wp-config.php', '/backup.zip', '/backup.sql', '/dump.sql', '/phpinfo.php', '/wp-content/debug.log', '/.htpasswd'];
    $high     = ['/phpmyadmin/', '/adminer.php', '/xmlrpc.php', '/.git/HEAD', '/server-status', '/graphql'];
    $medium   = ['/wp-admin/', '/admin/', '/wp-login.php', '/wp-json/wp/v2/users', '/swagger.json', '/api-docs'];

    if ($code === 200 || $code === 301 || $code === 302) {
        foreach ($critical as $p) { if (strpos($path, $p) !== false) return ['severity' => 'critical', 'note' => 'Sensitive file accessible']; }
        foreach ($high     as $p) { if (strpos($path, $p) !== false) return ['severity' => 'high',     'note' => 'High-risk endpoint accessible']; }
        foreach ($medium   as $p) { if (strpos($path, $p) !== false) return ['severity' => 'medium',   'note' => 'Admin/sensitive endpoint accessible']; }
    }
    return null;
}

// ── Mode: Probe — hit common paths, report status ────────────
if ($mode === 'probe') {
    foreach ($probe_paths as $path) {
        if (count($results['probed']) >= MAX_CRAWL_URLS) break;
        $url  = $base . $path;
        $r    = fetch_url($url);
        $code = $r['code'];

        $results['stats']['total']++;
        if      ($code >= 500)                            $results['stats']['error']++;
        elseif  ($code === 404)                           $results['stats']['not_found']++;
        elseif  ($code === 403)                           $results['stats']['forbidden']++;
        elseif  (in_array($code, [301, 302, 307, 308]))  $results['stats']['redirect']++;
        elseif  ($code === 200)                           $results['stats']['ok']++;

        $entry = ['url' => $url, 'path' => $path, 'code' => $code, 'type' => $r['type'], 'size' => $r['size']];

        $finding = classify_finding($path, $code);
        if ($finding) {
            $entry['severity'] = $finding['severity'];
            $results['findings'][] = ['type' => 'probe', 'detail' => "{$path} returned HTTP $code — {$finding['note']}", 'severity' => $finding['severity'], 'url' => $url];
        }

        // Only record non-404 results to keep output clean
        if ($code !== 404) {
            $results['probed'][] = $entry;
            $results['endpoints'][] = $url;
        }
    }
}

// ── Mode: Crawl — spider HTML links from start URL ───────────
if ($mode === 'crawl') {
    $queue   = [$start_url];
    $visited = [];
    $current_depth = 0;
    $depth_markers = [$start_url => 0];

    while (!empty($queue) && count($results['crawled']) < MAX_CRAWL_URLS) {
        $url  = array_shift($queue);
        $url  = strtok($url, '?'); // strip query strings for dedup
        if (isset($visited[$url])) continue;
        $visited[$url] = true;

        $current_depth = $depth_markers[$url] ?? 0;
        if ($current_depth > $depth) continue;

        $r    = fetch_url($url);
        $code = $r['code'];

        $results['stats']['total']++;
        if      ($code >= 500)                           $results['stats']['error']++;
        elseif  ($code === 404)                          $results['stats']['not_found']++;
        elseif  ($code === 403)                          $results['stats']['forbidden']++;
        elseif  (in_array($code, [301,302,307,308]))     $results['stats']['redirect']++;
        elseif  ($code === 200)                          $results['stats']['ok']++;

        $path    = parse_url($url, PHP_URL_PATH) ?? '/';
        $finding = classify_finding($path, $code);
        $entry   = ['url' => $url, 'code' => $code, 'type' => $r['type'], 'depth' => $current_depth];
        if ($finding) {
            $entry['severity'] = $finding['severity'];
            $results['findings'][] = ['type' => 'crawl', 'detail' => "{$path} HTTP $code — {$finding['note']}", 'severity' => $finding['severity'], 'url' => $url];
        }
        $results['crawled'][]  = $entry;
        $results['endpoints'][] = $url;

        // Queue new links from HTML pages
        if ($code === 200 && strpos($r['type'] ?? '', 'html') !== false && $current_depth < $depth) {
            $links = extract_links($r['body'], $base);
            foreach ($links as $link) {
                $clean = strtok($link, '?');
                if (!isset($visited[$clean]) && !isset($depth_markers[$clean])) {
                    $depth_markers[$clean] = $current_depth + 1;
                    $queue[] = $link;
                }
            }
        }
    }

    $results['endpoints'] = array_unique($results['endpoints']);
}

// ── Log ───────────────────────────────────────────────────────
$log = date('Y-m-d H:i:s') . " | CRAWL | $start_url | mode=$mode | total={$results['stats']['total']} | findings=" . count($results['findings']) . PHP_EOL;
@file_put_contents(LOG_DIR . 'scans.log', $log, FILE_APPEND | LOCK_EX);

json_out($results);
