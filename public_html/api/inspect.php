<?php
require_once __DIR__ . '/auth.php';
require_auth();
verify_csrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    json_out(['error' => 'POST required']);
}

$raw_url = trim($_POST['url'] ?? '');
$scan_js = !empty($_POST['scan_js']) && $_POST['scan_js'] !== '0';

if (!$raw_url) json_out(['error' => 'URL required']);
if (!filter_var($raw_url, FILTER_VALIDATE_URL)) json_out(['error' => 'Invalid URL']);

$parts = parse_url($raw_url);
if (!in_array($parts['scheme'] ?? '', ['http', 'https'])) json_out(['error' => 'Only http/https allowed']);

$base_origin = $parts['scheme'] . '://' . $parts['host'];

$results = [
    'url'              => $raw_url,
    'domain'           => $parts['host'],
    'headers'          => [],
    'header_issues'    => [],
    'cookies'          => [],
    'cookie_issues'    => [],
    'cors'             => null,
    'credentials'      => [],
    'api_endpoints'    => [],
    'js_files'         => [],
    'comments'         => [],
    'emails'           => [],
    'internal_ips'     => [],
    'source_maps'      => [],
    'outdated_libs'    => [],
    'dom_xss'          => [],
    'error_disclosures'=> [],
    'url_param_leaks'  => [],
    'mixed_content'    => [],
    'sri_missing'      => [],
    'insecure_forms'   => [],
    'autocomplete'     => [],
    'cache_issues'     => [],
    'http_methods'     => null,
    'localstorage'     => [],
    'postmessage'      => [],
    'backup_links'     => [],
    'internal_hosts'   => [],
    'findings'         => [],
    'severity'         => 'low',
];

// ── Credential / secret patterns ─────────────────────────────
$cred_patterns = [
    'AWS Access Key'        => '/\b(AKIA[0-9A-Z]{16})\b/',
    'AWS Secret Key'        => '/aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[\s]*[=:]\s*["\']?([A-Za-z0-9\/+=]{40})["\']?/i',
    'Google API Key'        => '/(AIza[0-9A-Za-z\-_]{35})/',
    'Stripe Live Secret'    => '/(sk_live_[0-9a-zA-Z]{24,})/',
    'Stripe Live Public'    => '/(pk_live_[0-9a-zA-Z]{24,})/',
    'Stripe Test Secret'    => '/(sk_test_[0-9a-zA-Z]{24,})/',
    'Twilio Account SID'    => '/(AC[a-zA-Z0-9]{32})/',
    'Twilio Auth Token'     => '/twilio[^=\n]*=[^=\n]*([a-zA-Z0-9]{32})/i',
    'SendGrid API Key'      => '/(SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43})/',
    'GitHub Token'          => '/(gh[pousr]_[A-Za-z0-9_]{36,})/',
    'JWT Token'             => '/(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_\+\/=]*)/',
    'Bearer Token'          => '/["\s]bearer\s+([A-Za-z0-9\-_\.]{20,})/i',
    'Basic Auth (encoded)'  => '/["\s]basic\s+([A-Za-z0-9+\/=]{10,})/i',
    'Private Key'           => '/(-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY)/',
    'Password in code'      => '/["\s\'`]password["\s\'`]?\s*[:=]\s*["\']([^"\']{4,50})["\'](?!\s*\+)/i',
    'API Key in code'       => '/["\s\'`]api[_\-]?key["\s\'`]?\s*[:=]\s*["\']([a-zA-Z0-9\-_]{16,})["\'](?!\s*\+)/i',
    'Secret in code'        => '/["\s\'`](?:app[_\-]?)?secret["\s\'`]?\s*[:=]\s*["\']([^"\']{8,50})["\'](?!\s*\+)/i',
    'Token in code'         => '/["\s\'`](?:auth[_\-]?)?token["\s\'`]?\s*[:=]\s*["\']([a-zA-Z0-9\-_\.]{20,})["\'](?!\s*\+)/i',
    'Database password'     => '/(?:db|database)[_\-]?pass(?:word)?["\s\'`]?\s*[:=]\s*["\']([^"\']{4,50})["\'](?!\s*\+)/i',
    'Connection string'     => '/(?:mysql|postgres|mongodb|redis):\/\/[^:]+:([^@]{4,50})@/i',
];

// ── API endpoint patterns ─────────────────────────────────────
$endpoint_patterns = [
    '/fetch\s*\(\s*["\']((\/[a-zA-Z0-9_\-\/\?=&%]+))["\']/',
    '/axios\.[a-z]+\s*\(\s*["\']((\/[a-zA-Z0-9_\-\/\?=&%]+))["\']/',
    '/\$\.(?:get|post|ajax)\s*\(\s*["\']((\/[a-zA-Z0-9_\-\/\?=&%]+))["\']/',
    '/XMLHttpRequest[^;]*open\s*\([^,]+,\s*["\']((\/[a-zA-Z0-9_\-\/\?=&%]+))["\']/',
    '/(?:url|endpoint|baseUrl|apiUrl)\s*[:=]\s*["\']((https?:\/\/[a-zA-Z0-9._\-\/]+|\/[a-zA-Z0-9_\-\/]+))["\']/',
    '/route\s*\(\s*["\']((\/[a-zA-Z0-9_\-\/:]+))["\']/',
];

// ── Internal IP pattern ───────────────────────────────────────
$internal_ip_pattern = '/\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/';

// ── Outdated library CVE table ────────────────────────────────
$known_vuln_libs = [
    'jquery' => [
        'name'     => 'jQuery',
        'patterns' => ['/jquery[.\-v](\d+\.\d+\.?\d*)/i', '/jQuery\s+v(\d+\.\d+\.?\d*)/i'],
        'vulns'    => [
            ['below' => '3.5.0', 'severity' => 'high',     'cve' => 'CVE-2020-11022/11023', 'issue' => 'XSS via HTML manipulation methods'],
            ['below' => '3.4.0', 'severity' => 'high',     'cve' => 'CVE-2019-11358',        'issue' => 'Prototype pollution via $.extend'],
            ['below' => '1.9.0', 'severity' => 'medium',   'cve' => 'CVE-2012-6708',         'issue' => 'XSS via crafted selector string'],
        ],
    ],
    'bootstrap' => [
        'name'     => 'Bootstrap',
        'patterns' => ['/bootstrap[.\-v](\d+\.\d+\.?\d*)/i', '/Bootstrap\s+v(\d+\.\d+\.?\d*)/i'],
        'vulns'    => [
            ['below' => '4.3.1', 'severity' => 'high',     'cve' => 'CVE-2019-8331',  'issue' => 'XSS via data-template in tooltip/popover'],
            ['below' => '3.4.1', 'severity' => 'high',     'cve' => 'CVE-2018-14041', 'issue' => 'XSS via data-target attribute'],
            ['below' => '3.4.0', 'severity' => 'medium',   'cve' => 'CVE-2018-20677', 'issue' => 'XSS via data-container attribute'],
        ],
    ],
    'angularjs' => [
        'name'     => 'AngularJS',
        'patterns' => ['/angular[.\-v](\d+\.\d+\.?\d*)/i', '/AngularJS\s+v(\d+\.\d+\.?\d*)/i'],
        'vulns'    => [
            ['below' => '1.8.3', 'severity' => 'medium',   'cve' => 'CVE-2022-25869', 'issue' => 'XSS via SVG animate element'],
            ['below' => '1.7.9', 'severity' => 'high',     'cve' => 'CVE-2019-14863', 'issue' => 'Prototype pollution via merge'],
        ],
    ],
    'lodash' => [
        'name'     => 'Lodash',
        'patterns' => ['/lodash[.\-v](\d+\.\d+\.?\d*)/i', '/Lodash\s+(\d+\.\d+\.?\d*)/i'],
        'vulns'    => [
            ['below' => '4.17.21', 'severity' => 'high',     'cve' => 'CVE-2021-23337', 'issue' => 'Command injection via template function'],
            ['below' => '4.17.20', 'severity' => 'high',     'cve' => 'CVE-2020-28500', 'issue' => 'ReDoS via string methods'],
            ['below' => '4.17.19', 'severity' => 'critical', 'cve' => 'CVE-2020-8203',  'issue' => 'Prototype pollution via zipObjectDeep'],
        ],
    ],
    'moment' => [
        'name'     => 'Moment.js',
        'patterns' => ['/moment[.\-v](\d+\.\d+\.?\d*)/i', '/moment\.js\s+v(\d+\.\d+\.?\d*)/i'],
        'vulns'    => [
            ['below' => '2.29.4', 'severity' => 'high',     'cve' => 'CVE-2022-31129', 'issue' => 'ReDoS via specially crafted date string'],
            ['below' => '2.29.2', 'severity' => 'medium',   'cve' => 'CVE-2022-24785', 'issue' => 'Path traversal via locale switching'],
        ],
    ],
    'handlebars' => [
        'name'     => 'Handlebars.js',
        'patterns' => ['/handlebars[.\-v](\d+\.\d+\.?\d*)/i', '/Handlebars\s+v(\d+\.\d+\.?\d*)/i'],
        'vulns'    => [
            ['below' => '4.7.7', 'severity' => 'critical', 'cve' => 'CVE-2021-23369', 'issue' => 'Prototype pollution leading to RCE via template'],
            ['below' => '4.7.6', 'severity' => 'critical', 'cve' => 'CVE-2019-19919', 'issue' => 'Prototype pollution in compiler'],
        ],
    ],
    'underscore' => [
        'name'     => 'Underscore.js',
        'patterns' => ['/underscore[.\-v](\d+\.\d+\.?\d*)/i'],
        'vulns'    => [
            ['below' => '1.13.0', 'severity' => 'high', 'cve' => 'CVE-2021-23358', 'issue' => 'Arbitrary code execution via template function'],
        ],
    ],
    'vue' => [
        'name'     => 'Vue.js',
        'patterns' => ['/[^a-z]vue[.\-v](\d+\.\d+\.?\d*)/i', '/Vue\.js\s+v(\d+\.\d+\.?\d*)/i'],
        'vulns'    => [
            ['below' => '2.6.13', 'severity' => 'medium', 'cve' => 'CVE-2021-22929', 'issue' => 'XSS via v-bind:href with unsanitized user input'],
        ],
    ],
];

// ── DOM XSS sink patterns ─────────────────────────────────────
$dom_xss_patterns = [
    'innerHTML assignment'    => '/\.innerHTML\s*[+]?=(?!\s*["\'][^"\'<]{0,5}["\'])/m',
    'outerHTML assignment'    => '/\.outerHTML\s*[+]?=(?!\s*["\'][^"\'<]{0,5}["\'])/m',
    'document.write'          => '/document\.write(?:ln)?\s*\(/m',
    'eval() call'             => '/\beval\s*\(/m',
    'setTimeout with string'  => '/setTimeout\s*\(\s*["\'][^"\']{5,}/m',
    'setInterval with string' => '/setInterval\s*\(\s*["\'][^"\']{5,}/m',
    'location.href assign'    => '/\blocation\.href\s*=/m',
    'location.assign()'       => '/\blocation\.assign\s*\(/m',
    'location.replace()'      => '/\blocation\.replace\s*\(/m',
    'document.domain assign'  => '/\bdocument\.domain\s*=/m',
    'insertAdjacentHTML'      => '/\.insertAdjacentHTML\s*\(/m',
];

// ── Error / stack trace patterns ──────────────────────────────
$error_patterns = [
    'PHP Fatal Error'         => ['pattern' => '/Fatal error:\s*[^\n<]{10,200}/i',                                          'severity' => 'critical'],
    'PHP Warning'             => ['pattern' => '/Warning:\s+[^\n<]{10,200}/i',                                              'severity' => 'high'],
    'PHP Notice'              => ['pattern' => '/Notice:\s+[^\n<]{10,200}/i',                                               'severity' => 'medium'],
    'PHP Parse Error'         => ['pattern' => '/Parse error:\s*[^\n<]{10,200}/i',                                          'severity' => 'high'],
    'PHP Uncaught Exception'  => ['pattern' => '/Uncaught\s+\w+Exception[:\s][^\n<]{10,200}/i',                             'severity' => 'high'],
    'PHP Stack Trace'         => ['pattern' => '/Stack trace:\s*\n#\d/i',                                                   'severity' => 'high'],
    'Python Traceback'        => ['pattern' => '/Traceback \(most recent call last\):/i',                                   'severity' => 'high'],
    'Python File Path'        => ['pattern' => '/File "\/[^"]{5,100}", line \d+/i',                                        'severity' => 'medium'],
    'Java Stack Trace'        => ['pattern' => '/at (?:com|org|java|sun|net)\.[a-zA-Z0-9.]+\([^)]+\.java:\d+\)/i',         'severity' => 'medium'],
    'Java Exception Class'    => ['pattern' => '/(?:java\.lang|java\.io|javax)\.\w+Exception/i',                           'severity' => 'medium'],
    'SQL Error (MySQL)'       => ['pattern' => '/You have an error in your SQL syntax/i',                                   'severity' => 'critical'],
    'SQL Error (PDO/SQLSTATE)'=> ['pattern' => '/SQLSTATE\[\w+\][^<]{5,100}/i',                                            'severity' => 'critical'],
    'SQL Error (PostgreSQL)'  => ['pattern' => '/pg_query\(\): Query failed:/i',                                            'severity' => 'critical'],
    'SQL Error (Oracle)'      => ['pattern' => '/ORA-\d{5}:/i',                                                            'severity' => 'critical'],
    'SQL Error (MSSQL)'       => ['pattern' => '/Microsoft OLE DB Provider for SQL Server/i',                              'severity' => 'critical'],
    'ASP.NET Error Page'      => ['pattern' => '/Server Error in .{0,60} Application\./i',                                 'severity' => 'high'],
    'ASP.NET Exception'       => ['pattern' => '/System\.\w+(?:Exception|Error)/i',                                        'severity' => 'high'],
    'Ruby on Rails Error'     => ['pattern' => '/ActionController::\w+Error/i',                                            'severity' => 'medium'],
    'Node.js Stack Trace'     => ['pattern' => '/at Object\.<anonymous>\s*\([^)]+\.js:\d+:\d+\)/i',                        'severity' => 'medium'],
    'Laravel Exception'       => ['pattern' => '/Illuminate\\\\\w+\\\\\w+Exception/i',                                    'severity' => 'high'],
    'WordPress DB Error'      => ['pattern' => '/WordPress database error.*for query/i',                                   'severity' => 'critical'],
    'Symfony Debug Bar'       => ['pattern' => '/sf-toolbar|symfony-toolbar|sfdt-/i',                                      'severity' => 'medium'],
    'Django Debug Page'       => ['pattern' => '/Django Version:|Request Method:|Request URL:|Exception Type:/i',          'severity' => 'high'],
];

// ── Sensitive URL parameter names ─────────────────────────────
$sensitive_url_params = [
    'token', 'access_token', 'auth_token', 'id_token', 'refresh_token',
    'key', 'api_key', 'apikey', 'api-key',
    'password', 'passwd', 'pwd', 'pass',
    'secret', 'client_secret',
    'auth', 'authorization',
    'private_key', 'private-key',
    'session', 'sess',
    'credential', 'credentials',
    'sig', 'signature', 'hmac',
];

// ── Fetch with full header capture ───────────────────────────
function full_fetch(string $url, int $timeout = 10): array {
    $response_headers = [];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
        CURLOPT_HEADERFUNCTION => function($ch, $header) use (&$response_headers) {
            $parts = explode(':', $header, 2);
            if (count($parts) === 2) {
                $response_headers[strtolower(trim($parts[0]))][] = trim($parts[1]);
            }
            return strlen($header);
        },
    ]);
    $body  = curl_exec($ch);
    $code  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $type  = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $final = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);
    return ['body' => $body ?: '', 'code' => $code, 'type' => $type, 'headers' => $response_headers, 'final_url' => $final];
}

// ── Scan text content for credentials + endpoints ────────────
function scan_content(string $content, string $source, array $cred_patterns, array $endpoint_patterns, string $internal_ip_pattern): array {
    $found = ['credentials' => [], 'endpoints' => [], 'internal_ips' => [], 'comments' => [], 'emails' => []];

    foreach ($cred_patterns as $label => $pattern) {
        if (preg_match_all($pattern, $content, $m)) {
            foreach (array_unique($m[1] ?? $m[0]) as $match) {
                $match = trim($match);
                if (strlen($match) < 4) continue;
                $display = strlen($match) > 12
                    ? substr($match, 0, 4) . str_repeat('*', min(strlen($match) - 8, 12)) . substr($match, -4)
                    : '****';
                $found['credentials'][] = ['type' => $label, 'value' => $display, 'source' => $source, 'raw_length' => strlen($match)];
            }
        }
    }

    foreach ($endpoint_patterns as $pattern) {
        if (preg_match_all($pattern, $content, $m)) {
            foreach (array_unique($m[1]) as $ep) {
                $ep = trim($ep);
                if (strlen($ep) > 2 && !in_array($ep, $found['endpoints'])) {
                    $found['endpoints'][] = $ep;
                }
            }
        }
    }

    if (preg_match_all($internal_ip_pattern, $content, $m)) {
        foreach (array_unique($m[1]) as $ip) {
            $found['internal_ips'][] = ['ip' => $ip, 'source' => $source];
        }
    }

    preg_match_all('/<!--([\s\S]{10,500}?)-->/m', $content, $cm);
    foreach ($cm[1] as $comment) {
        $c = trim($comment);
        if (preg_match('/(?:pass|key|secret|token|todo|fixme|hack|credential|remove|temp|debug|test)/i', $c)) {
            $found['comments'][] = ['text' => substr($c, 0, 300), 'source' => $source];
        }
    }
    preg_match_all('/\/\*([\s\S]{10,500}?)\*\//m', $content, $bc);
    foreach ($bc[1] as $comment) {
        $c = trim($comment);
        if (preg_match('/(?:pass|key|secret|token|todo|fixme|hack|credential)/i', $c)) {
            $found['comments'][] = ['text' => substr($c, 0, 300), 'source' => $source];
        }
    }

    preg_match_all('/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/', $content, $em);
    foreach (array_unique($em[0]) as $email) {
        if (!preg_match('/\.(png|jpg|gif|svg|woff|css|js)$/i', $email)) {
            $found['emails'][] = ['email' => $email, 'source' => $source];
        }
    }

    return $found;
}

// ── Check source map exposure ─────────────────────────────────
function check_source_map(string $js_body, string $js_url, string $base_origin): ?array {
    if (!preg_match('/\/\/[#@]\s*sourceMappingURL\s*=\s*([^\s\n\r]+)/i', $js_body, $m)) return null;
    $map_ref = trim($m[1]);
    if (strpos($map_ref, 'data:') === 0) return null;

    if (substr($map_ref, 0, 4) === 'http') {
        $map_url = $map_ref;
    } elseif ($map_ref[0] === '/') {
        $map_url = $base_origin . $map_ref;
    } else {
        $dir = substr($js_url, 0, strrpos($js_url, '/') + 1);
        $map_url = $dir . $map_ref;
    }

    $resp = full_fetch($map_url, 5);
    return [
        'js_url'     => $js_url,
        'map_url'    => $map_url,
        'accessible' => $resp['code'] === 200,
        'http_code'  => $resp['code'],
        'size_kb'    => $resp['code'] === 200 ? round(strlen($resp['body']) / 1024, 1) : null,
    ];
}

// ── Detect outdated libraries ─────────────────────────────────
function detect_lib_versions(string $content, string $source, array $known_vuln_libs): array {
    $found = [];
    foreach ($known_vuln_libs as $lib_key => $lib) {
        $detected_version = null;
        foreach ($lib['patterns'] as $pattern) {
            if (preg_match($pattern, $content, $m)) {
                $detected_version = $m[1];
                break;
            }
        }
        if (!$detected_version) continue;

        foreach ($lib['vulns'] as $vuln) {
            if (version_compare($detected_version, $vuln['below'], '<')) {
                $found[] = [
                    'library'  => $lib['name'],
                    'version'  => $detected_version,
                    'below'    => $vuln['below'],
                    'cve'      => $vuln['cve'],
                    'issue'    => $vuln['issue'],
                    'severity' => $vuln['severity'],
                    'source'   => $source,
                ];
                break; // report highest-severity vuln only (list is sorted worst-first)
            }
        }
    }
    return $found;
}

// ── Scan JS for DOM XSS sinks ─────────────────────────────────
function scan_dom_sinks(string $content, string $source, array $dom_xss_patterns): array {
    $found = [];
    $lines = explode("\n", $content);
    foreach ($dom_xss_patterns as $label => $pattern) {
        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach (array_slice($matches[0], 0, 3) as $match) {
                $line_num = substr_count(substr($content, 0, $match[1]), "\n") + 1;
                $line_text = trim($lines[$line_num - 1] ?? '');
                $found[] = [
                    'sink'    => $label,
                    'line'    => $line_num,
                    'context' => substr($line_text, 0, 150),
                    'source'  => $source,
                ];
            }
        }
    }
    return $found;
}

// ── Scan body for verbose errors / stack traces ───────────────
function scan_error_disclosure(string $body, string $source, array $error_patterns): array {
    $found = [];
    foreach ($error_patterns as $label => $info) {
        if (preg_match($info['pattern'], $body, $m)) {
            $found[] = [
                'type'     => $label,
                'excerpt'  => substr(strip_tags($m[0]), 0, 200),
                'severity' => $info['severity'],
                'source'   => $source,
            ];
        }
    }
    return $found;
}

// ── Check URL params + href attrs for credential leaks ────────
function check_url_params(string $final_url, string $body, array $sensitive_params): array {
    $leaks = [];
    $seen  = [];

    $check = function(string $url, string $context) use ($sensitive_params, &$leaks, &$seen) {
        $qs = parse_url($url, PHP_URL_QUERY);
        if (!$qs) return;
        parse_str($qs, $params);
        foreach ($params as $name => $value) {
            $lower = strtolower($name);
            if (!$value || strlen($value) < 4) continue;
            foreach ($sensitive_params as $sp) {
                if (strpos($lower, $sp) !== false) {
                    $key = $lower . ':' . substr($value, 0, 8);
                    if (!isset($seen[$key])) {
                        $seen[$key] = true;
                        $display = strlen($value) > 8
                            ? substr($value, 0, 4) . '****' . substr($value, -2)
                            : '****';
                        $leaks[] = [
                            'param'    => $name,
                            'value'    => $display,
                            'context'  => $context,
                            'url'      => $url,
                        ];
                    }
                    break;
                }
            }
        }
    };

    $check($final_url, 'Final URL (after redirects)');

    // Check href attributes in page body
    preg_match_all('/href=["\']([^"\']{10,500})["\']/', $body, $links);
    foreach (array_unique($links[1]) as $href) {
        if (strpos($href, '?') !== false) {
            $check($href, 'href attribute in page HTML');
        }
    }

    return $leaks;
}

// ── Fire OPTIONS request to check allowed HTTP methods ───────
function fetch_options(string $url, int $timeout = 8): array {
    $resp_headers = [];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CUSTOMREQUEST  => 'OPTIONS',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
        CURLOPT_HEADERFUNCTION => function($ch, $h) use (&$resp_headers) {
            $p = explode(':', $h, 2);
            if (count($p) === 2) $resp_headers[strtolower(trim($p[0]))][] = trim($p[1]);
            return strlen($h);
        },
    ]);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ['code' => $code, 'allow' => implode(', ', $resp_headers['allow'] ?? [])];
}

// ── Mixed content — HTTP resources loaded on HTTPS page ──────
function scan_mixed_content(string $body, string $scheme): array {
    if ($scheme !== 'https') return [];
    $found = [];
    $checks = [
        ['/<script[^>]+src=["\']http:\/\/([^"\'>\s]+)["\'][^>]*>/i',           'script src',  true],
        ['/<link[^>]+href=["\']http:\/\/([^"\'>\s]+)["\'][^>]*>/i',            'link href',   true],
        ['/<iframe[^>]+src=["\']http:\/\/([^"\'>\s]+)["\'][^>]*>/i',           'iframe src',  true],
        ['/<img[^>]+src=["\']http:\/\/([^"\'>\s]+)["\'][^>]*>/i',              'img src',     false],
        ['/<(?:audio|video)[^>]+src=["\']http:\/\/([^"\'>\s]+)["\'][^>]*>/i',  'media src',   false],
    ];
    foreach ($checks as [$pattern, $type, $active]) {
        if (preg_match_all($pattern, $body, $m, PREG_SET_ORDER)) {
            foreach ($m as $match) {
                $found[] = ['type' => $type, 'url' => 'http://' . $match[1], 'active' => $active, 'tag' => substr($match[0], 0, 150)];
            }
        }
    }
    return $found;
}

// ── SRI missing on external scripts / stylesheets ────────────
function scan_sri_missing(string $body, string $target_host): array {
    $found = [];
    if (preg_match_all('/<script[^>]+src=["\']https?:\/\/([^"\'\/]+)([^"\']*)["\'][^>]*>/i', $body, $m, PREG_SET_ORDER)) {
        foreach ($m as $tag) {
            $ext = $tag[1];
            if ($ext === $target_host || $ext === 'www.' . $target_host) continue;
            if (stripos($tag[0], 'integrity=') === false) {
                $found[] = ['type' => 'script', 'host' => $ext, 'url' => 'https://' . $ext . $tag[2], 'tag' => substr($tag[0], 0, 200)];
            }
        }
    }
    if (preg_match_all('/<link[^>]+href=["\']https?:\/\/([^"\'\/]+)([^"\']*)["\'][^>]*>/i', $body, $m, PREG_SET_ORDER)) {
        foreach ($m as $tag) {
            $ext = $tag[1];
            if ($ext === $target_host || $ext === 'www.' . $target_host) continue;
            if (stripos($tag[0], 'stylesheet') !== false && stripos($tag[0], 'integrity=') === false) {
                $found[] = ['type' => 'stylesheet', 'host' => $ext, 'url' => 'https://' . $ext . $tag[2], 'tag' => substr($tag[0], 0, 200)];
            }
        }
    }
    return $found;
}

// ── Insecure form actions (HTTPS page → HTTP POST target) ────
function scan_insecure_forms(string $body, string $scheme): array {
    if ($scheme !== 'https') return [];
    $found = [];
    if (preg_match_all('/<form[^>]*action=["\']http:\/\/([^"\']+)["\'][^>]*>/i', $body, $m, PREG_SET_ORDER)) {
        foreach ($m as $tag) {
            $found[] = ['action' => 'http://' . $tag[1], 'tag' => substr($tag[0], 0, 200)];
        }
    }
    return $found;
}

// ── Autocomplete missing on password / payment inputs ────────
function scan_autocomplete(string $body): array {
    $found = [];
    if (preg_match_all('/<input[^>]*type=["\']password["\'][^>]*>/i', $body, $m, PREG_SET_ORDER)) {
        foreach ($m as $tag) {
            if (!preg_match('/autocomplete=["\'](?:off|new-password|current-password)["\']/', $tag[0])) {
                $found[] = ['field_type' => 'password', 'tag' => substr($tag[0], 0, 200)];
            }
        }
    }
    if (preg_match_all('/<input[^>]*(?:name|id)=["\'][^"\']*(?:card|cc_|ccnum|credit|cvv|cvc|expir)[^"\']*["\'][^>]*>/i', $body, $m, PREG_SET_ORDER)) {
        foreach ($m as $tag) {
            if (!preg_match('/autocomplete=["\'](?:off|cc-[a-z-]+)["\']/', $tag[0])) {
                $found[] = ['field_type' => 'payment/card', 'tag' => substr($tag[0], 0, 200)];
            }
        }
    }
    return $found;
}

// ── localStorage/sessionStorage with sensitive key names ─────
function scan_localstorage(string $content, string $source): array {
    $found = [];
    $keys  = 'token|auth|password|passwd|pwd|secret|key|credential|session|email|private';
    if (preg_match_all("/(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"]($keys)['\"]/i", $content, $m, PREG_SET_ORDER)) {
        foreach ($m as $match) {
            $storage = stripos($match[0], 'sessionStorage') !== false ? 'sessionStorage' : 'localStorage';
            $found[] = ['storage' => $storage, 'key' => $match[1], 'source' => $source, 'context' => substr($match[0], 0, 100)];
        }
    }
    return $found;
}

// ── postMessage listeners without origin validation ──────────
function scan_postmessage(string $content, string $source): array {
    $found = [];
    if (!preg_match_all('/addEventListener\s*\(\s*["\']message["\']\s*,/i', $content, $m, PREG_OFFSET_CAPTURE)) return [];
    foreach ($m[0] as $listener) {
        $ctx        = substr($content, $listener[1], 600);
        $has_origin = (bool) preg_match('/["\']?\.?origin\s*[!=]==?\s*["\']|\.origin\b/i', $ctx);
        $found[]    = ['has_origin_check' => $has_origin, 'source' => $source, 'context' => substr(trim($listener[0]), 0, 100)];
    }
    return $found;
}

// ── Backup / temp file links in HTML ─────────────────────────
function scan_backup_links(string $body): array {
    $found   = [];
    $pattern = '/(?:href|src)=["\']([^"\']*(?:\.bak|\.old|\.orig|\.swp|\.backup|_backup|copy[-_]of|[-_]old\b|[-_]temp\b|[-_]tmp\b)[^"\']*)["\'](?!>)/i';
    if (preg_match_all($pattern, $body, $m)) {
        foreach (array_unique($m[1]) as $url) {
            if (!preg_match('/^mailto:|^tel:|^#/', $url)) {
                $found[] = ['url' => $url];
            }
        }
    }
    return $found;
}

// ── Absolute internal hostnames in HTML ──────────────────────
function scan_internal_hosts(string $body, string $target_host): array {
    $found = [];
    $seen  = [];
    $tlds  = 'local|internal|intranet|corp|lan|test|dev|staging|localhost';
    $pat   = '/(?:href|src|action|fetch|axios\.\w+)\s*[=(]\s*["\']?(https?:\/\/([a-zA-Z0-9\-_.]+\.(?:' . $tlds . ')(?::\d+)?(?:\/[^"\'>\s]*)?))["\']?/i';
    if (preg_match_all($pat, $body, $m, PREG_SET_ORDER)) {
        foreach ($m as $match) {
            $key = strtolower($match[2]);
            if (!isset($seen[$key]) && $key !== strtolower($target_host)) {
                $seen[$key] = true;
                $found[]    = ['url' => $match[1], 'host' => $match[2]];
            }
        }
    }
    if (preg_match_all('/https?:\/\/localhost(?::\d+)?(?:\/[^"\'>\s]*)?/i', $body, $m)) {
        foreach (array_unique($m[0]) as $url) {
            if (!isset($seen['localhost'])) { $seen['localhost'] = true; $found[] = ['url' => $url, 'host' => 'localhost']; }
        }
    }
    return $found;
}

// ─────────────────────────────────────────────────────────────
// MAIN SCAN
// ─────────────────────────────────────────────────────────────

// ── Fetch main page ───────────────────────────────────────────
$page = full_fetch($raw_url);
$results['http_code']    = $page['code'];
$results['final_url']    = $page['final_url'];
$results['content_type'] = $page['type'];

// ── URL parameter / credential leak check ────────────────────
$url_leaks = check_url_params($page['final_url'], $page['body'], $sensitive_url_params);
$results['url_param_leaks'] = $url_leaks;
foreach ($url_leaks as $leak) {
    $results['findings'][] = [
        'type'     => 'url_param',
        'detail'   => "Sensitive param [{$leak['param']}={$leak['value']}] in URL — logged in browser history, server logs, and Referer headers",
        'severity' => 'high',
        'url'      => $leak['url'],
    ];
}

// ── Analyse response headers ──────────────────────────────────
$h = $page['headers'];
$results['headers'] = $h;

$leak_checks = [
    'x-powered-by'          => ['severity' => 'low',      'msg' => 'Reveals server-side technology version'],
    'server'                => ['severity' => 'low',      'msg' => 'Reveals web server software and version'],
    'x-aspnet-version'      => ['severity' => 'low',      'msg' => 'Reveals ASP.NET version'],
    'x-aspnetmvc-version'   => ['severity' => 'low',      'msg' => 'Reveals ASP.NET MVC version'],
    'x-generator'           => ['severity' => 'low',      'msg' => 'Reveals CMS or framework'],
    'x-debug-token'         => ['severity' => 'high',     'msg' => 'Symfony debug token exposed — debug mode may be on'],
    'x-debug-token-link'    => ['severity' => 'high',     'msg' => 'Symfony profiler link exposed'],
    'x-cf-debug'            => ['severity' => 'medium',   'msg' => 'Cloudflare debug header present'],
    'x-runtime'             => ['severity' => 'low',      'msg' => 'Rails/framework execution time exposed'],
    'x-rack-cache'          => ['severity' => 'info',     'msg' => 'Internal caching layer disclosed'],
    'x-drupal-cache'        => ['severity' => 'info',     'msg' => 'Drupal CMS identified via header'],
    'x-varnish'             => ['severity' => 'info',     'msg' => 'Varnish cache layer identified'],
    'x-backend-server'      => ['severity' => 'medium',   'msg' => 'Internal backend server hostname exposed'],
    'x-forwarded-server'    => ['severity' => 'medium',   'msg' => 'Internal server name disclosed via proxy header'],
    'via'                   => ['severity' => 'info',     'msg' => 'Proxy chain disclosed'],
    'authorization'         => ['severity' => 'critical', 'msg' => 'Authorization credentials exposed in response header'],
    'x-auth-token'          => ['severity' => 'critical', 'msg' => 'Auth token exposed in response header'],
    'x-api-key'             => ['severity' => 'critical', 'msg' => 'API key exposed in response header'],
    'x-secret'              => ['severity' => 'critical', 'msg' => 'Secret value exposed in response header'],
    'x-wp-nonce'            => ['severity' => 'medium',   'msg' => 'WordPress nonce exposed — can be used in authenticated requests'],
    'x-wp-total'            => ['severity' => 'info',     'msg' => 'WordPress total count exposed'],
    'x-pingback'            => ['severity' => 'medium',   'msg' => 'WordPress XML-RPC pingback URL exposed in header'],
    'link'                  => ['severity' => 'info',     'msg' => 'Link header may reveal API entry points or resources'],
];

foreach ($leak_checks as $header => $info) {
    if (isset($h[$header])) {
        $val = implode(', ', $h[$header]);
        $results['header_issues'][] = ['header' => $header, 'value' => $val, 'severity' => $info['severity'], 'msg' => $info['msg']];
        $results['findings'][] = ['type' => 'header', 'detail' => "Response header [{$header}: {$val}] — {$info['msg']}", 'severity' => $info['severity']];
    }
}

$required_headers = [
    'strict-transport-security' => ['severity' => 'medium', 'msg' => 'HSTS not set — downgrade attacks possible'],
    'x-frame-options'           => ['severity' => 'medium', 'msg' => 'X-Frame-Options missing — clickjacking risk'],
    'x-content-type-options'    => ['severity' => 'low',    'msg' => 'X-Content-Type-Options missing — MIME sniffing risk'],
    'content-security-policy'   => ['severity' => 'medium', 'msg' => 'No CSP — XSS protection limited'],
    'referrer-policy'           => ['severity' => 'low',    'msg' => 'Referrer-Policy not set'],
];
foreach ($required_headers as $header => $info) {
    if (!isset($h[$header])) {
        $results['header_issues'][] = ['header' => $header, 'value' => null, 'severity' => $info['severity'], 'msg' => 'MISSING: ' . $info['msg']];
        $results['findings'][] = ['type' => 'header_missing', 'detail' => "Missing header [{$header}] — {$info['msg']}", 'severity' => $info['severity']];
    }
}

// ── CORS analysis ─────────────────────────────────────────────
$acao = $h['access-control-allow-origin'][0]      ?? null;
$acac = $h['access-control-allow-credentials'][0] ?? null;
$acam = $h['access-control-allow-methods'][0]     ?? null;
$acah = $h['access-control-allow-headers'][0]     ?? null;

if ($acao) {
    $cors = ['origin' => $acao, 'credentials' => $acac, 'methods' => $acam, 'allow_headers' => $acah, 'issues' => []];
    if ($acao === '*') {
        $cors['issues'][] = 'Wildcard origin (*) allows any domain to make cross-origin requests';
        $results['findings'][] = ['type' => 'cors', 'detail' => 'CORS: Access-Control-Allow-Origin: * — any site can read this response', 'severity' => 'medium'];
    }
    if ($acao === '*' && $acac === 'true') {
        $cors['issues'][] = 'CRITICAL: Wildcard origin + credentials=true — indicates misconfiguration';
        $results['findings'][] = ['type' => 'cors', 'detail' => 'CORS misconfiguration: wildcard origin with credentials=true', 'severity' => 'critical'];
    }
    if ($acam && preg_match('/DELETE|PUT|PATCH/i', $acam)) {
        $cors['issues'][] = 'Destructive methods (DELETE/PUT/PATCH) allowed cross-origin';
        $results['findings'][] = ['type' => 'cors', 'detail' => "CORS allows destructive methods cross-origin: $acam", 'severity' => 'medium'];
    }
    $results['cors'] = $cors;
}

// ── Cookie analysis ───────────────────────────────────────────
$set_cookies = $h['set-cookie'] ?? [];
foreach ($set_cookies as $raw_cookie) {
    $parts    = array_map('trim', explode(';', $raw_cookie));
    $name_val = explode('=', $parts[0], 2);
    $name     = $name_val[0] ?? '';
    $flags    = array_map('strtolower', array_slice($parts, 1));

    $cookie = ['name' => $name, 'httponly' => in_array('httponly', $flags), 'secure' => in_array('secure', $flags), 'samesite' => null, 'issues' => []];
    foreach ($flags as $f) {
        if (strpos($f, 'samesite') === 0) $cookie['samesite'] = explode('=', $f, 2)[1] ?? 'unknown';
    }

    if (!$cookie['httponly']) {
        $cookie['issues'][] = 'Missing HttpOnly — readable by JavaScript (XSS risk)';
        $results['findings'][] = ['type' => 'cookie', 'detail' => "Cookie [{$name}] missing HttpOnly flag — accessible via JavaScript", 'severity' => 'medium'];
    }
    if (!$cookie['secure']) {
        $cookie['issues'][] = 'Missing Secure — may be sent over HTTP';
        $results['findings'][] = ['type' => 'cookie', 'detail' => "Cookie [{$name}] missing Secure flag — can be sent over plain HTTP", 'severity' => 'medium'];
    }
    if (!$cookie['samesite']) {
        $cookie['issues'][] = 'Missing SameSite — CSRF risk';
        $results['findings'][] = ['type' => 'cookie', 'detail' => "Cookie [{$name}] missing SameSite — CSRF attacks possible", 'severity' => 'low'];
    }
    if (preg_match('/sess|auth|token|login|user|admin|jwt/i', $name)) {
        $cookie['sensitive'] = true;
        if (!$cookie['httponly'] || !$cookie['secure']) {
            $results['findings'][] = ['type' => 'cookie', 'detail' => "Sensitive cookie [{$name}] has weak flags — high risk", 'severity' => 'high'];
        }
    }
    $results['cookies'][] = $cookie;
}

// ── Cache-Control on pages with session cookies ───────────────
$has_session_cookie = false;
foreach ($results['cookies'] as $c) {
    if (!empty($c['sensitive']) || preg_match('/sess|auth|login|jwt/i', $c['name'])) {
        $has_session_cookie = true;
        break;
    }
}
$cc_header = $h['cache-control'][0] ?? '';
if ($has_session_cookie && stripos($cc_header, 'no-store') === false) {
    $results['cache_issues'][] = [
        'cache_control' => $cc_header ?: '(not set)',
        'detail'        => 'Session cookie present but Cache-Control does not include no-store',
    ];
    $results['findings'][] = [
        'type'     => 'cache',
        'detail'   => 'Cache-Control missing no-store on session-authenticated page — response may be cached by proxies or browser, leaking sensitive content',
        'severity' => 'medium',
    ];
}

// ── OPTIONS / TRACE probe ─────────────────────────────────────
$opts    = fetch_options($raw_url);
$methods = ['allow' => $opts['allow'], 'http_code' => $opts['code'], 'issues' => []];
if ($opts['allow']) {
    if (preg_match('/\bTRACE\b/i', $opts['allow'])) {
        $methods['issues'][] = 'TRACE enabled — Cross-Site Tracing (XST) can steal HttpOnly cookies via XSS';
        $results['findings'][] = ['type' => 'http_method', 'detail' => 'HTTP TRACE method allowed — Cross-Site Tracing (XST) attack can bypass HttpOnly cookie protection', 'severity' => 'high'];
    }
    if (preg_match('/\b(DELETE|PUT|PATCH)\b/i', $opts['allow'], $dm)) {
        $methods['issues'][] = "Dangerous method {$dm[1]} listed in Allow header — verify this is intentional";
        $results['findings'][] = ['type' => 'http_method', 'detail' => "Dangerous HTTP method [{$dm[1]}] allowed on this URL — confirm this is intentional", 'severity' => 'medium'];
    }
}
$results['http_methods'] = $methods;

// ── Scan page body ────────────────────────────────────────────
$body_scan = scan_content($page['body'], $raw_url, $cred_patterns, $endpoint_patterns, $internal_ip_pattern);
$results['credentials']   = array_merge($results['credentials'],   $body_scan['credentials']);
$results['api_endpoints'] = array_merge($results['api_endpoints'], $body_scan['endpoints']);
$results['internal_ips']  = array_merge($results['internal_ips'],  $body_scan['internal_ips']);
$results['comments']      = array_merge($results['comments'],      $body_scan['comments']);
$results['emails']        = array_merge($results['emails'],        $body_scan['emails']);

foreach ($body_scan['credentials'] as $c) {
    $results['findings'][] = ['type' => 'credential', 'detail' => "{$c['type']} found in page body [{$c['value']}]", 'severity' => 'critical'];
}
foreach ($body_scan['internal_ips'] as $ip) {
    $results['findings'][] = ['type' => 'internal_ip', 'detail' => "Internal IP {$ip['ip']} exposed in page body", 'severity' => 'medium'];
}
foreach ($body_scan['comments'] as $c) {
    $results['findings'][] = ['type' => 'comment', 'detail' => 'Sensitive keyword in HTML/JS comment: ' . substr($c['text'], 0, 100), 'severity' => 'medium'];
}

// ── Verbose error / stack trace scan on body ──────────────────
$errors = scan_error_disclosure($page['body'], $raw_url, $error_patterns);
$results['error_disclosures'] = array_merge($results['error_disclosures'], $errors);
foreach ($errors as $e) {
    $results['findings'][] = [
        'type'     => 'error_disclosure',
        'detail'   => "{$e['type']} in page body — server internals exposed: " . substr($e['excerpt'], 0, 120),
        'severity' => $e['severity'],
    ];
}

// ── Mixed content ─────────────────────────────────────────────
$mc = scan_mixed_content($page['body'], $parts['scheme']);
$results['mixed_content'] = $mc;
foreach ($mc as $item) {
    $sev = $item['active'] ? 'high' : 'medium';
    $results['findings'][] = ['type' => 'mixed_content', 'detail' => "Mixed content [{$item['type']}] — HTTP resource on HTTPS page: {$item['url']}", 'severity' => $sev];
}

// ── SRI missing on external assets ───────────────────────────
$sri = scan_sri_missing($page['body'], $parts['host']);
$results['sri_missing'] = $sri;
foreach ($sri as $item) {
    $results['findings'][] = ['type' => 'sri', 'detail' => "No integrity= on external {$item['type']} from {$item['host']} — CDN compromise injects malicious code silently", 'severity' => 'medium'];
}

// ── Insecure form actions ─────────────────────────────────────
$forms = scan_insecure_forms($page['body'], $parts['scheme']);
$results['insecure_forms'] = $forms;
foreach ($forms as $form) {
    $results['findings'][] = ['type' => 'insecure_form', 'detail' => "Form POSTs to HTTP target: {$form['action']} — credentials sent in plaintext despite page loading over HTTPS", 'severity' => 'high'];
}

// ── Autocomplete on sensitive inputs ─────────────────────────
$ac = scan_autocomplete($page['body']);
$results['autocomplete'] = $ac;
foreach ($ac as $field) {
    $results['findings'][] = ['type' => 'autocomplete', 'detail' => "No autocomplete=off on {$field['field_type']} input — browser will offer to store credentials locally", 'severity' => 'low'];
}

// ── Backup / temp file links ──────────────────────────────────
$bk = scan_backup_links($page['body']);
$results['backup_links'] = $bk;
foreach ($bk as $item) {
    $results['findings'][] = ['type' => 'backup_link', 'detail' => "Backup/temp file linked in HTML: {$item['url']} — may expose unprotected copy of source or data", 'severity' => 'medium'];
}

// ── Absolute internal hostnames ───────────────────────────────
$ih = scan_internal_hosts($page['body'], $parts['host']);
$results['internal_hosts'] = $ih;
foreach ($ih as $item) {
    $results['findings'][] = ['type' => 'internal_host', 'detail' => "Internal hostname exposed in HTML: {$item['url']} — leaks internal network topology", 'severity' => 'medium'];
}

// ── Find and scan linked JS files ─────────────────────────────
if ($scan_js && strpos($page['type'] ?? '', 'html') !== false) {
    preg_match_all('/<script[^>]+src=["\']([^"\']+\.js(?:[?#][^"\']*)?)["\'][^>]*>/i', $page['body'], $js_matches);
    $js_urls = [];
    foreach (array_unique($js_matches[1]) as $src) {
        if (substr($src, 0, 2) === '//') $src = $parts['scheme'] . ':' . $src;
        elseif ($src[0] === '/')          $src = $base_origin . $src;
        elseif (substr($src, 0, 4) !== 'http') $src = $base_origin . '/' . ltrim($src, '/');
        if (parse_url($src, PHP_URL_HOST) === $parts['host']) $js_urls[] = $src;
    }
    $js_urls = array_slice(array_unique($js_urls), 0, 15);

    foreach ($js_urls as $js_url) {
        $js_resp = full_fetch($js_url, 8);
        $js_scan = scan_content($js_resp['body'], $js_url, $cred_patterns, $endpoint_patterns, $internal_ip_pattern);

        $js_entry = ['url' => $js_url, 'size' => strlen($js_resp['body']), 'findings_count' => 0];

        // Credentials
        foreach ($js_scan['credentials'] as $c) {
            $results['credentials'][] = $c;
            $results['findings'][] = ['type' => 'credential', 'detail' => "{$c['type']} found in JS file", 'severity' => 'critical', 'url' => $js_url];
            $js_entry['findings_count']++;
        }
        // Endpoints
        foreach ($js_scan['endpoints'] as $ep) {
            if (!in_array($ep, $results['api_endpoints'])) $results['api_endpoints'][] = $ep;
        }
        // Internal IPs
        foreach ($js_scan['internal_ips'] as $ip) {
            $results['internal_ips'][] = $ip;
            $results['findings'][] = ['type' => 'internal_ip', 'detail' => "Internal IP {$ip['ip']} in JS file", 'severity' => 'medium', 'url' => $js_url];
            $js_entry['findings_count']++;
        }
        // Comments
        foreach ($js_scan['comments'] as $c) {
            $results['comments'][] = $c;
            $results['findings'][] = ['type' => 'comment', 'detail' => 'Sensitive comment in JS: ' . substr($c['text'], 0, 100), 'severity' => 'medium', 'url' => $js_url];
            $js_entry['findings_count']++;
        }
        // Emails
        foreach ($js_scan['emails'] as $e) {
            if (!in_array($e['email'], array_column($results['emails'], 'email'))) $results['emails'][] = $e;
        }

        // ── Source map check ──────────────────────────────────
        $map = check_source_map($js_resp['body'], $js_url, $base_origin);
        if ($map) {
            $results['source_maps'][] = $map;
            if ($map['accessible']) {
                $results['findings'][] = [
                    'type'     => 'source_map',
                    'detail'   => "Source map PUBLICLY ACCESSIBLE ({$map['size_kb']} KB) — unminified source code exposed at {$map['map_url']}",
                    'severity' => 'high',
                    'url'      => $map['map_url'],
                ];
                $js_entry['findings_count']++;
            } else {
                $results['findings'][] = [
                    'type'     => 'source_map',
                    'detail'   => "Source map reference found in {$js_url} but map file returns HTTP {$map['http_code']} — blocked",
                    'severity' => 'info',
                ];
            }
        }

        // ── Outdated library detection ────────────────────────
        $libs = detect_lib_versions($js_resp['body'] . ' ' . $js_url, $js_url, $known_vuln_libs);
        foreach ($libs as $lib) {
            $results['outdated_libs'][] = $lib;
            $results['findings'][] = [
                'type'     => 'outdated_lib',
                'detail'   => "{$lib['library']} v{$lib['version']} (< {$lib['below']}) — {$lib['cve']}: {$lib['issue']}",
                'severity' => $lib['severity'],
                'url'      => $js_url,
            ];
            $js_entry['findings_count']++;
        }

        // ── DOM XSS sinks ─────────────────────────────────────
        $sinks = scan_dom_sinks($js_resp['body'], $js_url, $dom_xss_patterns);
        foreach ($sinks as $sink) {
            $results['dom_xss'][] = $sink;
            $results['findings'][] = [
                'type'     => 'dom_xss',
                'detail'   => "DOM XSS sink [{$sink['sink']}] at line {$sink['line']}: " . substr($sink['context'], 0, 100),
                'severity' => 'medium',
                'url'      => $js_url,
            ];
            $js_entry['findings_count']++;
        }

        // ── localStorage / sessionStorage sensitive keys ──────
        $ls = scan_localstorage($js_resp['body'], $js_url);
        foreach ($ls as $item) {
            $results['localstorage'][] = $item;
            $results['findings'][] = [
                'type'     => 'localstorage',
                'detail'   => "Sensitive key '{$item['key']}' stored in {$item['storage']} — readable by any same-origin JS (XSS pivot)",
                'severity' => 'medium',
                'url'      => $js_url,
            ];
            $js_entry['findings_count']++;
        }

        // ── postMessage without origin check ─────────────────
        $pm = scan_postmessage($js_resp['body'], $js_url);
        foreach ($pm as $item) {
            $results['postmessage'][] = $item;
            if (!$item['has_origin_check']) {
                $results['findings'][] = [
                    'type'     => 'postmessage',
                    'detail'   => "postMessage listener missing origin validation — any window can send arbitrary messages",
                    'severity' => 'medium',
                    'url'      => $js_url,
                ];
                $js_entry['findings_count']++;
            }
        }

        $results['js_files'][] = $js_entry;
    }
}

// ── Deduplicate ───────────────────────────────────────────────
$results['api_endpoints'] = array_values(array_unique($results['api_endpoints']));
sort($results['api_endpoints']);

// ── Overall severity ──────────────────────────────────────────
$sev_rank = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1, 'info' => 0];
$max = 0;
foreach ($results['findings'] as $f) {
    $r = $sev_rank[$f['severity']] ?? 0;
    if ($r > $max) { $max = $r; $results['severity'] = $f['severity']; }
}

// ── Log ───────────────────────────────────────────────────────
$log = date('Y-m-d H:i:s') . ' | INSPECT | ' . $raw_url . ' | sev=' . $results['severity'] . ' | findings=' . count($results['findings']) . PHP_EOL;
@file_put_contents(LOG_DIR . 'scans.log', $log, FILE_APPEND | LOCK_EX);

json_out($results);
