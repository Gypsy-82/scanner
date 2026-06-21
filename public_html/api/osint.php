<?php
require_once __DIR__ . '/auth.php';
require_auth();
verify_csrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    json_out(['error' => 'POST required']);
}

$target = trim($_POST['target'] ?? '');
$type   = trim($_POST['type']   ?? 'all');

if (!$target) json_out(['error' => 'Target (domain or IP) required']);

// Normalize — strip protocol if pasted
$target = preg_replace('#^https?://#', '', $target);
$target = strtolower(trim($target, '/'));

$is_ip     = filter_var($target, FILTER_VALIDATE_IP) !== false;
$is_domain = !$is_ip && preg_match('/^([a-z0-9-]+\.)+[a-z]{2,}$/', $target);

if (!$is_ip && !$is_domain) {
    json_out(['error' => 'Invalid target — enter a domain (example.com) or IP address']);
}

$results = [
    'target'      => $target,
    'is_ip'       => $is_ip,
    'reverse_ip'  => null,
    'subdomains'  => null,
    'dns'         => null,
    'whois_hint'  => null,
    'shodan'      => null,
    'findings'    => [],
];

// ── Resolve IP if domain given ────────────────────────────────
if ($is_domain) {
    $resolved = gethostbyname($target);
    $results['resolved_ip'] = ($resolved !== $target) ? $resolved : null;
    $ip_for_lookup = $results['resolved_ip'];
} else {
    $ip_for_lookup = $target;
    $results['resolved_ip'] = $target;
}

// ── Reverse IP — HackerTarget (free, no key) ──────────────────
if (($type === 'all' || $type === 'reverseip') && $ip_for_lookup) {
    $ht = http_get("https://api.hackertarget.com/reverseiplookup/?q=" . urlencode($ip_for_lookup));
    if ($ht['code'] === 200 && $ht['body'] && strpos($ht['body'], 'error') === false && strpos($ht['body'], 'API count') === false) {
        $domains = array_filter(array_map('trim', explode("\n", $ht['body'])));
        $domains = array_values($domains);
        $results['reverse_ip'] = [
            'ip'      => $ip_for_lookup,
            'count'   => count($domains),
            'domains' => $domains,
            'source'  => 'HackerTarget',
        ];
        if (count($domains) > 50) {
            $results['findings'][] = ['type' => 'reverse_ip', 'detail' => count($domains) . ' domains share this IP — shared hosting, wider attack surface', 'severity' => 'info'];
        }
    } else {
        $results['reverse_ip'] = ['error' => 'HackerTarget: ' . ($ht['body'] ?? 'no response'), 'fallback' => 'Rate limited — try again in a few minutes'];
    }
}

// ── Subdomain enumeration — two sources ──────────────────────
if (($type === 'all' || $type === 'subdomains') && $is_domain) {
    $all_subs = [];

    // Source 1: HackerTarget host search
    $ht2 = http_get("https://api.hackertarget.com/hostsearch/?q=" . urlencode($target));
    if ($ht2['code'] === 200 && $ht2['body'] && strpos($ht2['body'], 'error') === false) {
        foreach (explode("\n", $ht2['body']) as $line) {
            $line = trim($line);
            if (!$line) continue;
            $parts = explode(',', $line);
            $all_subs[trim($parts[0])] = ['source' => 'HackerTarget', 'ip' => trim($parts[1] ?? '')];
        }
    }

    // Source 2: crt.sh certificate transparency (no key, totally free)
    $crt = http_get("https://crt.sh/?q=%25." . urlencode($target) . "&output=json");
    if ($crt['code'] === 200 && $crt['body']) {
        $crt_data = json_decode($crt['body'], true);
        if (is_array($crt_data)) {
            foreach ($crt_data as $entry) {
                $names = explode("\n", $entry['name_value'] ?? '');
                foreach ($names as $name) {
                    $name = strtolower(trim($name));
                    if (!$name || strpos($name, '*') !== false) continue;
                    if (str_ends_with($name, '.' . $target) || $name === $target) {
                        if (!isset($all_subs[$name])) {
                            $all_subs[$name] = ['source' => 'crt.sh', 'ip' => ''];
                        }
                    }
                }
            }
        }
    }

    // Resolve IPs for subdomains that don't have one yet
    foreach ($all_subs as $sub => &$data) {
        if (empty($data['ip'])) {
            $resolved = gethostbyname($sub);
            $data['ip'] = ($resolved !== $sub) ? $resolved : 'unresolved';
        }
    }
    unset($data);

    ksort($all_subs);
    $results['subdomains'] = [
        'count'  => count($all_subs),
        'list'   => $all_subs,
        'source' => 'HackerTarget + crt.sh certificate transparency',
    ];

    if (count($all_subs) > 0) {
        $results['findings'][] = ['type' => 'subdomains', 'detail' => count($all_subs) . ' subdomains found — review each for exposure', 'severity' => 'info'];
    }
}

// ── DNS records ───────────────────────────────────────────────
if ($is_domain) {
    $dns_types = [DNS_A, DNS_AAAA, DNS_MX, DNS_NS, DNS_TXT, DNS_CNAME];
    $dns_all   = [];
    foreach ($dns_types as $type_flag) {
        $recs = @dns_get_record($target, $type_flag);
        if ($recs) $dns_all = array_merge($dns_all, $recs);
    }
    $results['dns'] = $dns_all;

    // Check TXT records for interesting data
    foreach ($dns_all as $rec) {
        if ($rec['type'] === 'TXT') {
            $txt = $rec['txt'] ?? '';
            if (strpos($txt, 'v=spf1') !== false) {
                $results['findings'][] = ['type' => 'dns', 'detail' => 'SPF record found: ' . $txt, 'severity' => 'info'];
            }
            if (stripos($txt, 'google-site-verification') !== false ||
                stripos($txt, 'facebook-domain-verification') !== false) {
                $results['findings'][] = ['type' => 'dns', 'detail' => 'Verification TXT record reveals platform usage: ' . $txt, 'severity' => 'info'];
            }
        }
        // MX record reveals email provider
        if ($rec['type'] === 'MX') {
            $results['findings'][] = ['type' => 'dns', 'detail' => 'Mail provider: ' . ($rec['target'] ?? ''), 'severity' => 'info'];
        }
    }
}

// ── Shodan (optional, needs key) ──────────────────────────────
if (SHODAN_API_KEY && $ip_for_lookup) {
    $sh = http_get("https://api.shodan.io/shodan/host/$ip_for_lookup?key=" . SHODAN_API_KEY);
    $sh_data = json_decode($sh['body'] ?? '', true);
    if ($sh['code'] === 200 && $sh_data) {
        $ports = array_column($sh_data['data'] ?? [], 'port');
        $results['shodan'] = [
            'ip'       => $ip_for_lookup,
            'org'      => $sh_data['org'] ?? null,
            'os'       => $sh_data['os']  ?? null,
            'ports'    => array_unique($ports),
            'hostnames'=> $sh_data['hostnames'] ?? [],
            'vulns'    => array_keys($sh_data['vulns'] ?? []),
        ];
        if (!empty($sh_data['vulns'])) {
            foreach (array_keys($sh_data['vulns']) as $cve) {
                $results['findings'][] = ['type' => 'shodan', 'detail' => "Known vulnerability: $cve", 'severity' => 'high'];
            }
        }
        // Flag unusual open ports
        $sensitive_ports = [21, 23, 25, 110, 143, 3306, 5432, 6379, 27017, 9200, 5601];
        foreach ($ports as $p) {
            if (in_array($p, $sensitive_ports)) {
                $results['findings'][] = ['type' => 'shodan', 'detail' => "Sensitive port open: $p", 'severity' => 'medium'];
            }
        }
    }
}

// ── Log ───────────────────────────────────────────────────────
$log = date('Y-m-d H:i:s') . ' | OSINT | ' . $target . ' | subs=' . ($results['subdomains']['count'] ?? 0) . ' | reverseip=' . ($results['reverse_ip']['count'] ?? 0) . PHP_EOL;
@file_put_contents(LOG_DIR . 'scans.log', $log, FILE_APPEND | LOCK_EX);

json_out($results);
