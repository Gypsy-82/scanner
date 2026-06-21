<?php
require_once __DIR__ . '/auth.php';
require_auth();
verify_csrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    json_out(['error' => 'POST required']);
}

$raw_url = trim($_POST['url'] ?? '');
if (!$raw_url) json_out(['error' => 'URL required']);

// Validate URL
if (!filter_var($raw_url, FILTER_VALIDATE_URL)) {
    json_out(['error' => 'Invalid URL format']);
}
$parts = parse_url($raw_url);
if (!in_array($parts['scheme'] ?? '', ['http', 'https'])) {
    json_out(['error' => 'Only http/https URLs allowed']);
}

$results = [
    'url'        => $raw_url,
    'domain'     => $parts['host'] ?? '',
    'urlhaus'    => null,
    'virustotal' => null,
    'gsb'        => null,
    'abuseipdb'  => null,
    'headers'    => null,
    'verdict'    => 'unknown',
    'severity'   => 'low',
    'findings'   => [],
];

$domain = $results['domain'];

// ── Resolve IP ────────────────────────────────────────────────
$ip = gethostbyname($domain);
$results['resolved_ip'] = ($ip !== $domain) ? $ip : null;

// ── URLhaus (no key required) ─────────────────────────────────
$uh = http_post('https://urlhaus-api.abuse.ch/v1/url/', ['url' => $raw_url]);
$uh_data = json_decode($uh['body'] ?? '', true);
if ($uh_data) {
    $status = $uh_data['query_status'] ?? '';
    $results['urlhaus'] = [
        'status'    => $status,
        'threat'    => $uh_data['threat']     ?? null,
        'tags'      => $uh_data['tags']       ?? [],
        'blacklists'=> $uh_data['blacklists'] ?? [],
        'link'      => $uh_data['urlhaus_reference'] ?? null,
    ];
    if ($status === 'is_db') {
        $results['verdict']  = 'malicious';
        $results['severity'] = 'critical';
        $results['findings'][] = ['type' => 'urlhaus', 'detail' => 'URL is in URLhaus malware database (threat: ' . ($uh_data['threat'] ?? 'unknown') . ')', 'severity' => 'critical'];
    }
} else {
    $results['urlhaus'] = ['error' => 'No response from URLhaus'];
}

// ── VirusTotal URL scan ───────────────────────────────────────
if (VT_API_KEY) {
    // Get URL ID
    $url_id = rtrim(base64_encode($raw_url), '=');
    $vt_res = http_get("https://www.virustotal.com/api/v3/urls/$url_id", ['x-apikey: ' . VT_API_KEY]);
    $vt = json_decode($vt_res['body'] ?? '', true);
    if ($vt_res['code'] === 200 && isset($vt['data']['attributes'])) {
        $attrs = $vt['data']['attributes'];
        $stats = $attrs['last_analysis_stats'] ?? [];
        $results['virustotal'] = [
            'malicious'  => $stats['malicious']  ?? 0,
            'suspicious' => $stats['suspicious'] ?? 0,
            'harmless'   => $stats['harmless']   ?? 0,
            'undetected' => $stats['undetected'] ?? 0,
            'last_scan'  => $attrs['last_analysis_date'] ?? null,
            'categories' => $attrs['categories'] ?? [],
            'link'       => "https://www.virustotal.com/gui/url/$url_id",
        ];
        $mal = $stats['malicious'] ?? 0;
        $sus = $stats['suspicious'] ?? 0;
        if ($mal > 0) {
            $results['findings'][] = ['type' => 'virustotal', 'detail' => "$mal engine(s) flagged as malicious", 'severity' => 'critical'];
            if ($results['severity'] !== 'critical') { $results['verdict'] = 'malicious'; $results['severity'] = 'critical'; }
        } elseif ($sus > 0) {
            $results['findings'][] = ['type' => 'virustotal', 'detail' => "$sus engine(s) flagged as suspicious", 'severity' => 'medium'];
            if ($results['severity'] === 'low') { $results['verdict'] = 'suspicious'; $results['severity'] = 'medium'; }
        }
    } elseif ($vt_res['code'] === 404) {
        // Submit for scanning
        $submit = http_post('https://www.virustotal.com/api/v3/urls', ['url' => $raw_url], ['x-apikey: ' . VT_API_KEY]);
        $results['virustotal'] = ['status' => 'submitted', 'message' => 'URL submitted to VT for scanning. Re-check in 60 seconds.'];
    } else {
        $results['virustotal'] = ['error' => "VT HTTP {$vt_res['code']}"];
    }
}

// ── Google Safe Browsing ──────────────────────────────────────
if (GSB_API_KEY) {
    $gsb_payload = json_encode([
        'client'    => ['clientId' => 'security-scanner', 'clientVersion' => '1.0'],
        'threatInfo'=> [
            'threatTypes'      => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes'    => ['ANY_PLATFORM'],
            'threatEntryTypes' => ['URL'],
            'threatEntries'    => [['url' => $raw_url]],
        ],
    ]);
    $gsb_res = http_post(
        'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . GSB_API_KEY,
        $gsb_payload,
        ['Content-Type: application/json']
    );
    $gsb = json_decode($gsb_res['body'] ?? '', true);
    $matches = $gsb['matches'] ?? [];
    $results['gsb'] = [
        'safe'    => empty($matches),
        'matches' => $matches,
    ];
    if (!empty($matches)) {
        foreach ($matches as $m) {
            $results['findings'][] = ['type' => 'google_safebrowsing', 'detail' => $m['threatType'] . ' detected by Google Safe Browsing', 'severity' => 'critical'];
        }
        $results['verdict']  = 'malicious';
        $results['severity'] = 'critical';
    }
}

// ── AbuseIPDB (for the resolved IP) ──────────────────────────
if (ABUSEIPDB_KEY && $results['resolved_ip']) {
    $ab_res = http_get(
        'https://api.abuseipdb.com/api/v2/check?ipAddress=' . urlencode($results['resolved_ip']) . '&maxAgeInDays=90',
        ['Key: ' . ABUSEIPDB_KEY, 'Accept: application/json']
    );
    $ab = json_decode($ab_res['body'] ?? '', true);
    if (isset($ab['data'])) {
        $d = $ab['data'];
        $results['abuseipdb'] = [
            'ip'               => $d['ipAddress'],
            'abuse_confidence' => $d['abuseConfidenceScore'],
            'total_reports'    => $d['totalReports'],
            'isp'              => $d['isp'],
            'country'          => $d['countryCode'],
            'usage_type'       => $d['usageType'],
            'is_tor'           => $d['isTor'],
        ];
        if ($d['abuseConfidenceScore'] >= 50) {
            $results['findings'][] = ['type' => 'abuseipdb', 'detail' => "IP {$d['ipAddress']} has {$d['abuseConfidenceScore']}% abuse confidence score ({$d['totalReports']} reports)", 'severity' => 'high'];
            if ($results['severity'] === 'low') { $results['verdict'] = 'suspicious'; $results['severity'] = 'high'; }
        }
    }
}

// ── HTTP header snapshot ──────────────────────────────────────
$head_res = http_get($raw_url);
if ($head_res['code'] > 0) {
    // Parse response headers from curl output
    $results['headers'] = ['http_code' => $head_res['code']];
}

// ── Log ───────────────────────────────────────────────────────
$log = date('Y-m-d H:i:s') . ' | URL | ' . $raw_url . ' | ' . $results['verdict'] . PHP_EOL;
@file_put_contents(LOG_DIR . 'scans.log', $log, FILE_APPEND | LOCK_EX);

json_out($results);
