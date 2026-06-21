<?php
require_once __DIR__ . '/auth.php';
require_auth();
verify_csrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    json_out(['error' => 'POST required']);
}

if (empty($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    json_out(['error' => 'No file uploaded or upload error: ' . ($_FILES['file']['error'] ?? 'none')]);
}

$file = $_FILES['file'];

// ── Validate size ─────────────────────────────────────────────
if ($file['size'] > MAX_UPLOAD_BYTES) {
    json_out(['error' => 'File too large (max 25 MB)']);
}

// ── Validate MIME (magic bytes, not extension) ────────────────
$allowed_mime = [
    'application/pdf', 'application/x-mobipocket-ebook',
    'application/epub+zip', 'application/zip',
    'application/x-rar-compressed', 'application/x-7z-compressed',
    'application/octet-stream', 'text/plain', 'text/html',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
];
$real_mime = mime_content_type($file['tmp_name']);
if (!in_array($real_mime, $allowed_mime)) {
    json_out(['error' => "File type not allowed: $real_mime"]);
}

// ── Create isolated temp directory ───────────────────────────
$scan_dir = '/tmp/scanner_' . bin2hex(random_bytes(8)) . '/';
mkdir($scan_dir, 0700);
$safe_name = preg_replace('/[^a-zA-Z0-9._-]/', '_', basename($file['name']));
$scan_path = $scan_dir . $safe_name;
move_uploaded_file($file['tmp_name'], $scan_path);
chmod($scan_path, 0600);

$results = [
    'filename'  => htmlspecialchars($file['name']),
    'size'      => $file['size'],
    'mime'      => $real_mime,
    'sha256'    => hash_file('sha256', $scan_path),
    'md5'       => hash_file('md5', $scan_path),
    'clamav'    => null,
    'pdfid'     => null,
    'strings'   => null,
    'virustotal'=> null,
    'verdict'   => 'clean',
    'severity'  => 'low',
    'findings'  => [],
];

// ── ClamAV ────────────────────────────────────────────────────
if (is_executable(CLAMSCAN_PATH)) {
    $cmd    = escapeshellcmd(CLAMSCAN_PATH) . ' --no-summary --max-filesize=25M --max-scansize=50M ' . escapeshellarg($scan_path) . ' 2>&1';
    $output = shell_exec($cmd);
    $lines  = array_filter(explode("\n", trim($output ?? '')));
    $found  = false;
    $detections = [];
    foreach ($lines as $line) {
        if (preg_match('/FOUND$/', $line)) {
            $found = true;
            $detections[] = trim($line);
        }
    }
    $results['clamav'] = [
        'clean'      => !$found,
        'detections' => $detections,
        'raw'        => implode("\n", $lines),
    ];
    if ($found) {
        $results['verdict']  = 'malicious';
        $results['severity'] = 'critical';
        foreach ($detections as $d) {
            $results['findings'][] = ['type' => 'clamav', 'detail' => $d, 'severity' => 'critical'];
        }
    }
} else {
    $results['clamav'] = ['error' => 'ClamAV not found at ' . CLAMSCAN_PATH . '. Run install.sh'];
}

// ── pdfid (PDFs only) ─────────────────────────────────────────
if ($real_mime === 'application/pdf' && file_exists(PDFID_PATH)) {
    $cmd    = 'python3 ' . escapeshellarg(PDFID_PATH) . ' ' . escapeshellarg($scan_path) . ' 2>&1';
    $output = shell_exec($cmd);

    // Dangerous PDF objects to watch for
    $suspicious_keys = ['/JS', '/JavaScript', '/AA', '/OpenAction', '/Launch', '/EmbeddedFile', '/XFA', '/RichMedia'];
    $pdfid_findings  = [];
    $parsed          = [];

    foreach (explode("\n", $output ?? '') as $line) {
        $line = trim($line);
        if (!$line || strpos($line, 'PDFiD') !== false) continue;
        if (preg_match('/^\s*(\S+)\s+(\d+)/', $line, $m)) {
            $key   = $m[1];
            $count = (int)$m[2];
            $parsed[$key] = $count;
            if (in_array($key, $suspicious_keys) && $count > 0) {
                $severity = in_array($key, ['/JS', '/JavaScript', '/OpenAction', '/Launch']) ? 'high' : 'medium';
                $pdfid_findings[] = ['key' => $key, 'count' => $count, 'severity' => $severity];
                $results['findings'][] = ['type' => 'pdfid', 'detail' => "$key: $count occurrence(s)", 'severity' => $severity];
                if ($results['severity'] !== 'critical') {
                    $results['severity'] = $severity;
                    $results['verdict']  = 'suspicious';
                }
            }
        }
    }

    $results['pdfid'] = [
        'parsed'   => $parsed,
        'findings' => $pdfid_findings,
        'raw'      => trim($output ?? ''),
    ];
} elseif ($real_mime === 'application/pdf') {
    $results['pdfid'] = ['error' => 'pdfid.py not found. Run install.sh'];
}

// ── Strings scan ──────────────────────────────────────────────
$suspicious_patterns = [
    'js_eval'      => '/\beval\s*\(/i',
    'js_unescape'  => '/unescape\s*\(/i',
    'js_fromchar'  => '/fromCharCode/i',
    'base64_blob'  => '/[A-Za-z0-9+\/]{80,}={0,2}/',
    'shell_cmd'    => '/\b(cmd\.exe|powershell|\/bin\/sh|\/bin\/bash|system\(|exec\(|passthru\(|shell_exec\()/i',
    'onion_url'    => '/[a-z2-7]{16,}\.onion/i',
    'ip_url'       => '/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i',
    'suspicious_tld'=> '/https?:\/\/[^\s"\'<>]+\.(xyz|tk|pw|cc|top|work|click|download|zip|review)/i',
    'auto_run'     => '/(AutoOpen|AutoClose|Auto_Open|Document_Open|Workbook_Open)/i',
];

$str_output = shell_exec('strings ' . escapeshellarg($scan_path) . ' 2>/dev/null') ?? '';
$str_lines  = explode("\n", $str_output);
$str_hits   = [];

foreach ($suspicious_patterns as $label => $pattern) {
    $matches = [];
    foreach ($str_lines as $line) {
        $line = trim($line);
        if (strlen($line) < 4) continue;
        if (preg_match($pattern, $line)) {
            $matches[] = substr($line, 0, 200);
            if (count($matches) >= 5) break;
        }
    }
    if ($matches) {
        $str_hits[$label] = $matches;
        $sev = in_array($label, ['shell_cmd', 'auto_run', 'onion_url']) ? 'high' : 'medium';
        $results['findings'][] = ['type' => 'strings', 'detail' => "Pattern [$label]: " . count($matches) . " match(es)", 'severity' => $sev];
        if ($results['severity'] === 'low') {
            $results['severity'] = $sev;
            $results['verdict']  = 'suspicious';
        }
    }
}
$results['strings'] = ['hits' => $str_hits, 'total_lines' => count($str_lines)];

// ── VirusTotal hash lookup (no upload — just hash check) ──────
if (VT_API_KEY) {
    $hash  = $results['sha256'];
    $res   = http_get("https://www.virustotal.com/api/v3/files/$hash", ['x-apikey: ' . VT_API_KEY]);
    $vt    = json_decode($res['body'] ?? '', true);
    if ($res['code'] === 200 && isset($vt['data']['attributes']['last_analysis_stats'])) {
        $stats = $vt['data']['attributes']['last_analysis_stats'];
        $results['virustotal'] = [
            'found'      => true,
            'malicious'  => $stats['malicious'] ?? 0,
            'suspicious' => $stats['suspicious'] ?? 0,
            'harmless'   => $stats['harmless'] ?? 0,
            'undetected' => $stats['undetected'] ?? 0,
            'link'       => "https://www.virustotal.com/gui/file/$hash",
        ];
        if (($stats['malicious'] ?? 0) > 0) {
            $results['verdict']  = 'malicious';
            $results['severity'] = 'critical';
        }
    } elseif ($res['code'] === 404) {
        $results['virustotal'] = ['found' => false, 'message' => 'Hash not in VT database (file never submitted)'];
    } else {
        $results['virustotal'] = ['error' => "VT HTTP $res[code]"];
    }
}

// ── Cleanup ───────────────────────────────────────────────────
@unlink($scan_path);
@rmdir($scan_dir);

// ── Log result ────────────────────────────────────────────────
$log = date('Y-m-d H:i:s') . ' | FILE | ' . $results['sha256'] . ' | ' . $results['verdict'] . ' | ' . $results['filename'] . PHP_EOL;
@file_put_contents(LOG_DIR . 'scans.log', $log, FILE_APPEND | LOCK_EX);

json_out($results);
