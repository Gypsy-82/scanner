<?php
// Shared auth + CSRF helper — required by every API endpoint

$config_path = __DIR__ . '/../../../config.php';
if (!file_exists($config_path)) {
    http_response_code(500);
    die(json_encode(['error' => 'Config missing. See install instructions.']));
}
require_once $config_path;

// Session config — must run before session_start()
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.name', 'scanner_sess');
ini_set('session.gc_maxlifetime', SESSION_TIMEOUT);
session_start();

function require_auth(): void {
    if (empty($_SESSION['authenticated']) || empty($_SESSION['last_active'])) {
        http_response_code(401);
        die(json_encode(['error' => 'Not authenticated']));
    }
    if (time() - $_SESSION['last_active'] > SESSION_TIMEOUT) {
        session_destroy();
        http_response_code(401);
        die(json_encode(['error' => 'Session expired']));
    }
    $_SESSION['last_active'] = time();
}

function verify_csrf(): void {
    $token = $_POST['csrf'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    if (empty($token) || !hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
        http_response_code(403);
        die(json_encode(['error' => 'Invalid CSRF token']));
    }
}

function json_out(array $data): void {
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

// Outbound HTTP helper
function http_get(string $url, array $headers = [], int $timeout = HTTP_TIMEOUT): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT      => 'SecurityScanner/1.0',
        CURLOPT_HTTPHEADER     => $headers,
    ]);
    $body   = curl_exec($ch);
    $code   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error  = curl_error($ch);
    curl_close($ch);
    return ['body' => $body, 'code' => $code, 'error' => $error];
}

function http_post(string $url, array $post_fields, array $headers = [], int $timeout = HTTP_TIMEOUT): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $post_fields,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT      => 'SecurityScanner/1.0',
        CURLOPT_HTTPHEADER     => $headers,
    ]);
    $body  = curl_exec($ch);
    $code  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    return ['body' => $body, 'code' => $code, 'error' => $error];
}
