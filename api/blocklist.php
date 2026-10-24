<?php
/**
 * Lista de IP bloqueadas por SecureWatch.
 *
 * La consultan el MikroTik (cada minuto, desde un script del router) y el portal web.
 * Se autentica con la API Key de la fuente y solo responde a la IP esperada de esa fuente.
 *
 *   ?source=MIKROTIK-RB2011&key=...&format=rsc   → script RouterOS
 *   ?source=WEB-PORTAL  (X-API-Key)  &format=json → {"ips":[...]}
 */
declare(strict_types=1);
require_once __DIR__ . '/../includes/functions.php';

header('Cache-Control: no-store');
$format = ($_GET['format'] ?? 'json') === 'rsc' ? 'rsc' : 'json';
header('Content-Type: ' . ($format === 'rsc' ? 'text/plain' : 'application/json') . '; charset=utf-8');

function bl_fail(int $code, string $msg, string $format): never
{
    http_response_code($code);
    echo $format === 'rsc' ? ':log warning "SecureWatch: ' . $msg . '"' : json_encode(['success' => false, 'message' => $msg]);
    exit;
}

$sourceKey = strtoupper(trim((string)($_GET['source'] ?? '')));
$key = (string)(api_header('X-API-Key') ?? ($_GET['key'] ?? ''));
$pdo = db();
$s = $pdo->prepare('SELECT * FROM sources WHERE source_key=? AND active=1 LIMIT 1');
$s->execute([$sourceKey]);
$source = $s->fetch();
if (!$source || $key === '' || !hash_equals((string)$source['api_key_hash'], hash('sha256', $key))) {
    try {
        log_event($pdo, 'API_AUTH_FAILED', 'Consulta a la lista de bloqueo con credenciales inválidas: ' . mb_substr($sourceKey, 0, 80), 'rejected', 'medium',
            null, null, ['transport' => 'external_api', 'endpoint' => 'blocklist'], 'SECUREWATCH-API', client_ip());
    } catch (Throwable $e) {}
    bl_fail(401, 'credenciales invalidas', $format);
}
if (!empty($source['expected_ip']) && !hash_equals((string)$source['expected_ip'], client_ip())) {
    bl_fail(403, 'IP no autorizada', $format);
}

$ips = array_column(active_blocks($pdo), 'ip_address');
blocklist_pull_record((string)$source['source_key'], count($ips));
echo $format === 'rsc' ? routeros_blocklist_script($ips) : json_encode(['success' => true, 'ips' => $ips]);
