<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/functions.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success'=>false,'message'=>'Method not allowed']);
    exit;
}

$raw = file_get_contents('php://input');
if (strlen((string)$raw) > 65536) {
    http_response_code(413);
    echo json_encode(['success'=>false,'message'=>'Payload too large']);
    exit;
}
$data = json_decode($raw ?: '', true);
if (!is_array($data)) {
    http_response_code(400);
    echo json_encode(['success'=>false,'message'=>'Invalid JSON']);
    exit;
}

$sourceKey = trim((string)($data['source'] ?? ''));
$eventType = strtoupper(trim((string)($data['event_type'] ?? '')));
$apiKey = (string)(api_header('X-API-Key') ?? '');

if ($sourceKey === '' || $eventType === '') {
    http_response_code(400);
    echo json_encode(['success'=>false,'message'=>'source and event_type are required']);
    exit;
}
if (!preg_match('/^[A-Z0-9_\-]{2,80}$/', $eventType)) {
    http_response_code(400);
    echo json_encode(['success'=>false,'message'=>'Invalid event_type']);
    exit;
}

const API_MAX_EVENTS_PER_MINUTE = 600; // límite por fuente para evitar inundación

$pdo = db();

/** Registra en el SIEM un intento de envío rechazado (queda como evidencia). */
function api_reject(PDO $pdo, int $code, string $message, string $reason, string $claimedSource): never
{
    try {
        log_event($pdo, 'API_AUTH_FAILED', $reason, 'rejected', 'medium', null, null,
            ['transport'=>'external_api','claimed_source'=>mb_substr($claimedSource,0,80),'http_code'=>$code],
            'SECUREWATCH-API', client_ip());
    } catch (Throwable $e) {}
    http_response_code($code);
    echo json_encode(['success'=>false,'message'=>$message]);
    exit;
}

$stmt = $pdo->prepare('SELECT * FROM sources WHERE source_key=? AND active=1 LIMIT 1');
$stmt->execute([$sourceKey]);
$source = $stmt->fetch();
if (!$source || $apiKey === '' || !hash_equals((string)$source['api_key_hash'], hash('sha256', $apiKey))) {
    api_reject($pdo, 401, 'Unauthorized source', 'API Key inválida o fuente inexistente/desactivada: ' . $sourceKey, $sourceKey);
}
if (!empty($source['expected_ip']) && !hash_equals((string)$source['expected_ip'], client_ip())) {
    api_reject($pdo, 403, 'Source IP not allowed', 'Envío desde IP no autorizada para la fuente ' . $sourceKey, $sourceKey);
}
$rate = $pdo->prepare('SELECT COUNT(*) FROM events WHERE source_key=? AND created_at >= (NOW() - INTERVAL 1 MINUTE)');
$rate->execute([$sourceKey]);
if ((int)$rate->fetchColumn() >= API_MAX_EVENTS_PER_MINUTE) {
    http_response_code(429);
    echo json_encode(['success'=>false,'message'=>'Too many events']);
    exit;
}

$externalId = trim((string)($data['event_id'] ?? '')) ?: null;
if ($externalId !== null) {
    $dup = $pdo->prepare('SELECT id FROM events WHERE source_id=? AND external_event_id=? LIMIT 1');
    $dup->execute([(int)$source['id'], $externalId]);
    $existing = (int)($dup->fetchColumn() ?: 0);
    if ($existing > 0) {
        echo json_encode(['success'=>true,'message'=>'Duplicate ignored','event_id'=>$existing,'duplicate'=>true]);
        exit;
    }
}

$username = trim((string)($data['username'] ?? 'anonymous')) ?: 'anonymous';
$ip = trim((string)($data['ip'] ?? ''));
if (filter_var($ip, FILTER_VALIDATE_IP) === false) $ip = client_ip();
$result = strtoupper(trim((string)($data['result'] ?? 'INFO')));
$description = trim((string)($data['description'] ?? $eventType));
$method = isset($data['method']) ? trim((string)$data['method']) : null;
$endpoint = isset($data['endpoint']) ? trim((string)$data['endpoint']) : null;
$requestData = isset($data['request_data']) ? (is_string($data['request_data']) ? $data['request_data'] : json_encode($data['request_data'], JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)) : null;
$timestamp = isset($data['timestamp']) ? (string)$data['timestamp'] : null;

// Los campos del servidor no pueden ser sobrescritos por la fuente:
// la metadata enviada por el cliente se guarda aparte, dentro de "client".
$metadata = [
    'transport' => 'external_api',
    'sender_ip' => client_ip(),
];
if (isset($data['metadata']) && is_array($data['metadata'])) {
    $metadata['client'] = $data['metadata'];
}

try {
    $eventId = log_event(
        $pdo,
        $eventType,
        $description,
        $result,
        default_event_severity($eventType),
        null,
        mb_substr($username,0,60),
        $metadata,
        $sourceKey,
        mb_substr($ip,0,45),
        $method,
        $endpoint,
        $requestData,
        $externalId,
        (int)$source['id'],
        $timestamp
    );
    $pdo->prepare('UPDATE sources SET last_seen_at=NOW() WHERE id=?')->execute([(int)$source['id']]);

    $a = $pdo->prepare('SELECT DISTINCT alert_id FROM alert_events WHERE event_id=?');
    $a->execute([$eventId]);
    $alerts = array_map('intval', array_column($a->fetchAll(), 'alert_id'));

    echo json_encode([
        'success'=>true,
        'message'=>'Event received',
        'event_id'=>$eventId,
        'alerts'=>$alerts,
    ], JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
} catch (PDOException $e) {
    if ((string)$e->getCode() === '23000' && $externalId !== null) {
        http_response_code(200);
        echo json_encode(['success'=>true,'message'=>'Duplicate ignored']);
        exit;
    }
    http_response_code(500);
    echo json_encode(['success'=>false,'message'=>'Internal database error']);
}
