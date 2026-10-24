<?php
declare(strict_types=1);
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/evidence.php';

function client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/** Ruta de un archivo estático con su versión, para que el navegador no use una copia vieja. */
function asset(string $path): string
{
    $file = __DIR__ . '/../' . $path;
    return $path . (is_file($file) ? '?v=' . filemtime($file) : '');
}

function esc(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

/** Etiqueta visible para distinguir eventos del simulador de eventos reales. */
function sim_badge($isSimulation): string
{
    return (int)$isSimulation === 1 ? ' <span class="badge text-bg-dark border border-warning text-warning">SIMULADO</span>' : '';
}

/** Estado del colector Syslog según su archivo de latido (storage/collector_status.json). */
function collector_status(): array
{
    $file = __DIR__ . '/../storage/collector_status.json';
    $data = is_file($file) ? (json_decode((string)@file_get_contents($file), true) ?: []) : [];
    $last = isset($data['last_heartbeat']) ? strtotime((string)$data['last_heartbeat']) : 0;
    $data['running'] = empty($data['stopped']) && $last > 0 && (time() - $last) <= 45;
    // Si alguien lo detuvo a mano, no se vuelve a encender solo durante ese mismo día.
    if (!empty($data['stopped_by_user']) && substr((string)($data['stopped_at'] ?? ''), 0, 10) !== date('Y-m-d')) $data['stopped_by_user'] = false;
    $data['age'] = $last > 0 ? time() - $last : null;
    return $data;
}

/**
 * Enciende el colector Syslog en segundo plano (sin ventana).
 * No hace nada si ya se intentó encender hace menos de 60 segundos.
 */
function collector_launch(bool $force = false): bool
{
    $dir = __DIR__ . '/../storage';
    $stamp = $dir . '/collector_launch.txt';
    if (!$force && is_file($stamp) && time() - (int)@file_get_contents($stamp) < 60) return false;
    @file_put_contents($stamp, (string)time());
    @unlink($dir . '/collector_stop.flag');
    $script = realpath(__DIR__ . '/../collector/syslog_collector.php');
    if (!$script) return false;
    if (PHP_OS_FAMILY === 'Windows') {
        // Ruta real de php.exe de XAMPP (PHP_BINDIR trae una ruta de compilación que no existe).
        $php = null;
        $ini = php_ini_loaded_file();
        foreach ([$ini ? dirname($ini) . '\\php.exe' : null, dirname(__DIR__, 3) . '\\php\\php.exe', 'C:\\xampp\\php\\php.exe'] as $c) {
            if ($c && is_file($c)) { $php = $c; break; }
        }
        if (!$php) return false;
        $cmd = 'start "SecureWatchColector" /B "' . $php . '" "' . $script . '" --background > NUL 2>&1';
        $h = @popen($cmd, 'r');
        if ($h) pclose($h);
        return (bool)$h;
    }
    $php = (PHP_BINARY && !str_contains(PHP_BINARY, 'fpm')) ? PHP_BINARY : 'php';
    exec(escapeshellarg($php) . ' ' . escapeshellarg($script) . ' --background > /dev/null 2>&1 &');
    return true;
}

/** Pide al colector que se detenga (lo hace en menos de 5 segundos). */
function collector_request_stop(): void
{
    @file_put_contents(__DIR__ . '/../storage/collector_stop.flag', date('Y-m-d H:i:s'));
}

/** Últimas líneas de la terminal del colector (storage/collector.log). */
function collector_tail(int $lines = 40): array
{
    $file = __DIR__ . '/../storage/collector.log';
    if (!is_file($file)) return [];
    $size = filesize($file);
    $fh = fopen($file, 'rb');
    if (!$fh) return [];
    fseek($fh, max(0, $size - 64 * 1024));
    $data = stream_get_contents($fh);
    fclose($fh);
    $rows = preg_split('/\r?\n/', trim((string)$data));
    return array_slice($rows, -$lines);
}

function severity_badge(string $severity): string
{
    return match ($severity) {
        'critical' => 'danger',
        'high' => 'warning',
        'medium' => 'info',
        'low' => 'secondary',
        default => 'secondary',
    };
}

function status_badge(string $status): string
{
    return match ($status) {
        'new', 'open' => 'danger',
        'investigating' => 'warning',
        'contained' => 'info',
        'resolved' => 'success',
        'closed' => 'secondary',
        'false_positive' => 'dark',
        default => 'secondary',
    };
}

function human_status(string $status): string
{
    return match ($status) {
        'new' => 'Nueva',
        'open' => 'Nuevo',
        'investigating' => 'Investigando',
        'contained' => 'Contenido',
        'resolved' => 'Resuelto',
        'closed' => 'Cerrado',
        'false_positive' => 'Falso positivo',
        default => ucfirst(str_replace('_', ' ', $status)),
    };
}

function severity_rank(string $severity): int
{
    return match ($severity) {
        'critical' => 4,
        'high' => 3,
        'medium' => 2,
        default => 1,
    };
}

function default_event_severity(string $eventType): string
{
    return match ($eventType) {
        'LOGIN_FAILED', 'ACCESS_DENIED', 'ACCESS_DENIED_ADMIN' => 'medium',
        'ADMIN_ACTION', 'ROLE_CHANGED', 'PERMISSION_CHANGED', 'USER_DELETED' => 'medium',
        'DATA_EXPORT', 'PASSWORD_RESET', 'ROUTER_CONFIG_CHANGE', 'API_AUTH_FAILED', 'LOGIN_BLOCKED' => 'medium',
        'PRICE_CHANGED', 'SALE_VOIDED', 'INVENTORY_ADJUSTMENT', 'PASSWORD_RESET_INVALID_TOKEN', 'PASSWORD_CHANGE_FAILED' => 'medium',
        default => 'low',
    };
}

function normalize_event_timestamp(?string $timestamp): string
{
    if (!$timestamp) return date('Y-m-d H:i:s');
    try {
        $dt = new DateTimeImmutable($timestamp);
        $dt = $dt->setTimezone(new DateTimeZone(APP_TIMEZONE));
        return $dt->format('Y-m-d H:i:s');
    } catch (Throwable $e) {
        return date('Y-m-d H:i:s');
    }
}

/**
 * Registra un evento y ejecuta inmediatamente el motor de correlación.
 * Mantiene compatibilidad con las llamadas del MVP y permite datos HTTP externos.
 */
function log_event(
    PDO $pdo,
    string $eventType,
    string $description,
    string $result = 'success',
    string $severity = 'low',
    ?int $userId = null,
    ?string $username = null,
    array $metadata = [],
    string $sourceKey = 'SECUREWATCH-INTERNAL',
    ?string $ipOverride = null,
    ?string $httpMethod = null,
    ?string $endpoint = null,
    ?string $requestData = null,
    ?string $externalEventId = null,
    ?int $sourceId = null,
    ?string $timestamp = null
): int {
    $eventType = strtoupper(trim($eventType));
    $sourceKey = trim($sourceKey) ?: 'SECUREWATCH-INTERNAL';
    $ip = $ipOverride ?: client_ip();
    $severity = in_array($severity, ['low','medium','high','critical'], true) ? $severity : default_event_severity($eventType);
    // La hora del evento es SIEMPRE la del servidor SIEM al recibirlo.
    // La hora informada por la fuente se guarda aparte (reported_at) como dato de referencia.
    $createdAt = date('Y-m-d H:i:s');
    $reportedAt = $timestamp !== null && $timestamp !== '' ? normalize_event_timestamp($timestamp) : null;
    $isSimulation = !empty($metadata['simulation']) ? 1 : 0;

    $pdo->query("SELECT GET_LOCK('securewatch_event_chain', 10)");
    try {
        $stmt = $pdo->prepare('INSERT INTO events
            (source_id,source_key,external_event_id,user_id,username,event_type,ip_address,http_method,endpoint,request_data,description,result,severity,is_simulation,metadata,created_at,reported_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
        $stmt->execute([
            $sourceId,
            $sourceKey,
            $externalEventId,
            $userId,
            $username !== null ? mb_substr($username, 0, 60) : null,
            mb_substr($eventType, 0, 80),
            mb_substr($ip, 0, 45),
            $httpMethod ? strtoupper(substr($httpMethod, 0, 12)) : null,
            $endpoint !== null ? mb_substr($endpoint, 0, 500) : null,
            $requestData !== null ? mb_substr($requestData, 0, 8000) : null,
            mb_substr($description, 0, 255),
            mb_substr($result, 0, 30),
            $severity,
            $isSimulation,
            json_encode($metadata, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            $createdAt,
            $reportedAt,
        ]);
        $eventId = (int)$pdo->lastInsertId();
        seal_event($pdo, $eventId);
    } finally {
        $pdo->query("SELECT RELEASE_LOCK('securewatch_event_chain')");
    }

    evaluate_rules($pdo, $eventId);
    return $eventId;
}

/**
 * Cadena de integridad de la bitácora.
 * Cada evento guarda el hash del evento anterior y su propio hash SHA-256.
 * Si alguien modifica o borra un evento directamente en la base de datos,
 * la verificación (integridad.php) detecta en qué punto se rompió la cadena.
 * La severidad no forma parte del sello porque el motor de reglas puede elevarla.
 */
function event_chain_hash(array $e, ?string $prevHash): string
{
    $fields = [];
    foreach (['id','source_key','external_event_id','user_id','username','event_type','ip_address','http_method','endpoint','request_data','description','result','is_simulation','metadata','created_at','reported_at'] as $f) {
        $v = $e[$f] ?? null;
        $fields[$f] = $v === null ? null : (string)$v;
    }
    return hash('sha256', ($prevHash ?? 'GENESIS') . '|' . json_encode($fields, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
}

function seal_event(PDO $pdo, int $eventId): void
{
    $prev = $pdo->prepare('SELECT integrity_hash FROM events WHERE id < ? AND integrity_hash IS NOT NULL ORDER BY id DESC LIMIT 1');
    $prev->execute([$eventId]);
    $prevHash = $prev->fetchColumn() ?: null;
    $row = $pdo->prepare('SELECT * FROM events WHERE id=?');
    $row->execute([$eventId]);
    $e = $row->fetch();
    if (!$e) return;
    $pdo->prepare('UPDATE events SET prev_hash=?, integrity_hash=? WHERE id=?')
        ->execute([$prevHash, event_chain_hash($e, $prevHash), $eventId]);
}

/** Recorre la cadena completa y devuelve el resultado de la verificación. */
function verify_event_chain(PDO $pdo): array
{
    $unsealed = (int)$pdo->query('SELECT COUNT(*) FROM events WHERE integrity_hash IS NULL')->fetchColumn();
    $stmt = $pdo->query('SELECT * FROM events WHERE integrity_hash IS NOT NULL ORDER BY id');
    $expectedPrev = null;
    $first = true;
    $checked = 0;
    while ($e = $stmt->fetch()) {
        $checked++;
        $storedPrev = $e['prev_hash'] ?: null;
        if (!$first && $storedPrev !== $expectedPrev) {
            return ['ok'=>false,'checked'=>$checked,'unsealed'=>$unsealed,'broken_id'=>(int)$e['id'],
                'reason'=>'El enlace con el evento anterior no coincide: falta un evento o fue alterado.'];
        }
        if (!hash_equals((string)$e['integrity_hash'], event_chain_hash($e, $storedPrev))) {
            return ['ok'=>false,'checked'=>$checked,'unsealed'=>$unsealed,'broken_id'=>(int)$e['id'],
                'reason'=>'El contenido del evento no coincide con su sello: fue modificado después de registrarse.'];
        }
        $expectedPrev = (string)$e['integrity_hash'];
        $first = false;
    }
    return ['ok'=>true,'checked'=>$checked,'unsealed'=>$unsealed,'broken_id'=>null,'reason'=>null];
}

function attach_alert_events(PDO $pdo, int $alertId, array $eventIds): void
{
    if (!$eventIds) return;
    $stmt = $pdo->prepare('INSERT IGNORE INTO alert_events(alert_id,event_id,relation_type) VALUES(?,?,?)');
    foreach (array_unique(array_map('intval', $eventIds)) as $eventId) {
        if ($eventId > 0) $stmt->execute([$alertId, $eventId, 'evidence']);
    }
}

function raise_event_severity(PDO $pdo, int $eventId, string $severity): void
{
    $stmt = $pdo->prepare('SELECT severity FROM events WHERE id=?');
    $stmt->execute([$eventId]);
    $current = (string)$stmt->fetchColumn();
    if ($current && severity_rank($severity) > severity_rank($current)) {
        $pdo->prepare('UPDATE events SET severity=? WHERE id=?')->execute([$severity, $eventId]);
    }
}

/**
 * Crea una alerta o agrega evidencia a una alerta activa del mismo contexto.
 * Esto evita inundar el SOC con una alerta nueva por cada evento del mismo ataque.
 */
function create_or_update_alert(
    PDO $pdo,
    array $rule,
    array $event,
    string $title,
    string $contextKey,
    array $evidenceIds
): int {
    $window = max(1, (int)$rule['window_minutes']);
    $find = $pdo->prepare("SELECT id FROM alerts
        WHERE rule_id=? AND context_key=? AND status IN ('new','investigating')
          AND created_at >= DATE_SUB(?, INTERVAL {$window} MINUTE)
        ORDER BY id DESC LIMIT 1");
    $find->execute([(int)$rule['id'], $contextKey, $event['created_at']]);
    $existing = (int)($find->fetchColumn() ?: 0);

    if ($existing > 0) {
        attach_alert_events($pdo, $existing, array_merge($evidenceIds, [(int)$event['id']]));
        raise_event_severity($pdo, (int)$event['id'], $rule['severity']);
        return $existing;
    }

    $stmt = $pdo->prepare('INSERT INTO alerts
        (event_id,rule_id,source_id,user_id,title,severity,status,risk_score,context_key,created_at)
        VALUES (?,?,?,?,?,?,\'new\',?,?,?)');
    $stmt->execute([
        (int)$event['id'],
        (int)$rule['id'],
        $event['source_id'] !== null ? (int)$event['source_id'] : null,
        $event['user_id'] !== null ? (int)$event['user_id'] : null,
        mb_substr($title, 0, 255),
        $rule['severity'],
        (int)$rule['risk_score'],
        mb_substr($contextKey, 0, 190),
        $event['created_at'],
    ]);
    $alertId = (int)$pdo->lastInsertId();
    attach_alert_events($pdo, $alertId, array_merge($evidenceIds, [(int)$event['id']]));
    raise_event_severity($pdo, (int)$event['id'], $rule['severity']);
    return $alertId;
}

function event_ids_for_window(PDO $pdo, array $event, array $types, int $windowMinutes, bool $sameUsername = false): array
{
    $placeholders = implode(',', array_fill(0, count($types), '?'));
    $sql = "SELECT id FROM events WHERE event_type IN ({$placeholders})
            AND source_key=? AND ip_address=?
            AND created_at >= DATE_SUB(?, INTERVAL {$windowMinutes} MINUTE)
            AND created_at <= ?";
    $params = array_values($types);
    $params[] = $event['source_key'];
    $params[] = $event['ip_address'];
    $params[] = $event['created_at'];
    $params[] = $event['created_at'];
    if ($sameUsername) {
        $sql .= ' AND username <=> ?';
        $params[] = $event['username'];
    }
    $sql .= ' ORDER BY id';
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return array_map('intval', array_column($stmt->fetchAll(), 'id'));
}

function suspicious_route(string $endpoint): bool
{
    $endpoint = strtolower(urldecode($endpoint));
    $needles = ['/.env','.git','phpinfo.php','backup.sql','config.php','wp-admin','wp-login','.bak','database.sql','/admin/backup'];
    foreach ($needles as $needle) {
        if (str_contains($endpoint, $needle)) return true;
    }
    return false;
}

/** Metadata que envió la fuente (se guarda dentro de "client" en el evento). */
function event_client_meta(array $event): array
{
    $m = json_decode((string)($event['metadata'] ?? ''), true);
    return is_array($m['client'] ?? null) ? $m['client'] : [];
}

function evaluate_rules(PDO $pdo, int $eventId): array
{
    $stmt = $pdo->prepare('SELECT * FROM events WHERE id=?');
    $stmt->execute([$eventId]);
    $event = $stmt->fetch();
    if (!$event) return [];

    $rules = $pdo->query('SELECT * FROM rules WHERE enabled=1')->fetchAll();
    $createdAlertIds = [];
    $eventType = (string)$event['event_type'];
    $source = (string)$event['source_key'];
    $ip = (string)$event['ip_address'];
    $username = (string)($event['username'] ?? 'anonymous');
    $haystack = strtolower(urldecode((string)($event['endpoint'] ?? '') . ' ' . (string)($event['request_data'] ?? '') . ' ' . (string)$event['description']));

    foreach ($rules as $rule) {
        $key = (string)$rule['rule_key'];
        $threshold = max(1, (int)$rule['threshold_value']);
        $window = max(1, (int)$rule['window_minutes']);
        $evidence = [];
        $title = null;
        $context = '';

        if ($key === 'BRUTE_FORCE' && $eventType === 'LOGIN_FAILED') {
            $evidence = event_ids_for_window($pdo, $event, ['LOGIN_FAILED'], $window, true);
            if (count($evidence) >= $threshold) {
                $title = 'Posible fuerza bruta contra ' . ($username ?: 'usuario desconocido');
                $context = implode('|', [$key,$source,$ip,$username]);
            }
        }

        if ($key === 'PASSWORD_SPRAY' && $eventType === 'LOGIN_FAILED') {
            $sql = "SELECT id, username FROM events WHERE event_type='LOGIN_FAILED' AND source_key=? AND ip_address=?
                    AND created_at >= DATE_SUB(?, INTERVAL {$window} MINUTE) AND created_at <= ? ORDER BY id";
            $q = $pdo->prepare($sql);
            $q->execute([$source,$ip,$event['created_at'],$event['created_at']]);
            $rows = $q->fetchAll();
            $distinct = array_unique(array_filter(array_map(fn($r)=>(string)$r['username'],$rows)));
            if (count($distinct) >= $threshold) {
                $evidence = array_map('intval', array_column($rows,'id'));
                $title = 'Posible password spraying desde ' . $ip;
                $context = implode('|', [$key,$source,$ip]);
            }
        }

        if ($key === 'ACCESS_DENIED' && in_array($eventType, ['ACCESS_DENIED','ACCESS_DENIED_ADMIN'], true)) {
            $evidence = event_ids_for_window($pdo, $event, ['ACCESS_DENIED','ACCESS_DENIED_ADMIN'], $window, false);
            if (count($evidence) >= $threshold) {
                $title = 'Accesos no autorizados repetidos desde ' . $ip;
                $context = implode('|', [$key,$source,$ip]);
            }
        }

        if ($key === 'XSS_ATTEMPT' && $eventType === 'HTTP_REQUEST') {
            $patterns = [
                '/<\s*script\b/i', '/javascript\s*:/i', '/on(?:error|load|click|mouseover)\s*=/i',
                '/<\s*iframe\b/i', '/document\.cookie/i', '/<\s*svg\b[^>]*\bonload\s*=/i'
            ];
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $haystack)) {
                    $title = 'Posible intento de XSS desde ' . $ip;
                    $context = implode('|', [$key,$source,$ip]);
                    $evidence = [$eventId];
                    break;
                }
            }
        }

        if ($key === 'SQL_INJECTION' && $eventType === 'HTTP_REQUEST') {
            $patterns = [
                '/\bunion\s+(?:all\s+)?select\b/i',
                '/[\'\"]\s*or\s+[\'\"\d]+\s*=\s*[\'\"\d]+/i',
                '/\binformation_schema\b/i', '/\bdrop\s+table\b/i',
                '/\bsleep\s*\(/i', '/\bbenchmark\s*\(/i', '/\bselect\b.+\bfrom\b/i'
            ];
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $haystack)) {
                    $title = 'Posible intento de SQL Injection desde ' . $ip;
                    $context = implode('|', [$key,$source,$ip]);
                    $evidence = [$eventId];
                    break;
                }
            }
        }

        if ($key === 'PATH_TRAVERSAL' && $eventType === 'HTTP_REQUEST') {
            if (preg_match('/(?:\.\.\/|%2e%2e(?:%2f|\/)|%252e%252e)|(?:\/etc\/passwd|windows\/win\.ini)/i', $haystack)) {
                $title = 'Posible Path Traversal desde ' . $ip;
                $context = implode('|', [$key,$source,$ip]);
                $evidence = [$eventId];
            }
        }

        if ($key === 'ROUTE_SCAN' && $eventType === 'HTTP_REQUEST' && suspicious_route((string)$event['endpoint'])) {
            $sql = "SELECT id, endpoint FROM events WHERE event_type='HTTP_REQUEST' AND source_key=? AND ip_address=?
                    AND created_at >= DATE_SUB(?, INTERVAL {$window} MINUTE) AND created_at <= ? ORDER BY id";
            $q = $pdo->prepare($sql);
            $q->execute([$source,$ip,$event['created_at'],$event['created_at']]);
            $rows = array_values(array_filter($q->fetchAll(), fn($r)=>suspicious_route((string)$r['endpoint'])));
            if (count($rows) >= $threshold) {
                $evidence = array_map('intval', array_column($rows,'id'));
                $title = 'Posible escaneo de rutas sensibles desde ' . $ip;
                $context = implode('|', [$key,$source,$ip]);
            }
        }

        if ($key === 'NIGHT_LOGIN' && $eventType === 'LOGIN_SUCCESS') {
            $hour = (int)date('G', strtotime((string)$event['created_at']));
            if ($hour >= 0 && $hour < min(24, $threshold)) {
                $title = 'Inicio de sesión en horario inusual';
                $context = implode('|', [$key,$source,$ip,$username,date('Y-m-d',strtotime((string)$event['created_at']))]);
                $evidence = [$eventId];
            }
        }

        if ($key === 'SENSITIVE_ADMIN' && in_array($eventType, ['ADMIN_ACTION','ROLE_CHANGED','PERMISSION_CHANGED','USER_DELETED','PASSWORD_RESET','ROUTER_CONFIG_CHANGE'], true)) {
            $title = 'Acción administrativa sensible: ' . $eventType;
            $context = implode('|', [$key,$source,$username,$eventType]);
            $evidence = [$eventId];
        }

        if ($key === 'MASS_DOWNLOAD' && in_array($eventType, ['FILE_DOWNLOAD','DATA_EXPORT'], true)) {
            $evidence = event_ids_for_window($pdo, $event, ['FILE_DOWNLOAD','DATA_EXPORT'], $window, false);
            if (count($evidence) >= $threshold) {
                $title = 'Posible extracción masiva de información desde ' . $ip;
                $context = implode('|', [$key,$source,$ip,$username]);
            }
        }

        if ($key === 'PORT_SCAN' && $eventType === 'FIREWALL_CONNECTION') {
            $sql = "SELECT id, endpoint FROM events WHERE event_type='FIREWALL_CONNECTION' AND source_key=? AND ip_address=?
                    AND created_at >= DATE_SUB(?, INTERVAL {$window} MINUTE) AND created_at <= ? ORDER BY id";
            $q = $pdo->prepare($sql);
            $q->execute([$source,$ip,$event['created_at'],$event['created_at']]);
            $rows = $q->fetchAll();
            $ports = array_unique(array_filter(array_map(fn($r)=>(string)$r['endpoint'], $rows)));
            if (count($ports) >= $threshold) {
                $evidence = array_map('intval', array_column($rows,'id'));
                $title = 'Posible escaneo de puertos desde ' . $ip . ' (' . count($ports) . ' puertos)';
                $context = implode('|', [$key,$source,$ip]);
            }
        }

        // ---- Reglas de negocio del portal (ventas e inventario) ----
        if ($key === 'PRICE_MANIPULATION' && $eventType === 'PRICE_CHANGED') {
            $m = event_client_meta($event);
            $drop = -(float)($m['variacion_pct'] ?? 0);
            if ($drop >= $threshold) {
                $title = sprintf('Rebaja de precio de %.0f%% en %s por %s', $drop, (string)($m['codigo'] ?? '?'), $username);
                $context = implode('|', [$key,$source,(string)($m['codigo'] ?? ''),$username]);
                $evidence = [$eventId];
            }
        }

        if ($key === 'PRICE_DROP_SALE' && $eventType === 'SALE_CREATED') {
            $codes = array_column((array)(event_client_meta($event)['items'] ?? []), 'codigo');
            if ($codes) {
                $q = $pdo->prepare("SELECT id, username, metadata FROM events WHERE event_type='PRICE_CHANGED' AND source_key=?
                    AND created_at >= DATE_SUB(?, INTERVAL {$window} MINUTE) AND created_at <= ? ORDER BY id");
                $q->execute([$source, $event['created_at'], $event['created_at']]);
                foreach ($q->fetchAll() as $pc) {
                    $m = event_client_meta($pc);
                    $drop = -(float)($m['variacion_pct'] ?? 0);
                    if (in_array($m['codigo'] ?? null, $codes, true) && $drop >= $threshold) {
                        $evidence[] = (int)$pc['id'];
                        $title = sprintf('Venta de %s poco después de rebajar su precio %.0f%% (rebaja: %s, venta: %s)',
                            (string)$m['codigo'], $drop, (string)$pc['username'], $username);
                        $context = implode('|', [$key,$source,(string)$m['codigo']]);
                    }
                }
            }
        }

        if ($key === 'VOID_ABUSE' && $eventType === 'SALE_VOIDED') {
            $q = $pdo->prepare("SELECT id FROM events WHERE event_type='SALE_VOIDED' AND source_key=? AND username <=> ?
                AND created_at >= DATE_SUB(?, INTERVAL {$window} MINUTE) AND created_at <= ? ORDER BY id");
            $q->execute([$source, $event['username'], $event['created_at'], $event['created_at']]);
            $ids = array_map('intval', array_column($q->fetchAll(), 'id'));
            if (count($ids) >= $threshold) {
                $evidence = $ids;
                $title = 'Anulaciones de ventas repetidas por ' . $username . ' (' . count($ids) . ')';
                $context = implode('|', [$key,$source,$username]);
            }
        }

        if ($key === 'NEGATIVE_ADJUSTMENT' && $eventType === 'INVENTORY_ADJUSTMENT') {
            $m = event_client_meta($event);
            $qty = (int)($m['cantidad'] ?? 0);
            if ($qty <= -$threshold) {
                $title = sprintf('Ajuste de inventario de %d unidades en %s por %s', $qty, (string)($m['codigo'] ?? '?'), $username);
                $context = implode('|', [$key,$source,(string)($m['codigo'] ?? ''),(string)$eventId]);
                $evidence = [$eventId];
            }
        }

        if ($key === 'RESET_ABUSE' && in_array($eventType, ['PASSWORD_RESET_REQUEST','PASSWORD_RESET_INVALID_TOKEN'], true)) {
            $evidence = event_ids_for_window($pdo, $event, ['PASSWORD_RESET_REQUEST','PASSWORD_RESET_INVALID_TOKEN'], $window, false);
            if (count($evidence) >= $threshold) {
                $title = 'Abuso de recuperación de contraseña desde ' . $ip;
                $context = implode('|', [$key,$source,$ip]);
            }
        }

        if ($key === 'API_AUTH_FAILURE' && $eventType === 'API_AUTH_FAILED') {
            $evidence = event_ids_for_window($pdo, $event, ['API_AUTH_FAILED'], $window, false);
            if (count($evidence) >= $threshold) {
                $title = 'Envíos de eventos no autorizados desde ' . $ip;
                $context = implode('|', [$key,$source,$ip]);
            }
        }

        if ($title !== null && $context !== '') {
            $createdAlertIds[] = create_or_update_alert($pdo, $rule, $event, $title, $context, $evidence);
        }
    }

    return array_values(array_unique($createdAlertIds));
}

function risk_score_for_user(PDO $pdo, int $userId): int
{
    $stmt = $pdo->prepare("SELECT COALESCE(SUM(CASE severity WHEN 'critical' THEN 35 WHEN 'high' THEN 25 WHEN 'medium' THEN 15 ELSE 5 END),0)
        FROM events WHERE user_id=? AND created_at >= (NOW() - INTERVAL 24 HOUR)");
    $stmt->execute([$userId]);
    return min(100, (int)$stmt->fetchColumn());
}

function api_header(string $name): ?string
{
    $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    if (isset($_SERVER[$key])) return (string)$_SERVER[$key];
    if (function_exists('getallheaders')) {
        foreach (getallheaders() as $k => $v) {
            if (strcasecmp((string)$k, $name) === 0) return (string)$v;
        }
    }
    return null;
}

function incident_history(PDO $pdo, int $incidentId, ?int $userId, string $action, ?string $fromStatus, ?string $toStatus, ?string $details=null): void
{
    $stmt = $pdo->prepare('INSERT INTO incident_history(incident_id,user_id,action,from_status,to_status,details) VALUES(?,?,?,?,?,?)');
    $stmt->execute([$incidentId,$userId,$action,$fromStatus,$toStatus,$details ? mb_substr($details,0,255) : null]);
}
