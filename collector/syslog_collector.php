<?php
/**
 * SecureWatch SIEM — Colector Syslog para MikroTik RouterOS.
 *
 * Escucha mensajes Syslog (UDP 514), acepta solo los que llegan desde la IP del router,
 * guarda la línea original como evidencia cruda en /storage, la normaliza y la registra
 * como evento de la fuente MIKROTIK-RB2011 para que el motor de reglas la analice.
 *
 * SecureWatch lo enciende solo en segundo plano cuando un administrador o analista abre
 * el SIEM, y se apaga solo si MySQL deja de estar disponible por 5 minutos o si se
 * detiene desde SecureWatch → Fuentes. Su estado y su terminal se ven en esa página.
 *
 * Uso manual:   C:\xampp\php\php.exe syslog_collector.php
 * Prueba:       php syslog_collector.php --test "<134>system,error,critical login failure for user x from 1.2.3.4 via winbox"
 */
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/syslog_parser.php';

const SYSLOG_LISTEN = 'udp://0.0.0.0:514';
const SYSLOG_ALLOWED_SENDERS = ['192.168.88.1'];   // IP del MikroTik
const SYSLOG_SOURCE_KEY = 'MIKROTIK-RB2011';
const RAW_LOG_DIR = __DIR__ . '/../storage';
const HEARTBEAT_SECONDS = 15;
const DB_GIVE_UP_SECONDS = 300;                         // 5 min sin MySQL → el colector se apaga
const STOP_FLAG = RAW_LOG_DIR . '/collector_stop.flag'; // lo crea el botón "Detener" del SIEM
$BACKGROUND = in_array('--background', $argv, true);

/**
 * Muestra una línea en consola y la guarda en storage/collector.log
 * (el colector corre en segundo plano, así que su "terminal" queda en ese archivo).
 * Al pasar de 5 MB el archivo se rota a collector.log.1.
 */
function out(string $text): void
{
    $line = '[' . date('Y-m-d H:i:s') . '] ' . $text . PHP_EOL;
    if (empty($GLOBALS['BACKGROUND'])) echo $line;
    $file = __DIR__ . '/../storage/collector.log';
    if (is_file($file) && filesize($file) > 5 * 1024 * 1024) { @copy($file, $file . '.1'); @file_put_contents($file, ''); }
    @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
}
/** Descarta la conexión actual a MySQL; la siguiente llamada a db() vuelve a conectar. */
function db_reset(): void { try { db(true); } catch (Throwable $e) {} }

// ---- Modo prueba: solo muestra cómo se interpreta una línea, no toca la base de datos ----
if (($argv[1] ?? '') === '--test') {
    $parsed = routeros_parse((string)($argv[2] ?? ''), $argv[3] ?? '192.168.88.1');
    echo json_encode($parsed, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit(0);
}

// Opcional: --allow=IP para autorizar otro remitente (por ejemplo, si cambia la IP del router).
$allowed = SYSLOG_ALLOWED_SENDERS;
foreach ($argv as $arg) {
    if (str_starts_with($arg, '--allow=') && filter_var(substr($arg, 8), FILTER_VALIDATE_IP)) $allowed[] = substr($arg, 8);
}

$sock = @stream_socket_server(SYSLOG_LISTEN, $errno, $errstr, STREAM_SERVER_BIND);
if (!$sock) {
    // Lo normal es que ya haya otro colector corriendo; en ese caso no se hace nada.
    if (empty($GLOBALS['BACKGROUND'])) out("No se pudo abrir " . SYSLOG_LISTEN . " ($errstr). Probablemente ya hay un colector en ejecución.");
    exit(1);
}

if (!is_dir(RAW_LOG_DIR)) @mkdir(RAW_LOG_DIR, 0750, true);

$state = [
    'pid' => getmypid(),
    'started_at' => date('Y-m-d H:i:s'),
    'last_heartbeat' => date('Y-m-d H:i:s'),
    'last_message_at' => null,
    'received' => 0,
    'rejected' => 0,
    'db' => 'conectando',
    'listen' => SYSLOG_LISTEN,
    'allowed' => $allowed,
];
/** Archivo de latido: SecureWatch lo lee para mostrar si el colector está activo. */
function heartbeat(array &$state): void
{
    $state['last_heartbeat'] = date('Y-m-d H:i:s');
    @file_put_contents(RAW_LOG_DIR . '/collector_status.json', json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
}

/** Termina el colector dejando constancia en su terminal y en el archivo de estado. */
function finish(array &$state, string $reason, bool $logEvent = false, bool $byUser = false): never
{
    out('Colector detenido: ' . $reason);
    if ($logEvent) {
        try {
            log_event(db(), 'COLLECTOR_STOP', 'Colector Syslog detenido: ' . $reason, 'SUCCESS', 'low', null, null,
                ['transport'=>'internal','received'=>$state['received']], 'SECUREWATCH-SYSLOG', '127.0.0.1');
        } catch (Throwable $e) {}
    }
    $state['stopped'] = true;
    $state['stopped_by_user'] = $byUser;
    $state['stop_reason'] = $reason;
    $state['stopped_at'] = date('Y-m-d H:i:s');
    heartbeat($state);
    @unlink(STOP_FLAG);
    exit(0);
}

/** Espera a que la base de datos esté disponible; si no aparece en 5 minutos, se apaga. */
function load_source(array &$state): array
{
    $since = time();
    while (true) {
        if (is_file(STOP_FLAG)) finish($state, 'detenido desde SecureWatch', true, true);
        if (time() - $since > DB_GIVE_UP_SECONDS) finish($state, 'MySQL no estuvo disponible durante 5 minutos');
        try {
            $s = db()->prepare('SELECT id, source_key, active FROM sources WHERE source_key=? LIMIT 1');
            $s->execute([SYSLOG_SOURCE_KEY]);
            $row = $s->fetch();
            if ($row) { $state['db'] = 'ok'; heartbeat($state); return $row; }
            $state['db'] = 'falta la fuente ' . SYSLOG_SOURCE_KEY;
            out('ERROR: no existe la fuente ' . SYSLOG_SOURCE_KEY . '. Importe database/laboratorio_v2.sql.');
        } catch (Throwable $e) {
            $state['db'] = 'sin conexión';
            out('Esperando a MySQL... (' . $e->getMessage() . ')');
            db_reset();
        }
        heartbeat($state);
        sleep(10);
    }
}

@unlink(STOP_FLAG);   // una orden de detener anterior ya no aplica
$source = load_source($state);
out('Colector Syslog de SecureWatch escuchando en ' . SYSLOG_LISTEN);
out('Remitentes permitidos: ' . implode(', ', $allowed) . ' · Fuente: ' . SYSLOG_SOURCE_KEY);
try {
    log_event(db(), 'COLLECTOR_START', 'Colector Syslog iniciado (PID ' . getmypid() . ')', 'SUCCESS', 'low', null, null,
        ['transport'=>'internal','listen'=>SYSLOG_LISTEN,'allowed'=>$allowed], 'SECUREWATCH-SYSLOG', '127.0.0.1');
} catch (Throwable $e) {}

$rejectedNotice = [];
$received = 0;
$lastBeat = 0;
$dbDownSince = null;

while (true) {
    if (is_file(STOP_FLAG)) finish($state, 'detenido desde SecureWatch', true, true);
    if (time() - $lastBeat >= HEARTBEAT_SECONDS) {
        // Comprueba que MySQL siga disponible; si lleva 5 minutos caído, el colector se apaga solo.
        try { db()->query('SELECT 1'); $dbDownSince = null; $state['db'] = 'ok'; }
        catch (Throwable $e) {
            db_reset();
            $dbDownSince ??= time();
            $state['db'] = 'sin conexión';
            if (time() - $dbDownSince > DB_GIVE_UP_SECONDS) finish($state, 'MySQL no estuvo disponible durante 5 minutos');
        }
        heartbeat($state);
        $lastBeat = time();
    }
    $r = [$sock]; $w = null; $x = null;
    if (@stream_select($r, $w, $x, 5) < 1) continue;   // sin mensajes: revisar latido y orden de detener
    $data = stream_socket_recvfrom($sock, 8192, 0, $peer);
    if ($data === false || $data === '') continue;
    $senderIp = preg_replace('/:\d+$/', '', (string)$peer);
    $now = date('Y-m-d H:i:s');

    // Evidencia cruda (un archivo por día). Se guarda TODO lo recibido, incluso lo rechazado.
    @file_put_contents(RAW_LOG_DIR . '/syslog_' . date('Y-m-d') . '.log', "$now\t$senderIp\t" . trim($data) . PHP_EOL, FILE_APPEND | LOCK_EX);

    if (!in_array($senderIp, $allowed, true)) {
        $state['rejected']++;
        out("RECHAZADO: mensaje desde $senderIp (no autorizado)");
        // Se registra como evento como máximo una vez por minuto por IP, para no inundar el SIEM.
        if (time() - ($rejectedNotice[$senderIp] ?? 0) >= 60) {
            $rejectedNotice[$senderIp] = time();
            try {
                log_event(db(), 'SYSLOG_REJECTED', 'Mensaje Syslog desde un equipo no autorizado', 'REJECTED', 'medium', null, null,
                    ['transport'=>'syslog_udp','sender_ip'=>$senderIp,'raw'=>mb_substr(trim($data), 0, 500)], 'SECUREWATCH-SYSLOG', $senderIp);
            } catch (Throwable $e) {}
        }
        continue;
    }

    $ev = routeros_parse($data, $senderIp);
    // Las consultas del router a la lista de bloqueo (tema "fetch") se repiten cada minuto:
    // quedan en la evidencia cruda, pero no se registran como eventos.
    if (in_array('fetch', explode(',', (string)($ev['metadata']['topics'] ?? '')), true)) continue;
    for ($attempt = 1; $attempt <= 2; $attempt++) {
        try {
            $pdo = db();
            if ((int)$source['active'] !== 1) { $source = load_source($state); if ((int)$source['active'] !== 1) { out('Fuente desactivada en el SIEM: mensaje ignorado'); break; } }
            $id = log_event($pdo, $ev['event_type'], $ev['description'], $ev['result'], $ev['severity'], null, $ev['username'],
                $ev['metadata'], SYSLOG_SOURCE_KEY, $ev['ip'], $ev['method'], $ev['endpoint'], $ev['request_data'], null, (int)$source['id']);
            $pdo->prepare('UPDATE sources SET last_seen_at=NOW() WHERE id=?')->execute([(int)$source['id']]);
            $a = $pdo->prepare('SELECT COUNT(DISTINCT alert_id) FROM alert_events WHERE event_id=?');
            $a->execute([$id]);
            $alerts = (int)$a->fetchColumn();
            $received++;
            $state['received'] = $received;
            $state['last_message_at'] = date('Y-m-d H:i:s');
            $state['db'] = 'ok';
            if (time() - $lastBeat >= 2) { heartbeat($state); $lastBeat = time(); }
            out(sprintf('#%d %-20s %-15s %s%s', $id, $ev['event_type'], $ev['ip'], $ev['description'], $alerts ? "  >>> ALERTA" : ''));
            break;
        } catch (Throwable $e) {
            out('Error de base de datos (' . $e->getMessage() . ')' . ($attempt === 1 ? ', reconectando...' : ''));
            $state['db'] = 'error: ' . mb_substr($e->getMessage(), 0, 120);
            db_reset();
            if ($attempt === 2) sleep(2);
        }
    }
}
