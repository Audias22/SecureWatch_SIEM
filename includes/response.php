<?php
/**
 * Respuesta a incidentes y continuidad:
 *  - Bloqueo de IP: el MikroTik y el portal consultan la lista en api/blocklist.php.
 *  - Respaldo de la base de datos (manual y uno automático por día).
 *  - Enlaces a MITRE ATT&CK.
 */
declare(strict_types=1);

const BLOCK_LIST_NAME = 'SW-BLOQUEO';            // address-list en el MikroTik
const BLOCK_MAX_ACTIVE = 25;                     // la respuesta al router debe caber en 4 KB
const BACKUP_DIR = __DIR__ . '/../storage/respaldos';
const BACKUP_KEEP = 7;

/** IP que nunca se pueden bloquear (router, servidor SIEM y el propio analista). */
function protected_ips(): array
{
    return array_values(array_unique(['127.0.0.1', '::1', '0.0.0.0', '192.168.88.1', '192.168.88.254', client_ip()]));
}

function expire_blocks(PDO $pdo): void
{
    $pdo->exec("UPDATE ip_blocks SET active=0, removed_at=expires_at WHERE active=1 AND expires_at IS NOT NULL AND expires_at <= NOW()");
}

function active_blocks(PDO $pdo): array
{
    expire_blocks($pdo);
    return $pdo->query('SELECT b.*, u.username created_by_name FROM ip_blocks b LEFT JOIN users u ON u.id=b.created_by
        WHERE b.active=1 ORDER BY b.created_at DESC')->fetchAll();
}

function ip_block_of(PDO $pdo, string $ip): ?array
{
    expire_blocks($pdo);
    $s = $pdo->prepare('SELECT * FROM ip_blocks WHERE active=1 AND ip_address=? LIMIT 1');
    $s->execute([$ip]);
    return $s->fetch() ?: null;
}

/** Bloquea una IP. Devuelve [true, mensaje] o [false, motivo]. */
function block_ip(PDO $pdo, string $ip, string $reason, ?int $hours, ?int $alertId, array $user): array
{
    $ip = trim($ip);
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return [false, 'La IP no es válida (solo IPv4).'];
    if (in_array($ip, protected_ips(), true)) return [false, "La IP $ip está protegida (router, servidor o su propio equipo) y no se puede bloquear."];
    if (ip_block_of($pdo, $ip)) return [false, "La IP $ip ya está bloqueada."];
    if (count(active_blocks($pdo)) >= BLOCK_MAX_ACTIVE) return [false, 'Se alcanzó el máximo de ' . BLOCK_MAX_ACTIVE . ' bloqueos activos. Libere alguno primero.'];
    $reason = trim($reason) !== '' ? mb_substr(trim($reason), 0, 255) : 'Bloqueo manual';
    $expires = $hours ? date('Y-m-d H:i:s', time() + $hours * 3600) : null;
    $pdo->prepare('INSERT INTO ip_blocks(ip_address,reason,alert_id,created_by,created_at,expires_at,active) VALUES (?,?,?,?,NOW(),?,1)')
        ->execute([$ip, $reason, $alertId, (int)$user['id'], $expires]);
    log_event($pdo, 'IP_BLOCKED', "IP $ip bloqueada" . ($hours ? " por $hours h" : ' sin vencimiento') . ": $reason", 'SUCCESS', 'medium',
        (int)$user['id'], $user['username'], ['transport' => 'internal', 'alert_id' => $alertId, 'expires_at' => $expires], 'SECUREWATCH-INTERNAL', $ip);
    return [true, "IP $ip bloqueada. El router y el portal aplican el bloqueo en menos de un minuto."];
}

function unblock_ip(PDO $pdo, int $blockId, array $user): ?string
{
    $s = $pdo->prepare('SELECT * FROM ip_blocks WHERE id=? AND active=1');
    $s->execute([$blockId]);
    $b = $s->fetch();
    if (!$b) return null;
    $pdo->prepare('UPDATE ip_blocks SET active=0, removed_by=?, removed_at=NOW() WHERE id=?')->execute([(int)$user['id'], $blockId]);
    log_event($pdo, 'IP_UNBLOCKED', 'IP ' . $b['ip_address'] . ' desbloqueada', 'SUCCESS', 'low',
        (int)$user['id'], $user['username'], ['transport' => 'internal', 'block_id' => $blockId], 'SECUREWATCH-INTERNAL', $b['ip_address']);
    return (string)$b['ip_address'];
}

/** Guarda cuándo consultó cada fuente la lista (para mostrar si el router está sincronizado). */
function blocklist_pull_record(string $sourceKey, int $count): void
{
    $file = __DIR__ . '/../storage/blocklist_pulls.json';
    $data = is_file($file) ? (json_decode((string)@file_get_contents($file), true) ?: []) : [];
    $data[$sourceKey] = ['at' => date('Y-m-d H:i:s'), 'ip' => client_ip(), 'count' => $count];
    @file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
}

function blocklist_pulls(): array
{
    $file = __DIR__ . '/../storage/blocklist_pulls.json';
    return is_file($file) ? (json_decode((string)@file_get_contents($file), true) ?: []) : [];
}

/**
 * Script RouterOS que deja la address-list igual a la lista del SIEM.
 * Solo agrega o quita cuando hay diferencias, para no llenar el log del router.
 */
function routeros_blocklist_script(array $ips): string
{
    $ips = array_values(array_filter($ips, fn($ip) => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)));
    $l = BLOCK_LIST_NAME;
    return ':local want [:toarray "' . implode(',', $ips) . '"]' . "\n"
        . ':foreach i in=[/ip firewall address-list find list="' . $l . '"] do={'
        . ':local a [:tostr [/ip firewall address-list get $i address]];:local keep false;'
        . ':foreach w in=$want do={:if ([:tostr $w]=$a) do={:set keep true}};'
        . ':if (!$keep) do={/ip firewall address-list remove $i}}' . "\n"
        . ':foreach w in=$want do={:if ([:len [/ip firewall address-list find list="' . $l . '" address=[:tostr $w]]]=0) do={'
        . '/ip firewall address-list add list="' . $l . '" address=[:tostr $w] comment="SecureWatch"}}' . "\n";
}

function mitre_url(?string $id): ?string
{
    if (!$id || !preg_match('/^T\d{4}(?:\.\d{3})?$/', $id)) return null;
    return 'https://attack.mitre.org/techniques/' . str_replace('.', '/', $id) . '/';
}

/** Etiqueta de la técnica MITRE ATT&CK con enlace a la ficha oficial. */
function mitre_tag(?string $id, ?string $name = null, ?string $tactic = null): string
{
    if (!$id && !$name) return '';
    $label = $id ?: 'ATT&CK';
    $title = trim(($name ?? '') . ($tactic ? ' · ' . $tactic : ''));
    $url = mitre_url($id);
    return $url
        ? '<a class="mitre-tag" href="' . esc($url) . '" target="_blank" rel="noopener" title="' . esc($title) . '">' . esc($label) . '</a>'
        : '<span class="mitre-tag" title="' . esc($title) . '">' . esc($label) . '</span>';
}

// ---------------------------------------------------------------- Respaldos

/** Escribe un respaldo SQL completo (estructura y datos) en un archivo .sql.gz. */
function backup_create(PDO $pdo, string $origin = 'manual'): string
{
    if (!is_dir(BACKUP_DIR)) @mkdir(BACKUP_DIR, 0750, true);
    $file = BACKUP_DIR . '/securewatch_' . date('Ymd_His') . '_' . $origin . '.sql.gz';
    $gz = gzopen($file, 'wb6');
    if (!$gz) throw new RuntimeException('No se pudo crear el archivo de respaldo.');
    gzwrite($gz, "-- Respaldo de SecureWatch SIEM\n-- Fecha: " . date('Y-m-d H:i:s') . " ($origin)\n"
        . "SET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\n\n");
    $tables = $pdo->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN);
    foreach ($tables as $t) {
        $create = $pdo->query('SHOW CREATE TABLE `' . str_replace('`', '', $t) . '`')->fetch(PDO::FETCH_NUM)[1];
        gzwrite($gz, "DROP TABLE IF EXISTS `$t`;\n$create;\n\n");
        $rows = $pdo->query('SELECT * FROM `' . str_replace('`', '', $t) . '`', PDO::FETCH_NUM);
        $batch = [];
        foreach ($rows as $row) {
            $batch[] = '(' . implode(',', array_map(fn($v) => $v === null ? 'NULL' : $pdo->quote((string)$v), $row)) . ')';
            if (count($batch) === 200) { gzwrite($gz, "INSERT INTO `$t` VALUES\n" . implode(",\n", $batch) . ";\n"); $batch = []; }
        }
        if ($batch) gzwrite($gz, "INSERT INTO `$t` VALUES\n" . implode(",\n", $batch) . ";\n");
        gzwrite($gz, "\n");
    }
    gzwrite($gz, "SET FOREIGN_KEY_CHECKS=1;\n");
    gzclose($gz);

    // Conserva solo los últimos respaldos.
    $all = backup_list();
    foreach (array_slice($all, BACKUP_KEEP) as $old) @unlink(BACKUP_DIR . '/' . $old['name']);
    return basename($file);
}

function backup_list(): array
{
    $out = [];
    foreach (glob(BACKUP_DIR . '/securewatch_*.sql.gz') ?: [] as $f) {
        $out[] = ['name' => basename($f), 'size' => filesize($f), 'time' => filemtime($f), 'sha256' => hash_file('sha256', $f)];
    }
    usort($out, fn($a, $b) => $b['time'] <=> $a['time']);
    return $out;
}

/** Un respaldo automático por día, la primera vez que un administrador abre el SIEM. */
function backup_auto(PDO $pdo): void
{
    $last = backup_list()[0]['time'] ?? 0;
    if ($last && date('Y-m-d', $last) === date('Y-m-d')) return;
    try {
        $name = backup_create($pdo, 'auto');
        log_event($pdo, 'BACKUP_CREATED', "Respaldo automático de la base de datos ($name)", 'SUCCESS', 'low', null, 'sistema',
            ['transport' => 'internal', 'file' => $name], 'SECUREWATCH-INTERNAL', '127.0.0.1');
    } catch (Throwable $e) {
        error_log('Respaldo automático fallido: ' . $e->getMessage());
    }
}
