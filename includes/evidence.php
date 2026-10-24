<?php
declare(strict_types=1);
/**
 * Presentación legible de la evidencia de un evento: convierte la metadata técnica
 * (JSON) en una lista de datos con nombres en español.
 */

const EVIDENCE_LABELS = [
    // Portal (negocio)
    'codigo' => 'Producto', 'producto_id' => 'ID de producto', 'precio_anterior' => 'Precio anterior',
    'precio_nuevo' => 'Precio nuevo', 'variacion_pct' => 'Variación', 'precio' => 'Precio',
    'venta' => 'Venta', 'total' => 'Total', 'cliente_nit' => 'NIT del cliente', 'items' => 'Productos',
    'motivo' => 'Motivo', 'vendedor' => 'Vendedor', 'cantidad' => 'Cantidad', 'existencia' => 'Existencia resultante',
    'referencia' => 'Referencia', 'user_agent' => 'Navegador',
    // MikroTik
    'service' => 'Servicio', 'src_ip' => 'IP de origen', 'src_port' => 'Puerto de origen', 'dst_ip' => 'IP de destino',
    'dst_port' => 'Puerto de destino', 'protocol' => 'Protocolo', 'chain' => 'Cadena del firewall', 'in_interface' => 'Interfaz de entrada',
    'out_interface' => 'Interfaz de salida', 'flags' => 'Banderas TCP', 'log_prefix' => 'Prefijo del log', 'mac' => 'MAC',
    'src_mac' => 'MAC de origen', 'dhcp_server' => 'Servidor DHCP', 'interface' => 'Interfaz', 'change' => 'Cambio',
    'topics' => 'Temas RouterOS', 'router_time' => 'Hora del router', 'router_host' => 'Equipo', 'raw' => 'Mensaje original',
    // SIEM
    'transport' => 'Canal', 'sender_ip' => 'IP que envió el evento', 'claimed_source' => 'Fuente declarada',
    'http_code' => 'Código HTTP', 'listen' => 'Escucha', 'allowed' => 'Remitentes autorizados', 'received' => 'Mensajes procesados',
    'simulation' => 'Simulado', 'facility' => 'Facility Syslog', 'syslog_severity' => 'Severidad Syslog',
];

function evidence_value(string $key, $v): string
{
    if (is_bool($v)) return $v ? 'Sí' : 'No';
    if ($key === 'items' && is_array($v)) {
        return implode(' · ', array_map(fn($i) => is_array($i)
            ? (($i['cantidad'] ?? '?') . ' × ' . ($i['codigo'] ?? '?') . (isset($i['precio']) ? ' a Q' . number_format((float)$i['precio'], 2) : ''))
            : (string)$i, $v));
    }
    if (in_array($key, ['precio_anterior','precio_nuevo','precio','total'], true) && is_numeric($v)) return 'Q ' . number_format((float)$v, 2);
    if ($key === 'variacion_pct' && is_numeric($v)) return sprintf('%+.1f %%', (float)$v);
    if ($key === 'transport') return ['external_api' => 'API (aplicación web)', 'syslog_udp' => 'Syslog UDP (router)', 'internal' => 'Interno del SIEM'][$v] ?? (string)$v;
    if (is_array($v)) return implode(', ', array_map(fn($x) => is_scalar($x) ? (string)$x : json_encode($x, JSON_UNESCAPED_UNICODE), $v));
    return (string)$v;
}

/** Devuelve [[etiqueta, valor], ...] con los datos útiles de un evento. */
function evidence_details(array $e): array
{
    $meta = json_decode((string)($e['metadata'] ?? ''), true) ?: [];
    $client = is_array($meta['client'] ?? null) ? $meta['client'] : [];
    unset($meta['client']);
    $rows = [];
    // Primero lo que mandó la fuente (lo más relevante para el negocio), luego lo técnico.
    foreach ([$client, $meta] as $block) {
        foreach ($block as $k => $v) {
            if ($v === null || $v === '' || $v === []) continue;
            $rows[] = [EVIDENCE_LABELS[$k] ?? ucfirst(str_replace('_', ' ', (string)$k)), evidence_value((string)$k, $v)];
        }
    }
    // El navegador es dato secundario: va al final.
    usort($rows, fn($a, $b) => ($a[0] === 'Navegador') <=> ($b[0] === 'Navegador'));
    if (!empty($e['http_method']) || !empty($e['endpoint'])) $rows[] = ['Solicitud', trim(($e['http_method'] ?? '') . ' ' . ($e['endpoint'] ?? ''))];
    if (!empty($e['request_data'])) $rows[] = ['Datos enviados', (string)$e['request_data']];
    if (!empty($e['reported_at'])) $rows[] = ['Hora informada por la fuente', (string)$e['reported_at']];
    return $rows;
}

/** Tabla de evidencia con detalle desplegable por evento. */
function render_evidence_table(array $events, bool $showSource = true): string
{
    if (!$events) return '<div class="text-secondary small">Sin eventos de evidencia.</div>';
    $h = '<div class="table-responsive"><table class="table cyber-table evidence-table"><thead><tr><th>Hora</th>'
       . ($showSource ? '<th>Fuente</th>' : '') . '<th>Evento</th><th>Usuario</th><th>IP</th><th>Descripción y datos</th><th>Nivel</th></tr></thead><tbody>';
    foreach ($events as $ev) {
        $details = evidence_details($ev);
        $h .= '<tr><td>' . esc((string)$ev['created_at']) . '</td>'
           . ($showSource ? '<td>' . esc((string)$ev['source_key']) . '</td>' : '')
           . '<td><a href="evento.php?id=' . (int)$ev['id'] . '"><strong>' . esc((string)$ev['event_type']) . '</strong></a>' . sim_badge($ev['is_simulation'] ?? 0) . '</td>'
           . '<td>' . esc($ev['username'] ?: '—') . '</td><td>' . esc((string)$ev['ip_address']) . '</td>'
           . '<td><div>' . esc((string)$ev['description']) . '</div>';
        if ($details) {
            $h .= '<details class="ev-details"><summary>Ver datos (' . count($details) . ')</summary><dl class="kv-list">';
            foreach ($details as [$k, $v]) $h .= '<dt>' . esc($k) . '</dt><dd>' . esc($v) . '</dd>';
            $h .= '</dl></details>';
        }
        $h .= '</td><td><span class="badge text-bg-' . severity_badge((string)$ev['severity']) . '">' . strtoupper((string)$ev['severity']) . '</span></td></tr>';
    }
    return $h . '</tbody></table></div>';
}
