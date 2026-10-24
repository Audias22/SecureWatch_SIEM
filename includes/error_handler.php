<?php
declare(strict_types=1);

/**
 * Manejo de errores sin divulgar información interna.
 * - El navegador nunca ve rutas, consultas, usuarios de base de datos ni trazas.
 * - El detalle completo queda en un log privado, con un código de referencia
 *   que también se muestra al usuario para poder ubicarlo.
 */
function install_error_handling(string $logFile, string $appName, bool $jsonUnder = false, string $jsonPathMarker = '/api/'): void
{
    if (PHP_SAPI === 'cli') return;   // en consola (colector) se siguen viendo los errores
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
    ini_set('error_log', $logFile);
    error_reporting(E_ALL);
    ob_start();   // si algo falla a mitad de la página, se descarta lo que ya se había generado

    $handler = function (Throwable $e) use ($logFile, $appName, $jsonUnder, $jsonPathMarker): void {
        $ref = strtoupper(bin2hex(random_bytes(4)));
        $line = sprintf("[%s] REF-%s %s: %s en %s:%d | %s %s | IP %s\n%s\n",
            date('Y-m-d H:i:s'), $ref, get_class($e), $e->getMessage(), $e->getFile(), $e->getLine(),
            $_SERVER['REQUEST_METHOD'] ?? '-', $_SERVER['REQUEST_URI'] ?? '-', $_SERVER['REMOTE_ADDR'] ?? '-',
            $e->getTraceAsString());
        @file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
        while (ob_get_level() > 0) ob_end_clean();
        if (!headers_sent()) {
            http_response_code(503);
            header('Cache-Control: no-store');
        }
        $isDb = $e instanceof PDOException;
        if ($jsonUnder && str_contains($_SERVER['REQUEST_URI'] ?? '', $jsonPathMarker)) {
            if (!headers_sent()) header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['success' => false, 'message' => 'Service unavailable', 'reference' => 'REF-' . $ref]);
            return;
        }
        if (!headers_sent()) header('Content-Type: text/html; charset=utf-8');
        $title = htmlspecialchars($appName, ENT_QUOTES, 'UTF-8');
        $msg = $isDb ? 'El servicio no está disponible en este momento. Intente de nuevo en unos minutos.'
                     : 'Ocurrió un error inesperado. El problema quedó registrado.';
        echo '<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Servicio no disponible · ' . $title . '</title>'
           . '<style>body{font-family:"Segoe UI",Tahoma,sans-serif;background:#f3f2ee;color:#16191d;display:grid;place-items:center;min-height:100vh;margin:0;padding:20px}'
           . '.c{background:#fff;border:1px solid #dcd8ce;border-top:3px solid #b42318;border-radius:6px;padding:28px 30px;max-width:460px}'
           . 'h1{font-size:20px;margin:0 0 8px}p{color:#464c55;margin:0 0 10px}code{font-family:Consolas,monospace;background:#f3f2ee;padding:2px 6px;border-radius:3px}</style></head>'
           . '<body><div class="c"><h1>Servicio no disponible</h1><p>' . $msg . '</p><p>Si el problema continúa, comunique este código al administrador: <code>REF-' . $ref . '</code></p></div></body></html>';
    };
    set_exception_handler($handler);
    // Errores fatales que no son excepciones (memoria, tiempo, etc.)
    register_shutdown_function(function () use ($handler): void {
        $err = error_get_last();
        if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
            $handler(new ErrorException($err['message'], 0, $err['type'], $err['file'], $err['line']));
        }
    });
}
