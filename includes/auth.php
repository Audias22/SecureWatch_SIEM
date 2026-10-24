<?php
declare(strict_types=1);
require_once __DIR__ . '/../config/database.php';

function current_user(): ?array
{
    return $_SESSION['user'] ?? null;
}

function is_logged_in(): bool
{
    return isset($_SESSION['user']['id']);
}

function require_login(): void
{
    $loginUrl = str_contains($_SERVER['SCRIPT_NAME'] ?? '', '/actions/') ? '../login.php' : 'login.php';
    if (!is_logged_in()) {
        header('Location: ' . $loginUrl);
        exit;
    }
    // Cierre de sesión por inactividad.
    $last = (int)($_SESSION['last_activity'] ?? time());
    if (time() - $last > SESSION_IDLE_SECONDS) {
        $_SESSION = [];
        session_regenerate_id(true);
        header('Location: ' . $loginUrl . '?timeout=1');
        exit;
    }
    $_SESSION['last_activity'] = time();
}

function require_role(array $roles): void
{
    require_login();
    if (!in_array($_SESSION['user']['role'], $roles, true)) {
        http_response_code(403);
        exit('Acceso denegado.');
    }
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf(): void
{
    $token = $_POST['csrf_token'] ?? '';
    if (!is_string($token) || !hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
        http_response_code(419);
        exit('Token CSRF inválido.');
    }
}
