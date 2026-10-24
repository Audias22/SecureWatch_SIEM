<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/functions.php';
if (is_logged_in()) {
    $u = current_user();
    try { log_event(db(), 'LOGOUT', 'Cierre de sesión', 'success', 'low', (int)$u['id'], $u['username']); } catch (Throwable $e) {}
}
$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $p=session_get_cookie_params();
    setcookie(session_name(), '', time()-42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
}
session_destroy();
header('Location: login.php');
exit;
