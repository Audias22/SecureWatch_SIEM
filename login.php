<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/functions.php';

const LOGIN_MAX_FAILED = 5;       // intentos fallidos permitidos
const LOGIN_LOCK_MINUTES = 15;    // ventana de bloqueo

if (is_logged_in()) { header('Location: dashboard.php'); exit; }
$error = '';
$info = isset($_GET['timeout']) ? 'La sesión se cerró por inactividad.' : '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $username = mb_substr(trim((string)($_POST['username'] ?? '')), 0, 60);
    $password = (string)($_POST['password'] ?? '');
    $pdo = db();

    // Bloqueo temporal: demasiados fallos para este usuario desde esta IP.
    $q = $pdo->prepare("SELECT COUNT(*) FROM events WHERE source_key='SECUREWATCH-INTERNAL' AND event_type='LOGIN_FAILED'
        AND is_simulation=0 AND ip_address=? AND username=? AND created_at >= (NOW() - INTERVAL " . LOGIN_LOCK_MINUTES . " MINUTE)");
    $q->execute([client_ip(), $username ?: 'desconocido']);
    if ((int)$q->fetchColumn() >= LOGIN_MAX_FAILED) {
        log_event($pdo, 'LOGIN_BLOCKED', 'Intento de acceso durante bloqueo temporal', 'blocked', 'medium', null, $username ?: 'desconocido');
        $error = 'Demasiados intentos fallidos. Espere ' . LOGIN_LOCK_MINUTES . ' minutos e intente de nuevo.';
    } else {
        $stmt = $pdo->prepare('SELECT * FROM users WHERE username = ? AND active = 1 LIMIT 1');
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['user'] = ['id'=>(int)$user['id'],'username'=>$user['username'],'full_name'=>$user['full_name'],'role'=>$user['role']];
            $_SESSION['last_activity'] = time();
            // Aviso si la cuenta sigue con la contraseña inicial de demostración.
            $_SESSION['weak_password'] = password_verify('Admin123!', $user['password_hash']);
            $pdo->prepare('UPDATE users SET last_login_at=NOW() WHERE id=?')->execute([$user['id']]);
            log_event($pdo, 'LOGIN_SUCCESS', 'Inicio de sesión correcto', 'success', 'low', (int)$user['id'], $user['username']);
            header('Location: dashboard.php'); exit;
        }

        $uid = $user ? (int)$user['id'] : null;
        log_event($pdo, 'LOGIN_FAILED', 'Credenciales incorrectas', 'failed', 'high', $uid, $username ?: 'desconocido');
        $error = 'Usuario o contraseña incorrectos.';
    }
}
?>
<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Acceso | SecureWatch SIEM</title><link href="assets/vendor/bootstrap.min.css" rel="stylesheet"><link rel="stylesheet" href="<?= asset('assets/css/style.css') ?>"></head>
<body class="login-body">
<div class="login-card">
  <div class="text-center mb-4"><div class="login-shield">SW</div><h1>SecureWatch SIEM</h1><p>Centro de monitoreo y auditoría de seguridad</p></div>
  <?php if ($info): ?><div class="alert alert-info py-2"><?= esc($info) ?></div><?php endif; ?>
  <?php if ($error): ?><div class="alert alert-danger py-2"><?= esc($error) ?></div><?php endif; ?>
  <form method="post">
    <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
    <div class="mb-3"><label class="form-label">Usuario</label><input class="form-control" name="username" autocomplete="username" maxlength="60" required></div>
    <div class="mb-4"><label class="form-label">Contraseña</label><input class="form-control" type="password" name="password" autocomplete="current-password" required></div>
    <button class="btn btn-cyber w-100">Ingresar</button>
  </form>
  <div class="login-foot"><span>Acceso restringido</span><span>Toda actividad queda registrada</span></div>
</div><script src="<?= asset('assets/js/app.js') ?>"></script></body></html>
