<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/functions.php';
$user = current_user();
$current = basename($_SERVER['SCRIPT_NAME'] ?? '');
$collector = collector_status();
$collectorStarting = false;
// Al abrir el SIEM, si el colector no está corriendo, se enciende solo en segundo plano.
if (!$collector['running'] && in_array($user['role'] ?? '', ['admin','analyst'], true)
    && empty($collector['stopped_by_user']) && collector_launch()) {
    $collectorStarting = true;
}

/** Íconos de línea (SVG en el propio HTML, sin librerías externas). */
function nav_icon(string $name): string
{
    $p = [
        'dashboard'  => '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
        'eventos'    => '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
        'alertas'    => '<path d="M12 3 2 20h20L12 3z"/><path d="M12 10v4"/><path d="M12 17.5v.5"/>',
        'fuentes'    => '<circle cx="12" cy="12" r="2"/><path d="M16.2 7.8a6 6 0 0 1 0 8.4M7.8 16.2a6 6 0 0 1 0-8.4M19 5a10 10 0 0 1 0 14M5 19A10 10 0 0 1 5 5"/>',
        'incidentes' => '<path d="M4 4h16v12H8l-4 4V4z"/><path d="M12 8v3"/><path d="M12 13.5v.5"/>',
        'reportes'   => '<path d="M6 3h9l5 5v13H6z"/><path d="M14 3v6h6"/><path d="M9 13h6M9 17h6"/>',
        'integridad' => '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6l-8-3z"/><path d="m9 12 2 2 4-4"/>',
        'simulador'  => '<path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.8 3h10.4a2 2 0 0 0 1.8-3l-5-9V3"/><path d="M7.5 15h9"/>',
        'reglas'     => '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
        'usuarios'   => '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 4.5a3.5 3.5 0 0 1 0 7M18 14.5a6.5 6.5 0 0 1 3.5 5.5"/>',
    ][$name] ?? '';
    return '<svg class="nav-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $p . '</svg>';
}
function nav_link(string $file, string $icon, string $label, string $current): string
{
    $active = $current === $file || ($file === 'incidentes.php' && $current === 'incidente_detalle.php');
    return '<a href="' . $file . '"' . ($active ? ' class="active" aria-current="page"' : '') . '>' . nav_icon($icon) . '<span>' . esc($label) . '</span></a>';
}
$role = $user['role'] ?? '';
$roleName = ['admin'=>'Administrador','analyst'=>'Analista','auditor'=>'Auditor'][$role] ?? $role;
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= esc($title ?? APP_NAME) ?> · <?= APP_NAME ?></title>
    <link href="assets/vendor/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="<?= asset('assets/css/style.css') ?>">
</head>
<body>
<header class="topbar">
  <a class="brand" href="dashboard.php"><span class="brand-mark">SW</span><span class="brand-name">SecureWatch</span><span class="brand-tag">SIEM</span></a>
  <div class="topbar-right">
    <a href="fuentes.php" class="collector-chip <?= $collector['running'] ? 'on' : ($collectorStarting ? 'wait' : 'off') ?>" title="Colector Syslog del MikroTik"><i></i><?= $collector['running'] ? 'Colector activo' : ($collectorStarting ? 'Iniciando colector…' : 'Colector detenido') ?></a>
    <span class="who d-none d-md-inline"><?= esc($user['full_name'] ?? '') ?><em><?= esc($roleName) ?></em></span>
    <a class="btn btn-ghost btn-sm" href="cuenta.php">Mi cuenta</a>
    <a class="btn btn-ghost btn-sm" href="logout.php">Salir</a>
  </div>
</header>
<div class="app-shell">
<nav class="sidebar" aria-label="Navegación principal">
  <div class="side-title">Operación</div>
  <?= nav_link('dashboard.php','dashboard','Dashboard',$current) ?>
  <?= nav_link('eventos.php','eventos','Eventos',$current) ?>
  <?= nav_link('alertas.php','alertas','Alertas',$current) ?>
  <?= nav_link('fuentes.php','fuentes','Fuentes',$current) ?>

  <div class="side-title">Respuesta</div>
  <?= nav_link('incidentes.php','incidentes','Incidentes',$current) ?>
  <?= nav_link('reportes.php','reportes','Reportes',$current) ?>
  <?php if (in_array($role, ['admin','auditor'], true)): ?><?= nav_link('integridad.php','integridad','Integridad',$current) ?><?php endif; ?>

  <?php if (in_array($role, ['admin','analyst'], true)): ?>
  <div class="side-title">Laboratorio</div>
  <?= nav_link('simulador.php','simulador','Simulador',$current) ?>
  <?php endif; ?>

  <?php if ($role === 'admin'): ?>
  <div class="side-title">Administración</div>
  <?= nav_link('reglas.php','reglas','Reglas',$current) ?>
  <?= nav_link('usuarios.php','usuarios','Usuarios',$current) ?>
  <?php endif; ?>
</nav>
<main class="content">
<?php if (!empty($_SESSION['weak_password'])): ?>
<div class="notice notice-warn"><span><strong>Seguridad.</strong> Esta cuenta todavía usa la contraseña inicial de demostración.</span><a class="btn btn-sm btn-cyber" href="cuenta.php">Cambiar ahora</a></div>
<?php endif; ?>
<?php if (!$collector['running'] && !$collectorStarting && empty($collector['stopped_by_user']) && in_array($role, ['admin','analyst'], true) && $current !== 'fuentes.php'): ?>
<div class="notice notice-danger"><span><strong>Sin datos del router.</strong> El colector Syslog no está activo, así que los eventos del MikroTik no se están registrando.</span><a class="btn btn-sm btn-ghost" href="fuentes.php">Ver estado</a></div>
<?php endif; ?>
