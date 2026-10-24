<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_role(['admin','analyst']);
require_once __DIR__.'/includes/functions.php';
$pdo=db();$title='Simulador';$message='';$u=current_user();
$source='SECUREWATCH-LAB';$ip=client_ip();
if($_SERVER['REQUEST_METHOD']==='POST'){
 verify_csrf();$type=(string)($_POST['simulation']??'');
 if($type==='brute'){
   for($i=1;$i<=5;$i++) log_event($pdo,'LOGIN_FAILED','Intento fallido de laboratorio #'.$i,'FAILED','medium',null,'admin_demo',['simulation'=>true],$source,$ip);
   $message='Se generaron 5 LOGIN_FAILED contra admin_demo. Debe activarse Fuerza bruta.';
 }
 if($type==='spray'){
   foreach(['admin','soporte','gerencia'] as $name) log_event($pdo,'LOGIN_FAILED','Intento de laboratorio contra '.$name,'FAILED','medium',null,$name,['simulation'=>true],$source,$ip);
   $message='Se intentaron 3 usuarios desde la misma IP. Debe activarse Password spraying.';
 }
 if($type==='denied'){
   for($i=1;$i<=3;$i++) log_event($pdo,'ACCESS_DENIED','Acceso denegado a /admin (laboratorio)','DENIED','medium',null,'usuario_demo',['simulation'=>true],$source,$ip,'GET','/admin');
   $message='Se generaron 3 accesos no autorizados.';
 }
 if($type==='xss'){
   log_event($pdo,'HTTP_REQUEST','Solicitud de búsqueda recibida','INFO','low',null,'anonymous',['simulation'=>true],$source,$ip,'GET','/buscar.php?q=demo',"<script>alert('demo')</script>");
   $message='Se registró una cadena de laboratorio con patrón XSS.';
 }
 if($type==='sqli'){
   log_event($pdo,'HTTP_REQUEST','Solicitud de autenticación recibida','INFO','low',null,'anonymous',['simulation'=>true],$source,$ip,'POST','/login.php',"username=admin&value=' OR 1=1 --");
   $message='Se registró una cadena de laboratorio con patrón SQL Injection.';
 }
 if($type==='traversal'){
   log_event($pdo,'HTTP_REQUEST','Solicitud de descarga recibida','INFO','low',null,'anonymous',['simulation'=>true],$source,$ip,'GET','/download.php?file=../../../../etc/passwd','');
   $message='Se registró una ruta de laboratorio con patrón Path Traversal.';
 }
 if($type==='scan'){
   foreach(['/.env','/.git/config','/phpinfo.php','/backup.sql','/config.php'] as $path) log_event($pdo,'HTTP_REQUEST','Solicitud a ruta sensible','INFO','low',null,'anonymous',['simulation'=>true],$source,$ip,'GET',$path,'');
   $message='Se generaron 5 solicitudes a rutas sensibles. Debe activarse Escaneo de rutas.';
 }
 if($type==='downloads'){
   for($i=1;$i<=20;$i++) log_event($pdo,'FILE_DOWNLOAD','Descarga de laboratorio '.$i,'SUCCESS','low',null,'usuario_demo',['simulation'=>true],$source,$ip);
   $message='Se generaron 20 descargas para activar Extracción masiva.';
 }
}
require __DIR__.'/includes/header.php'; ?>
<div class="page-head"><div><h2>Laboratorio de demostración</h2><p>Inserta eventos controlados para comprobar las reglas sin atacar sistemas externos. Todo lo generado aquí queda marcado como <strong>SIMULADO</strong> y no se mezcla con la evidencia real.</p></div></div>
<?php if($message): ?><div class="alert alert-info"><?= esc($message) ?> <a href="alertas.php" class="alert-link">Ver alertas</a></div><?php endif; ?>
<div class="row g-3">
<?php $cards=[
['brute','Fuerza bruta','5 intentos fallidos contra el mismo usuario.','CRÍTICA'],
['spray','Password spraying','La misma IP prueba 3 usuarios distintos.','ALTA'],
['denied','Acceso no autorizado','3 accesos denegados en pocos segundos.','ALTA'],
['xss','Patrón XSS','Solicitud HTTP con una cadena XSS de laboratorio.','ALTA'],
['sqli','Patrón SQL Injection','Solicitud HTTP con una cadena SQLi de laboratorio.','CRÍTICA'],
['traversal','Path Traversal','Solicitud con navegación de directorios.','ALTA'],
['scan','Escaneo de rutas','Consulta 5 rutas sensibles comunes.','ALTA'],
['downloads','Descarga masiva','20 eventos de descarga consecutivos.','ALTA']
];foreach($cards as $c): ?>
<div class="col-md-6 col-xl-3"><div class="panel h-100"><div class="lab-icon"><?= nav_icon('simulador') ?></div><h5><?= esc($c[1]) ?></h5><p class="text-secondary small"><?= esc($c[2]) ?></p><div class="small mb-3">Esperada: <strong><?= esc($c[3]) ?></strong></div><form method="post"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><button class="btn btn-cyber btn-sm" name="simulation" value="<?= esc($c[0]) ?>">Ejecutar simulación</button></form></div></div>
<?php endforeach; ?></div>
<div class="panel mt-3"><strong>Uso académico:</strong> el laboratorio solo registra cadenas y eventos dentro de SecureWatch. No envía ataques ni modifica servicios externos.</div>
<?php require __DIR__.'/includes/footer.php'; ?>
