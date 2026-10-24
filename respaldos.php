<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_role(['admin']);
require_once __DIR__.'/includes/functions.php';
$pdo=db(); $title='Respaldos'; $u=current_user();

if(isset($_GET['download'])){
    $name=basename((string)$_GET['download']);
    $file=BACKUP_DIR.'/'.$name;
    if(!preg_match('/^securewatch_\d{8}_\d{6}_(manual|auto)\.sql\.gz$/',$name) || !is_file($file)){ http_response_code(404); exit('Respaldo no encontrado.'); }
    log_event($pdo,'BACKUP_DOWNLOADED','Descarga del respaldo '.$name,'SUCCESS','medium',(int)$u['id'],$u['username'],['transport'=>'internal','file'=>$name]);
    header('Content-Type: application/gzip');
    header('Content-Disposition: attachment; filename="'.$name.'"');
    header('Content-Length: '.filesize($file));
    readfile($file); exit;
}
if($_SERVER['REQUEST_METHOD']==='POST'){
    verify_csrf();
    try{
        $name=backup_create($pdo,'manual');
        log_event($pdo,'BACKUP_CREATED','Respaldo manual de la base de datos ('.$name.')','SUCCESS','low',(int)$u['id'],$u['username'],['transport'=>'internal','file'=>$name]);
        $_SESSION['flash']=['success','Respaldo creado: '.$name];
    }catch(Throwable $e){ error_log('Respaldo fallido: '.$e->getMessage()); $_SESSION['flash']=['danger','No se pudo crear el respaldo. Revise storage/php_errors.log.']; }
    header('Location: respaldos.php'); exit;
}
$flash=$_SESSION['flash']??null; unset($_SESSION['flash']);
$list=backup_list();
$tables=$pdo->query("SELECT table_name t, table_rows n, ROUND((data_length+index_length)/1024) kb FROM information_schema.tables WHERE table_schema=DATABASE() ORDER BY table_name")->fetchAll();
function human_size(int $b): string { return $b>=1048576?number_format($b/1048576,1).' MB':number_format($b/1024,1).' KB'; }
require __DIR__.'/includes/header.php'; ?>
<div class="page-head"><div><h2>Respaldos de la base de datos</h2><p>SecureWatch hace un respaldo automático cada día la primera vez que un administrador entra, y guarda los últimos <?= BACKUP_KEEP ?>. Se guardan comprimidos en <code>storage/respaldos</code>, carpeta sin acceso desde la web.</p></div>
<form method="post"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><button class="btn btn-cyber btn-sm">Crear respaldo ahora</button></form></div>
<?php if($flash): ?><div class="alert alert-<?= esc($flash[0]) ?>"><?= esc($flash[1]) ?></div><?php endif; ?>
<div class="row g-3">
 <div class="col-lg-8"><div class="panel h-100"><h5>Respaldos disponibles</h5>
 <?php if(!$list): ?><p class="small text-secondary mb-0">Todavía no hay respaldos.</p><?php else: ?>
 <div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr><th>Archivo</th><th>Fecha</th><th>Tamaño</th><th>Tipo</th><th></th></tr></thead><tbody>
 <?php foreach($list as $b): ?><tr>
  <td class="small"><?= esc($b['name']) ?><div class="hash-box mt-1" title="SHA-256 del archivo">SHA-256 <?= esc($b['sha256']) ?></div></td>
  <td class="small"><?= date('Y-m-d H:i',$b['time']) ?></td>
  <td class="small"><?= human_size((int)$b['size']) ?></td>
  <td class="small"><?= str_contains($b['name'],'_auto')?'Automático':'Manual' ?></td>
  <td class="text-end"><a class="btn btn-sm btn-ghost" href="respaldos.php?download=<?= urlencode($b['name']) ?>">Descargar</a></td>
 </tr><?php endforeach; ?></tbody></table></div><?php endif; ?>
 </div></div>
 <div class="col-lg-4"><div class="panel h-100"><h5>Contenido</h5>
  <table class="table table-sm mb-2"><tbody><?php foreach($tables as $t): ?><tr><td class="small"><?= esc($t['t']) ?></td><td class="small text-end">~<?= number_format((int)$t['n']) ?> filas</td></tr><?php endforeach; ?></tbody></table>
  <p class="small-muted mb-0">Para restaurar: descomprimir el archivo e importarlo en phpMyAdmin con el usuario root. La aplicación no puede restaurar por sí misma porque su usuario de base de datos no tiene permiso para borrar tablas.</p>
 </div></div>
</div>
<?php require __DIR__.'/includes/footer.php'; ?>
