<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_role(['admin','auditor']);
require_once __DIR__.'/includes/functions.php';
$pdo=db(); $title='Integridad de la bitácora'; $result=null;
if($_SERVER['REQUEST_METHOD']==='POST'){
    verify_csrf();
    $result=verify_event_chain($pdo);
    $u=current_user();
    log_event($pdo,'INTEGRITY_CHECK',$result['ok']?'Verificación de integridad correcta ('.$result['checked'].' eventos)':'Verificación de integridad FALLIDA en el evento #'.$result['broken_id'],
        $result['ok']?'SUCCESS':'FAILED',$result['ok']?'low':'critical',(int)$u['id'],$u['username']);
}
$last=$pdo->query("SELECT id,integrity_hash,created_at FROM events WHERE integrity_hash IS NOT NULL ORDER BY id DESC LIMIT 1")->fetch();
require __DIR__.'/includes/header.php'; ?>
<div class="page-head"><div><h2>Integridad de la bitácora</h2><p>Cada evento queda sellado con SHA-256 y encadenado con el anterior. Si un registro se modifica o se elimina directamente en la base de datos, la cadena se rompe.</p></div></div>
<?php if($result): ?>
  <?php if($result['ok']): ?>
  <div class="alert alert-success"><strong>Cadena íntegra.</strong> Se verificaron <?= (int)$result['checked'] ?> eventos sin alteraciones.<?php if($result['unsealed']): ?> Hay <?= (int)$result['unsealed'] ?> eventos anteriores a la activación del sellado (no verificables).<?php endif; ?></div>
  <?php else: ?>
  <div class="alert alert-danger"><strong>Cadena rota en el evento #<?= (int)$result['broken_id'] ?>.</strong> <?= esc($result['reason']) ?> Se verificaron <?= (int)$result['checked'] ?> eventos hasta detectar el problema.</div>
  <?php endif; ?>
<?php endif; ?>
<div class="panel"><div class="row g-3 align-items-center">
 <div class="col-lg-8 small"><span class="text-secondary">Último sello registrado</span><br>
 <?php if($last): ?>Evento #<?= (int)$last['id'] ?> · <?= esc($last['created_at']) ?><div class="evidence-code mt-1"><?= esc($last['integrity_hash']) ?></div><?php else: ?>Aún no hay eventos sellados.<?php endif; ?></div>
 <div class="col-lg-4 text-lg-end"><form method="post"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><button class="btn btn-cyber">Verificar cadena completa</button></form></div>
</div></div>
<?php require __DIR__.'/includes/footer.php'; ?>
