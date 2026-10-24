<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_login();
require_once __DIR__.'/includes/functions.php';
$pdo=db(); $id=(int)($_GET['id']??0); $title='Detalle de evento';
$st=$pdo->prepare('SELECT * FROM events WHERE id=?'); $st->execute([$id]); $e=$st->fetch();
if(!$e){http_response_code(404);require __DIR__.'/includes/header.php';echo '<div class="panel">Evento no encontrado. <a href="eventos.php">Volver</a></div>';require __DIR__.'/includes/footer.php';exit;}
$al=$pdo->prepare('SELECT a.id,a.title,a.severity,a.status FROM alert_events ae JOIN alerts a ON a.id=ae.alert_id WHERE ae.event_id=? ORDER BY a.id');
$al->execute([$id]); $alerts=$al->fetchAll();
$details=evidence_details($e);
require __DIR__.'/includes/header.php'; ?>
<div class="page-head"><div><div class="small-muted mb-1">Evento #<?= (int)$e['id'] ?></div><h2><?= esc($e['event_type']) ?><?= sim_badge($e['is_simulation']) ?></h2><p><?= esc($e['description']) ?></p></div><a href="eventos.php" class="btn btn-sm btn-ghost">Volver</a></div>
<div class="row g-3">
 <div class="col-lg-7"><div class="panel h-100"><h5>Datos del evento</h5>
  <dl class="kv-list wide">
   <dt>Fecha y hora (SIEM)</dt><dd><?= esc($e['created_at']) ?></dd>
   <dt>Fuente</dt><dd><?= esc($e['source_key']) ?></dd>
   <dt>Usuario</dt><dd><?= esc($e['username']?:'—') ?></dd>
   <dt>IP</dt><dd><a href="eventos.php?ip=<?= urlencode((string)$e['ip_address']) ?>"><?= esc($e['ip_address']) ?></a></dd>
   <dt>Resultado</dt><dd><?= esc($e['result']) ?></dd>
   <dt>Nivel</dt><dd><span class="badge text-bg-<?= severity_badge($e['severity']) ?>"><?= strtoupper($e['severity']) ?></span></dd>
   <?php foreach($details as [$k,$v]): ?><dt><?= esc($k) ?></dt><dd><?= esc($v) ?></dd><?php endforeach; ?>
  </dl></div></div>
 <div class="col-lg-5">
  <div class="panel mb-3"><h5>Alertas relacionadas</h5>
   <?php foreach($alerts as $a): ?><div class="border-top py-2"><a href="alerta.php?id=<?= (int)$a['id'] ?>"><?= esc($a['title']) ?></a> <span class="badge text-bg-<?= severity_badge($a['severity']) ?>"><?= strtoupper($a['severity']) ?></span></div><?php endforeach; ?>
   <?php if(!$alerts): ?><div class="text-secondary small">Este evento no generó alertas.</div><?php endif; ?>
  </div>
  <div class="panel"><h5>Integridad</h5>
   <div class="small text-secondary">Sello SHA-256 de este evento</div><div class="hash-box mt-1"><?= esc($e['integrity_hash']?:'Sin sello (evento anterior a la cadena)') ?></div>
   <div class="small text-secondary mt-2">Encadenado al anterior</div><div class="hash-box mt-1"><?= esc($e['prev_hash']?:'—') ?></div>
  </div>
 </div>
</div>
<?php require __DIR__.'/includes/footer.php'; ?>
