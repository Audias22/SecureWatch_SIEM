<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_login();
require_once __DIR__.'/includes/functions.php';
$pdo=db(); $id=(int)($_GET['id']??0); $title='Detalle de alerta';
$st=$pdo->prepare("SELECT a.*, r.name rule_name, r.rule_key, r.description rule_desc, r.threshold_value, r.window_minutes,
  e.source_key, e.ip_address, e.username, e.is_simulation,
  (SELECT id FROM incidents i WHERE i.alert_id=a.id LIMIT 1) incident_id
  FROM alerts a JOIN rules r ON r.id=a.rule_id JOIN events e ON e.id=a.event_id WHERE a.id=?");
$st->execute([$id]); $a=$st->fetch();
if(!$a){http_response_code(404);require __DIR__.'/includes/header.php';echo '<div class="panel">Alerta no encontrada. <a href="alertas.php">Volver a alertas</a></div>';require __DIR__.'/includes/footer.php';exit;}
$ev=$pdo->prepare('SELECT e.* FROM alert_events ae JOIN events e ON e.id=ae.event_id WHERE ae.alert_id=? ORDER BY e.created_at, e.id');
$ev->execute([$id]); $evidence=$ev->fetchAll();
$first=$evidence[0]['created_at']??$a['created_at']; $last=$evidence?end($evidence)['created_at']:$a['created_at'];
$canAct=in_array(current_user()['role'],['admin','analyst'],true);
require __DIR__.'/includes/header.php'; ?>
<div class="page-head"><div><div class="small-muted mb-1"><a href="alertas.php?view=all&amp;rule=<?= urlencode($a['rule_key']) ?>">Regla: <?= esc($a['rule_name']) ?></a></div><h2><?= esc($a['title']) ?><?= sim_badge($a['is_simulation']) ?></h2><p><?= esc($a['rule_desc']) ?></p></div><a href="alertas.php" class="btn btn-sm btn-ghost">Volver</a></div>
<div class="row g-3 mb-3">
 <div class="col-lg-8"><div class="panel h-100"><div class="d-flex justify-content-between flex-wrap gap-2 mb-3"><div><span class="badge text-bg-<?= severity_badge($a['severity']) ?>"><?= strtoupper($a['severity']) ?></span> <span class="badge text-bg-<?= status_badge($a['status']) ?>"><?= esc(human_status($a['status'])) ?></span></div><div class="risk-number">RISK <?= (int)$a['risk_score'] ?>/100</div></div>
  <div class="row g-3 small">
   <div class="col-md-4"><span class="text-secondary">Fuente</span><br><strong><?= esc($a['source_key']) ?></strong></div>
   <div class="col-md-4"><span class="text-secondary">IP involucrada</span><br><strong><a href="eventos.php?ip=<?= urlencode((string)$a['ip_address']) ?>"><?= esc($a['ip_address']) ?></a></strong></div>
   <div class="col-md-4"><span class="text-secondary">Usuario</span><br><strong><?= esc($a['username']?:'anonymous') ?></strong></div>
   <div class="col-md-4"><span class="text-secondary">Primer evento</span><br><?= esc((string)$first) ?></div>
   <div class="col-md-4"><span class="text-secondary">Último evento</span><br><?= esc((string)$last) ?></div>
   <div class="col-md-4"><span class="text-secondary">Condición de la regla</span><br>Umbral <?= (int)$a['threshold_value'] ?> · ventana <?= (int)$a['window_minutes'] ?> min</div>
  </div></div></div>
 <div class="col-lg-4"><div class="panel h-100"><h5>Respuesta</h5>
  <?php if($a['incident_id']): ?><p class="small">Esta alerta ya tiene un incidente abierto.</p><a class="btn btn-sm btn-cyber" href="incidente_detalle.php?id=<?= (int)$a['incident_id'] ?>">Ver incidente #<?= (int)$a['incident_id'] ?></a>
  <?php elseif($canAct && in_array($a['status'],['new','investigating'],true)): ?>
  <form method="post" action="actions/alert_action.php" class="d-flex gap-2 flex-wrap"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="alert_id" value="<?= (int)$a['id'] ?>">
   <?php if($a['status']==='new'): ?><button name="action" value="investigate" class="btn btn-sm btn-outline-info">Investigar</button><?php endif; ?>
   <button name="action" value="incident" class="btn btn-sm btn-outline-warning">Crear incidente</button>
   <button name="action" value="resolve" class="btn btn-sm btn-outline-success">Resolver</button>
   <button name="action" value="false_positive" class="btn btn-sm btn-outline-secondary">Falso positivo</button>
  </form>
  <?php else: ?><p class="small text-secondary">Alerta <?= esc(strtolower(human_status($a['status']))) ?><?= $a['resolved_at']?' el '.esc($a['resolved_at']):'' ?>.</p><?php endif; ?>
 </div></div>
</div>
<div class="panel"><h5>Evidencia <span class="badge text-bg-secondary"><?= count($evidence) ?></span></h5>
<p class="small text-secondary mb-3">Eventos que dispararon esta alerta, del más antiguo al más reciente. Use "Ver datos" para el detalle de cada uno.</p>
<?= render_evidence_table($evidence) ?></div>
<?php require __DIR__.'/includes/footer.php'; ?>
