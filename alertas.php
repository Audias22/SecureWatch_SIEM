<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_login();
$pdo=db(); $title='Alertas';
$view=(string)($_GET['view']??'active');
$where = match($view){
    'resolved' => "WHERE a.status IN ('resolved','false_positive')",
    'all' => '',
    default => "WHERE a.status IN ('new','investigating')"
};
$alerts=$pdo->query("SELECT a.*, r.name rule_name, e.username, e.ip_address, e.source_key, e.endpoint, e.is_simulation,
 (SELECT COUNT(*) FROM alert_events ae WHERE ae.alert_id=a.id) evidence_count,
 (SELECT id FROM incidents i WHERE i.alert_id=a.id LIMIT 1) incident_id
 FROM alerts a JOIN rules r ON r.id=a.rule_id JOIN events e ON e.id=a.event_id {$where}
 ORDER BY FIELD(a.status,'new','investigating','resolved','false_positive'), a.id DESC LIMIT 250")->fetchAll();
require __DIR__.'/includes/header.php';
$canAct=in_array(current_user()['role'],['admin','analyst'],true);
?>
<div class="page-head"><div><h2>Alertas</h2><p>Hallazgos del motor de correlación que requieren revisión.</p></div></div>
<ul class="nav nav-pills mb-3">
 <li class="nav-item"><a class="nav-link <?= $view==='active'?'active':'' ?>" href="alertas.php?view=active">Activas</a></li>
 <li class="nav-item"><a class="nav-link <?= $view==='resolved'?'active':'' ?>" href="alertas.php?view=resolved">Resueltas</a></li>
 <li class="nav-item"><a class="nav-link <?= $view==='all'?'active':'' ?>" href="alertas.php?view=all">Todas</a></li>
</ul>
<div class="row g-3">
<?php foreach($alerts as $a): ?>
<div class="col-xl-6"><div class="alert-card severity-<?= esc($a['severity']) ?> h-100">
  <div class="d-flex justify-content-between gap-3">
    <div><span class="badge text-bg-<?= severity_badge($a['severity']) ?>"><?= strtoupper($a['severity']) ?></span><span class="badge text-bg-<?= status_badge($a['status']) ?> ms-1"><?= esc(human_status($a['status'])) ?></span><?= sim_badge($a['is_simulation']) ?></div>
    <strong>RISK <?= (int)$a['risk_score'] ?>/100</strong>
  </div>
  <h5 class="mt-3 mb-2"><?= esc($a['title']) ?></h5>
  <div class="small text-secondary mb-2">Regla: <?= esc($a['rule_name']) ?></div>
  <div class="small mb-3">Fuente: <strong><?= esc($a['source_key']) ?></strong> · IP: <strong><?= esc($a['ip_address']) ?></strong> · Usuario: <?= esc($a['username']?:'anonymous') ?></div>
  <div class="small-muted mb-3"><?= (int)$a['evidence_count'] ?> evento(s) de evidencia · <?= esc($a['created_at']) ?></div>
  <?php if($a['incident_id']): ?><a class="btn btn-sm btn-outline-info" href="incidente_detalle.php?id=<?= (int)$a['incident_id'] ?>">Ver incidente #<?= (int)$a['incident_id'] ?></a><?php endif; ?>
  <?php if($canAct && in_array($a['status'],['new','investigating'],true)): ?>
  <form method="post" action="actions/alert_action.php" class="d-flex gap-2 flex-wrap mt-2">
    <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="alert_id" value="<?= (int)$a['id'] ?>">
    <?php if($a['status']==='new'): ?><button name="action" value="investigate" class="btn btn-sm btn-outline-info">Investigar</button><?php endif; ?>
    <?php if(!$a['incident_id']): ?><button name="action" value="incident" class="btn btn-sm btn-outline-warning">Crear incidente</button><?php endif; ?>
    <button name="action" value="resolve" class="btn btn-sm btn-outline-success">Resolver alerta</button>
    <button name="action" value="false_positive" class="btn btn-sm btn-outline-secondary">Falso positivo</button>
  </form>
  <?php endif; ?>
</div></div>
<?php endforeach; ?>
<?php if(!$alerts): ?><div class="col"><div class="panel text-center py-5">No hay alertas en esta vista.</div></div><?php endif; ?>
</div>
<?php require __DIR__.'/includes/footer.php'; ?>
