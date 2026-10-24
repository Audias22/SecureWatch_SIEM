<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_login();
require_once __DIR__.'/includes/functions.php';
$pdo=db(); $id=(int)($_GET['id']??0); $title='Detalle de incidente';
$stmt=$pdo->prepare("SELECT i.*, a.risk_score,a.title alert_title,a.created_at alert_created,r.name rule_name,r.rule_key,
 e.source_key,e.ip_address,e.username,e.event_type,e.endpoint,
 creator.full_name creator,assignee.full_name assignee
 FROM incidents i
 LEFT JOIN alerts a ON a.id=i.alert_id
 LEFT JOIN rules r ON r.id=a.rule_id
 LEFT JOIN events e ON e.id=a.event_id
 LEFT JOIN users creator ON creator.id=i.created_by
 LEFT JOIN users assignee ON assignee.id=i.assigned_to
 WHERE i.id=?");
$stmt->execute([$id]);$inc=$stmt->fetch();
if(!$inc){http_response_code(404);exit('Incidente no encontrado.');}
$e=$pdo->prepare("SELECT ev.* FROM alert_events ae JOIN events ev ON ev.id=ae.event_id WHERE ae.alert_id=? ORDER BY ev.created_at,ev.id");
$e->execute([(int)$inc['alert_id']]);$evidence=$e->fetchAll();
$notes=$pdo->prepare("SELECT n.*,u.full_name FROM incident_notes n JOIN users u ON u.id=n.user_id WHERE n.incident_id=? ORDER BY n.id DESC");$notes->execute([$id]);$notes=$notes->fetchAll();
$history=$pdo->prepare("SELECT h.*,u.full_name FROM incident_history h LEFT JOIN users u ON u.id=h.user_id WHERE h.incident_id=? ORDER BY h.id DESC");$history->execute([$id]);$history=$history->fetchAll();
$analysts=$pdo->query("SELECT id,full_name,username FROM users WHERE active=1 AND role IN ('admin','analyst') ORDER BY full_name")->fetchAll();
$canAct=in_array(current_user()['role'],['admin','analyst'],true);
require __DIR__.'/includes/header.php'; ?>
<div class="page-head"><div><h2>Incidente #<?= (int)$inc['id'] ?></h2><p><?= esc($inc['title']) ?></p></div><a href="incidentes.php" class="btn btn-sm btn-outline-secondary">Volver</a></div>
<div class="row g-3 mb-3">
 <div class="col-lg-8"><div class="panel h-100">
  <div class="d-flex justify-content-between flex-wrap gap-2 mb-3"><div><span class="badge text-bg-<?= severity_badge($inc['severity']) ?>"><?= strtoupper($inc['severity']) ?></span> <span class="badge text-bg-<?= status_badge($inc['status']) ?>"><?= esc(human_status($inc['status'])) ?></span></div><div class="risk-number">RISK <?= (int)($inc['risk_score']??0) ?>/100</div></div>
  <div class="row g-3 small">
   <div class="col-md-4"><span class="text-secondary">Fuente</span><br><strong><?= esc($inc['source_key']?:'Interno') ?></strong></div>
   <div class="col-md-4"><span class="text-secondary">IP involucrada</span><br><strong><?= esc($inc['ip_address']?:'—') ?></strong></div>
   <div class="col-md-4"><span class="text-secondary">Usuario objetivo</span><br><strong><?= esc($inc['username']?:'anonymous') ?></strong></div>
   <div class="col-md-4"><span class="text-secondary">Regla</span><br><?= esc($inc['rule_key']?:'—') ?> · <?= esc($inc['rule_name']?:'—') ?></div>
   <div class="col-md-4"><span class="text-secondary">Creado por</span><br><?= esc($inc['creator']?:'—') ?></div>
   <div class="col-md-4"><span class="text-secondary">Analista</span><br><?= esc($inc['assignee']?:'Sin asignar') ?></div>
  </div>
 </div></div>
 <div class="col-lg-4"><div class="panel h-100"><h5>Fechas del ciclo</h5><div class="small"><div class="mb-2"><span class="text-secondary">Creado:</span><br><?= esc($inc['created_at']) ?></div><div class="mb-2"><span class="text-secondary">Contenido:</span><br><?= esc($inc['contained_at']?:'—') ?></div><div class="mb-2"><span class="text-secondary">Resuelto:</span><br><?= esc($inc['resolved_at']?:'—') ?></div><div><span class="text-secondary">Cerrado:</span><br><?= esc($inc['closed_at']?:'—') ?></div></div></div></div>
</div>

<?php if($canAct): ?><div class="panel mb-3"><h5>Gestionar incidente</h5><form method="post" action="actions/incident_action.php" class="row g-3"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="incident_id" value="<?= (int)$inc['id'] ?>">
 <div class="col-md-3"><label class="form-label">Estado</label><select class="form-select" name="status"><?php foreach(['open','investigating','contained','resolved','closed'] as $s): ?><option value="<?= $s ?>" <?= $inc['status']===$s?'selected':'' ?>><?= esc(human_status($s)) ?></option><?php endforeach; ?></select></div>
 <div class="col-md-3"><label class="form-label">Analista asignado</label><select class="form-select" name="assigned_to"><option value="">Sin asignar</option><?php foreach($analysts as $a): ?><option value="<?= (int)$a['id'] ?>" <?= (int)($inc['assigned_to']??0)===(int)$a['id']?'selected':'' ?>><?= esc($a['full_name']) ?></option><?php endforeach; ?></select></div>
 <div class="col-md-6"><label class="form-label">Resolución / acción tomada</label><input class="form-control" name="resolution" value="<?= esc($inc['resolution']) ?>" placeholder="Ej.: se restableció la contraseña y se revisó la cuenta"></div>
 <div class="col-12"><button class="btn btn-cyber">Guardar cambios</button></div>
 </form></div><?php endif; ?>

<div class="row g-3">
 <div class="col-xl-8"><div class="panel mb-3"><h5>Evidencia relacionada <span class="badge bg-dark"><?= count($evidence) ?></span></h5><?= render_evidence_table($evidence) ?></div>

 <div class="panel"><h5>Notas del analista</h5><?php if($canAct): ?><form method="post" action="actions/incident_action.php" class="mb-3"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="incident_id" value="<?= (int)$inc['id'] ?>"><input type="hidden" name="action" value="add_note"><textarea class="form-control mb-2" rows="3" name="note" placeholder="Documenta hallazgos, decisiones o acciones realizadas..." required></textarea><button class="btn btn-sm btn-cyber">Agregar nota</button></form><?php endif; ?>
 <?php foreach($notes as $n): ?><div class="border-top border-secondary-subtle py-3"><div><?= nl2br(esc($n['note'])) ?></div><div class="small-muted mt-1"><?= esc($n['full_name']) ?> · <?= esc($n['created_at']) ?></div></div><?php endforeach; ?><?php if(!$notes): ?><div class="text-secondary small">Aún no hay notas.</div><?php endif; ?></div></div>

 <div class="col-xl-4"><div class="panel"><h5>Línea de tiempo</h5><div class="timeline"><?php foreach($history as $h): ?><div class="timeline-item"><div><strong><?= esc($h['details']?:$h['action']) ?></strong></div><div class="small text-secondary"><?= esc($h['full_name']?:'Sistema') ?></div><div class="timeline-time"><?= esc($h['created_at']) ?></div></div><?php endforeach; ?><div class="timeline-item"><div><strong>Incidente originado</strong></div><div class="timeline-time"><?= esc($inc['created_at']) ?></div></div></div></div></div>
</div>
<?php require __DIR__.'/includes/footer.php'; ?>
