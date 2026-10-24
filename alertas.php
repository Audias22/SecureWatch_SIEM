<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_login();
$pdo=db(); $title='Alertas';
$view=(string)($_GET['view']??'active');
// Filtros opcionales (llegan desde Reportes, el Dashboard o el detalle de una alerta)
$fRule=preg_match('/^[A-Z_]{3,60}$/',(string)($_GET['rule']??''))?(string)$_GET['rule']:'';
$fSev=in_array($_GET['severity']??'',['low','medium','high','critical'],true)?(string)$_GET['severity']:'';
$fFrom=preg_match('/^\d{4}-\d{2}-\d{2}$/',(string)($_GET['from']??''))?(string)$_GET['from']:'';
$fTo=preg_match('/^\d{4}-\d{2}-\d{2}$/',(string)($_GET['to']??''))?(string)$_GET['to']:'';
$fIp=filter_var($_GET['ip']??'',FILTER_VALIDATE_IP)?(string)$_GET['ip']:'';
$hasFilter=$fRule||$fSev||$fFrom||$fTo||$fIp;
if($hasFilter && !isset($_GET['view'])) $view='all';
$where=[];$params=[];
if($view==='resolved') $where[]="a.status IN ('resolved','false_positive')";
elseif($view!=='all') $where[]="a.status IN ('new','investigating')";
if($fRule){$where[]='r.rule_key=?';$params[]=$fRule;}
if($fSev){$where[]='a.severity=?';$params[]=$fSev;}
if($fFrom){$where[]='a.created_at>=?';$params[]=$fFrom.' 00:00:00';}
if($fTo){$where[]='a.created_at<=?';$params[]=$fTo.' 23:59:59';}
if($fIp){$where[]='e.ip_address=?';$params[]=$fIp;}
$st=$pdo->prepare("SELECT a.*, r.name rule_name, r.mitre_id, r.mitre_name, r.mitre_tactic, e.username, e.ip_address, e.source_key, e.endpoint, e.is_simulation,
 (SELECT COUNT(*) FROM alert_events ae WHERE ae.alert_id=a.id) evidence_count,
 (SELECT id FROM incidents i WHERE i.alert_id=a.id LIMIT 1) incident_id
 FROM alerts a JOIN rules r ON r.id=a.rule_id JOIN events e ON e.id=a.event_id".($where?' WHERE '.implode(' AND ',$where):'')."
 ORDER BY FIELD(a.status,'new','investigating','resolved','false_positive'), a.id DESC LIMIT 250");
$st->execute($params);$alerts=$st->fetchAll();
$ruleName='';
if($fRule){$rn=$pdo->prepare('SELECT name FROM rules WHERE rule_key=?');$rn->execute([$fRule]);$ruleName=(string)$rn->fetchColumn();}
$keep=array_filter(['rule'=>$fRule,'severity'=>$fSev,'from'=>$fFrom,'to'=>$fTo,'ip'=>$fIp]);
$qs=fn(string $v)=>'alertas.php?'.http_build_query(['view'=>$v]+$keep);
require __DIR__.'/includes/header.php';
$canAct=in_array(current_user()['role'],['admin','analyst'],true);
?>
<div class="page-head"><div><h2>Alertas</h2><p>Hallazgos del motor de correlación que requieren revisión.</p></div></div>
<ul class="nav nav-pills mb-3">
 <li class="nav-item"><a class="nav-link <?= $view==='active'?'active':'' ?>" href="<?= esc($qs('active')) ?>">Activas</a></li>
 <li class="nav-item"><a class="nav-link <?= $view==='resolved'?'active':'' ?>" href="<?= esc($qs('resolved')) ?>">Resueltas</a></li>
 <li class="nav-item"><a class="nav-link <?= $view==='all'?'active':'' ?>" href="<?= esc($qs('all')) ?>">Todas</a></li>
</ul>
<?php if($hasFilter): ?><div class="filter-bar mb-3"><span>Filtrando:</span>
<?php if($fRule): ?><span class="chip">Regla: <?= esc($ruleName?:$fRule) ?></span><?php endif; ?>
<?php if($fSev): ?><span class="chip">Severidad: <?= strtoupper(esc($fSev)) ?></span><?php endif; ?>
<?php if($fIp): ?><span class="chip">IP: <?= esc($fIp) ?></span><?php endif; ?>
<?php if($fFrom||$fTo): ?><span class="chip">Período: <?= esc($fFrom?:'…') ?> a <?= esc($fTo?:'…') ?></span><?php endif; ?>
<span class="chip">Resultados: <?= count($alerts) ?></span>
<a href="alertas.php">Quitar filtros</a></div><?php endif; ?>
<div class="row g-3">
<?php foreach($alerts as $a): ?>
<div class="col-xl-6"><div class="alert-card severity-<?= esc($a['severity']) ?> h-100">
  <div class="d-flex justify-content-between gap-3">
    <div><span class="badge text-bg-<?= severity_badge($a['severity']) ?>"><?= strtoupper($a['severity']) ?></span><span class="badge text-bg-<?= status_badge($a['status']) ?> ms-1"><?= esc(human_status($a['status'])) ?></span><?= sim_badge($a['is_simulation']) ?></div>
    <strong>RISK <?= (int)$a['risk_score'] ?>/100</strong>
  </div>
  <h5 class="mt-3 mb-2"><a class="title-link" href="alerta.php?id=<?= (int)$a['id'] ?>"><?= esc($a['title']) ?></a></h5>
  <div class="small text-secondary mb-2">Regla: <?= esc($a['rule_name']) ?> <?= mitre_tag($a['mitre_id'],$a['mitre_name'],$a['mitre_tactic']) ?></div>
  <div class="small mb-3">Fuente: <strong><?= esc($a['source_key']) ?></strong> · IP: <strong><?= esc($a['ip_address']) ?></strong> · Usuario: <?= esc($a['username']?:'anonymous') ?></div>
  <div class="small-muted mb-3"><a href="alerta.php?id=<?= (int)$a['id'] ?>"><?= (int)$a['evidence_count'] ?> evento(s) de evidencia</a> · <?= esc($a['created_at']) ?></div>
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
