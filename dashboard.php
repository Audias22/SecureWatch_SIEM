<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_login();
require_once __DIR__.'/includes/functions.php';
$pdo=db();$title='Dashboard';
$eventsToday=(int)$pdo->query('SELECT COUNT(*) FROM events WHERE DATE(created_at)=CURDATE()')->fetchColumn();
$simToday=(int)$pdo->query('SELECT COUNT(*) FROM events WHERE DATE(created_at)=CURDATE() AND is_simulation=1')->fetchColumn();
$alertsOpen=(int)$pdo->query("SELECT COUNT(*) FROM alerts WHERE status IN ('new','investigating')")->fetchColumn();
$critical=(int)$pdo->query("SELECT COUNT(*) FROM alerts WHERE severity='critical' AND status IN ('new','investigating')")->fetchColumn();
$incidents=(int)$pdo->query("SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating','contained')")->fetchColumn();
$sourcesActive=(int)$pdo->query('SELECT COUNT(*) FROM sources WHERE active=1')->fetchColumn();
$sourcesOnline=(int)$pdo->query("SELECT COUNT(*) FROM sources WHERE active=1 AND last_seen_at >= (NOW()-INTERVAL 5 MINUTE)")->fetchColumn();
$recent=$pdo->query('SELECT * FROM events ORDER BY id DESC LIMIT 10')->fetchAll();
$recentAlerts=$pdo->query("SELECT a.id,a.title,a.severity,a.status,a.risk_score,a.created_at,e.source_key,e.ip_address,e.is_simulation FROM alerts a JOIN events e ON e.id=a.event_id ORDER BY a.id DESC LIMIT 6")->fetchAll();
$severity=$pdo->query("SELECT severity,COUNT(*) total FROM alerts WHERE created_at >= DATE_SUB(NOW(),INTERVAL 30 DAY) GROUP BY severity")->fetchAll();
$days=$pdo->query("SELECT DATE(created_at) d,COUNT(*) total FROM events WHERE created_at>=DATE_SUB(CURDATE(),INTERVAL 6 DAY) GROUP BY DATE(created_at) ORDER BY d")->fetchAll();
$rules=$pdo->query("SELECT r.rule_key,r.name,COUNT(a.id) total FROM rules r LEFT JOIN alerts a ON a.rule_id=r.id AND a.created_at>=DATE_SUB(NOW(),INTERVAL 30 DAY) GROUP BY r.id,r.rule_key,r.name HAVING total>0 ORDER BY total DESC LIMIT 5")->fetchAll();
require __DIR__.'/includes/header.php';
?>
<div class="page-head"><div><h2>Security Operations Center</h2><p>Monitoreo centralizado de eventos, fuentes, alertas e incidentes.</p></div><span class="live-pill">Monitoreo activo</span></div>
<div class="row g-3 mb-4">
<?php foreach([
['Eventos hoy',$eventsToday,'primary',($eventsToday-$simToday).' reales · '.$simToday.' simulados'],['Alertas activas',$alertsOpen,'warning','Pendientes de revisión'],['Críticas',$critical,'danger','Prioridad inmediata'],['Incidentes activos',$incidents,'info','Abiertos / investigando'],['Fuentes',$sourcesOnline.'/'.$sourcesActive,'success','En línea / activas']
] as $c): ?><div class="col-6 col-xl"><div class="metric-card h-100"><div class="metric-label"><?= esc((string)$c[0]) ?></div><div class="metric-value text-<?= esc((string)$c[2]) ?>"><?= esc((string)$c[1]) ?></div><div class="metric-sub"><?= esc((string)$c[3]) ?></div></div></div><?php endforeach; ?>
</div>
<div class="row g-3 mb-4">
 <div class="col-xl-8"><div class="panel h-100"><h5>Eventos — últimos 7 días</h5>
 <?php $maxDay=max([1,...array_map('intval',array_column($days,'total'))]); foreach($days as $d): $pct=((int)$d['total']/$maxDay)*100; ?>
 <div class="bar-row"><div class="bar-label"><?= esc($d['d']) ?></div><div class="bar-track"><div class="bar-fill" style="width:<?= round($pct,1) ?>%"></div></div><div class="bar-value"><?= (int)$d['total'] ?></div></div>
 <?php endforeach; ?><?php if(!$days): ?><div class="text-secondary small">Sin eventos todavía.</div><?php endif; ?>
 </div></div>
 <div class="col-xl-4"><div class="panel h-100"><h5>Alertas por severidad — 30 días</h5>
 <?php $maxSev=max([1,...array_map('intval',array_column($severity,'total'))]); foreach($severity as $sv): $pct=((int)$sv['total']/$maxSev)*100; ?>
 <div class="bar-row"><div class="bar-label"><?= esc(strtoupper($sv['severity'])) ?></div><div class="bar-track"><div class="bar-fill sev-<?= esc($sv['severity']) ?>" style="width:<?= round($pct,1) ?>%"></div></div><div class="bar-value"><?= (int)$sv['total'] ?></div></div>
 <?php endforeach; ?><?php if(!$severity): ?><div class="text-secondary small">Sin alertas todavía.</div><?php endif; ?>
 </div></div>
</div>
<div class="row g-3 mb-4">
 <div class="col-xl-7"><div class="panel h-100"><div class="d-flex justify-content-between"><h5>Actividad reciente</h5><a href="eventos.php" class="small">Ver todos</a></div><div class="table-responsive"><table class="table cyber-table"><thead><tr><th>Hora</th><th>Fuente</th><th>Evento</th><th>Usuario</th><th>IP</th><th>Nivel</th></tr></thead><tbody><?php foreach($recent as $e): ?><tr><td><?= date('H:i:s',strtotime($e['created_at'])) ?></td><td><?= esc($e['source_key']) ?></td><td><?= esc($e['event_type']) ?><?= sim_badge($e['is_simulation']) ?></td><td><?= esc($e['username']?:'—') ?></td><td><?= esc($e['ip_address']) ?></td><td><span class="badge text-bg-<?= severity_badge($e['severity']) ?>"><?= strtoupper($e['severity']) ?></span></td></tr><?php endforeach; ?></tbody></table></div></div></div>
 <div class="col-xl-5"><div class="panel h-100"><div class="d-flex justify-content-between"><h5>Alertas recientes</h5><a href="alertas.php" class="small">Ver todas</a></div><?php foreach($recentAlerts as $a): ?><div class="border-top border-secondary-subtle py-2"><div class="d-flex justify-content-between gap-2"><strong class="small"><a class="title-link" href="alerta.php?id=<?= (int)$a['id'] ?>"><?= esc($a['title']) ?></a><?= sim_badge($a['is_simulation']) ?></strong><span class="badge text-bg-<?= severity_badge($a['severity']) ?>"><?= strtoupper($a['severity']) ?></span></div><div class="small-muted mt-1"><?= esc($a['source_key']) ?> · <?= esc($a['ip_address']) ?> · Risk <?= (int)$a['risk_score'] ?></div></div><?php endforeach; ?><?php if(!$recentAlerts): ?><div class="text-secondary small">Aún no hay alertas.</div><?php endif; ?></div></div>
</div>
<div class="panel"><h5>Principales detecciones — 30 días</h5><div class="row g-3"><?php foreach($rules as $r): ?><div class="col-md"><a class="metric-card metric-link" href="alertas.php?view=all&amp;rule=<?= urlencode($r['rule_key']) ?>&amp;from=<?= date('Y-m-d',strtotime('-30 days')) ?>"><div class="metric-label"><?= esc($r['name']) ?></div><div class="metric-value"><?= (int)$r['total'] ?></div></a></div><?php endforeach; ?><?php if(!$rules): ?><div class="col text-secondary">Sin detecciones todavía.</div><?php endif; ?></div></div>
<?php require __DIR__.'/includes/footer.php'; ?>
