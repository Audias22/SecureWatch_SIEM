<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_login();
$pdo=db(); $title='Incidentes';
$view=(string)($_GET['view']??'active');
$where=match($view){
 'resolved'=>"WHERE i.status IN ('resolved','closed')",
 'all'=>'',
 default=>"WHERE i.status IN ('open','investigating','contained')"
};
$items=$pdo->query("SELECT i.*, a.risk_score, a.source_id, e.source_key, e.ip_address, e.username, e.is_simulation,
 creator.full_name creator, assignee.full_name assignee
 FROM incidents i
 LEFT JOIN alerts a ON a.id=i.alert_id
 LEFT JOIN events e ON e.id=a.event_id
 LEFT JOIN users creator ON creator.id=i.created_by
 LEFT JOIN users assignee ON assignee.id=i.assigned_to
 {$where} ORDER BY FIELD(i.status,'open','investigating','contained','resolved','closed'), i.updated_at DESC")->fetchAll();
require __DIR__.'/includes/header.php'; ?>
<div class="page-head"><div><h2>Incidentes de seguridad</h2><p>Gestiona investigación, contención, resolución y cierre sin eliminar el historial.</p></div></div>
<ul class="nav nav-pills mb-3">
<li class="nav-item"><a class="nav-link <?= $view==='active'?'active':'' ?>" href="incidentes.php?view=active">Activos</a></li>
<li class="nav-item"><a class="nav-link <?= $view==='resolved'?'active':'' ?>" href="incidentes.php?view=resolved">Resueltos / cerrados</a></li>
<li class="nav-item"><a class="nav-link <?= $view==='all'?'active':'' ?>" href="incidentes.php?view=all">Todos</a></li>
</ul>
<div class="panel"><div class="table-responsive"><table class="table cyber-table"><thead><tr><th>ID</th><th>Incidente</th><th>Fuente / IP</th><th>Severidad</th><th>Estado</th><th>Risk</th><th>Analista</th><th>Actualizado</th><th></th></tr></thead><tbody>
<?php foreach($items as $i): ?><tr>
<td>#<?= (int)$i['id'] ?></td>
<td><strong><?= esc($i['title']) ?></strong><?= sim_badge($i['is_simulation']??0) ?><div class="small text-secondary"><?= esc($i['username']?:'anonymous') ?></div></td>
<td><?= esc($i['source_key']?:'Interno') ?><div class="small text-secondary"><?= esc($i['ip_address']?:'—') ?></div></td>
<td><span class="badge text-bg-<?= severity_badge($i['severity']) ?>"><?= strtoupper($i['severity']) ?></span></td>
<td><span class="badge text-bg-<?= status_badge($i['status']) ?>"><?= esc(human_status($i['status'])) ?></span></td>
<td><strong><?= (int)($i['risk_score']??0) ?></strong></td><td><?= esc($i['assignee']?:'Sin asignar') ?></td><td><?= esc($i['updated_at']) ?></td>
<td><a class="btn btn-sm btn-outline-info" href="incidente_detalle.php?id=<?= (int)$i['id'] ?>">Abrir</a></td>
</tr><?php endforeach; ?>
<?php if(!$items): ?><tr><td colspan="9" class="text-center py-5 text-secondary">No hay incidentes en esta vista.</td></tr><?php endif; ?>
</tbody></table></div></div>
<?php require __DIR__.'/includes/footer.php'; ?>
