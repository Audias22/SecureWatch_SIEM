<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_login();
require_once __DIR__.'/includes/functions.php';
$pdo=db(); $title='Eventos';
$severity=trim((string)($_GET['severity']??''));
$source=trim((string)($_GET['source']??''));
$type=trim((string)($_GET['type']??''));
$ip=trim((string)($_GET['ip']??''));
$origin=(string)($_GET['origin']??'');
$from=preg_match('/^\d{4}-\d{2}-\d{2}$/',(string)($_GET['from']??''))?(string)$_GET['from']:'';
$to=preg_match('/^\d{4}-\d{2}-\d{2}$/',(string)($_GET['to']??''))?(string)$_GET['to']:'';
$where=[];$params=[];
if($from!==''){ $where[]='e.created_at>=?'; $params[]=$from.' 00:00:00'; }
if($to!==''){ $where[]='e.created_at<=?'; $params[]=$to.' 23:59:59'; }
if($origin==='real'){ $where[]='e.is_simulation=0'; }
if($origin==='sim'){ $where[]='e.is_simulation=1'; }
if(in_array($severity,['low','medium','high','critical'],true)){ $where[]='e.severity=?'; $params[]=$severity; }
if($source!==''){ $where[]='e.source_key=?'; $params[]=$source; }
if($type!==''){ $where[]='e.event_type=?'; $params[]=$type; }
if($ip!==''){ $where[]=filter_var($ip,FILTER_VALIDATE_IP)?'e.ip_address=?':'e.ip_address LIKE ?'; $params[]=filter_var($ip,FILTER_VALIDATE_IP)?$ip:'%'.$ip.'%'; }
$sql='SELECT e.* FROM events e'.($where?' WHERE '.implode(' AND ',$where):'').' ORDER BY e.id DESC LIMIT 300';
$stmt=$pdo->prepare($sql);$stmt->execute($params);$events=$stmt->fetchAll();
$sources=$pdo->query('SELECT DISTINCT source_key FROM events ORDER BY source_key')->fetchAll();
$types=$pdo->query('SELECT DISTINCT event_type FROM events ORDER BY event_type')->fetchAll();
require __DIR__.'/includes/header.php'; ?>
<div class="page-head"><div><h2>Eventos de seguridad</h2><p>Bitácora central de actividad interna y de fuentes externas.</p></div></div>
<div class="panel">
<form class="row g-2 mb-3">
 <div class="col-md-2"><select name="severity" class="form-select form-select-sm"><option value="">Severidad</option><?php foreach(['low','medium','high','critical'] as $s): ?><option <?= $severity===$s?'selected':'' ?> value="<?= $s ?>"><?= strtoupper($s) ?></option><?php endforeach; ?></select></div>
 <div class="col-md-2"><select name="source" class="form-select form-select-sm"><option value="">Fuente</option><?php foreach($sources as $s): ?><option <?= $source===$s['source_key']?'selected':'' ?> value="<?= esc($s['source_key']) ?>"><?= esc($s['source_key']) ?></option><?php endforeach; ?></select></div>
 <div class="col-md-2"><select name="type" class="form-select form-select-sm"><option value="">Tipo de evento</option><?php foreach($types as $t): ?><option <?= $type===$t['event_type']?'selected':'' ?> value="<?= esc($t['event_type']) ?>"><?= esc($t['event_type']) ?></option><?php endforeach; ?></select></div>
 <div class="col-md-2"><input name="ip" class="form-control form-control-sm" placeholder="IP" value="<?= esc($ip) ?>"></div>
 <div class="col-md-2"><select name="origin" class="form-select form-select-sm"><option value="">Origen: todos</option><option value="real" <?= $origin==='real'?'selected':'' ?>>Solo reales</option><option value="sim" <?= $origin==='sim'?'selected':'' ?>>Solo simulados</option></select></div>
 <div class="col-md-2"><input type="date" name="from" class="form-control form-control-sm" value="<?= esc($from) ?>" title="Desde"></div>
 <div class="col-md-2"><input type="date" name="to" class="form-control form-control-sm" value="<?= esc($to) ?>" title="Hasta"></div>
 <div class="col-auto"><button class="btn btn-sm btn-cyber">Filtrar</button> <a class="btn btn-sm btn-outline-secondary" href="eventos.php">Limpiar filtros</a></div>
</form>
<div class="table-responsive"><table class="table cyber-table"><thead><tr><th>Fecha</th><th>Fuente</th><th>Usuario</th><th>Evento</th><th>IP</th><th>Endpoint / Descripción</th><th>Resultado</th><th>Nivel</th></tr></thead><tbody>
<?php foreach($events as $e): ?><tr>
<td class="text-nowrap"><?= esc($e['created_at']) ?></td><td><?= esc($e['source_key']) ?></td><td><?= esc($e['username']?:'—') ?></td><td><a href="evento.php?id=<?= (int)$e['id'] ?>"><strong><?= esc($e['event_type']) ?></strong></a><?= sim_badge($e['is_simulation']) ?></td><td><?= esc($e['ip_address']) ?></td>
<td><?php if($e['endpoint']): ?><div class="evidence-code" title="<?= esc($e['endpoint']) ?>"><?= esc($e['http_method']) ?> <?= esc($e['endpoint']) ?></div><?php endif; ?><div class="small text-secondary"><?= esc($e['description']) ?></div></td>
<td><?= esc($e['result']) ?></td><td><span class="badge text-bg-<?= severity_badge($e['severity']) ?>"><?= strtoupper($e['severity']) ?></span></td></tr><?php endforeach; ?>
</tbody></table></div></div>
<?php require __DIR__.'/includes/footer.php'; ?>
