<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_login();
require_once __DIR__.'/includes/functions.php';
$pdo=db(); $title='Fuentes'; $msg=''; $newKey=$_SESSION['new_source_key']??null; unset($_SESSION['new_source_key']);
$isAdmin=current_user()['role']==='admin';

$canOperate=in_array(current_user()['role'],['admin','analyst'],true);
if($_SERVER['REQUEST_METHOD']==='POST' && $canOperate && in_array($_POST['action']??'',['collector_start','collector_stop'],true)){
    verify_csrf();
    if($_POST['action']==='collector_start'){ collector_launch(true); log_event($pdo,'ADMIN_ACTION','Inicio manual del colector Syslog','SUCCESS','low',(int)current_user()['id'],current_user()['username']); }
    else { collector_request_stop(); log_event($pdo,'ADMIN_ACTION','Detención manual del colector Syslog','SUCCESS','medium',(int)current_user()['id'],current_user()['username']); }
    sleep(2);
    header('Location: fuentes.php');exit;
}
if($_SERVER['REQUEST_METHOD']==='POST' && $isAdmin){
    verify_csrf();
    $action=(string)($_POST['action']??'create');
    if($action==='create'){
        $sourceKey=strtoupper(trim((string)($_POST['source_key']??'')));
        $name=trim((string)($_POST['name']??''));
        $type=trim((string)($_POST['source_type']??'Aplicación Web'));
        $expected=trim((string)($_POST['expected_ip']??''))?:null;
        $plain=trim((string)($_POST['api_key']??''));
        if($plain==='') $plain='SW-'.bin2hex(random_bytes(16));
        if(preg_match('/^[A-Z0-9_-]{3,80}$/',$sourceKey) && $name!==''){
            try{
                $pdo->prepare('INSERT INTO sources(source_key,name,source_type,expected_ip,api_key_hash) VALUES(?,?,?,?,?)')->execute([$sourceKey,$name,$type,$expected,hash('sha256',$plain)]);
                $_SESSION['new_source_key']=['source'=>$sourceKey,'key'=>$plain];
                log_event($pdo,'ADMIN_ACTION','Creación de fuente '.$sourceKey,'SUCCESS','medium',(int)current_user()['id'],current_user()['username']);
                header('Location: fuentes.php');exit;
            }catch(PDOException $e){$msg='No se pudo crear la fuente. Verifica que el identificador no esté repetido.';}
        }else{$msg='El identificador debe usar letras mayúsculas, números, guion o guion bajo.';}
    }
    if($action==='toggle'){
        $id=(int)($_POST['id']??0);$active=(int)($_POST['active']??0)===1?1:0;
        $pdo->prepare('UPDATE sources SET active=? WHERE id=?')->execute([$active,$id]);
        $s=$pdo->prepare('SELECT source_key FROM sources WHERE id=?');$s->execute([$id]);
        if($k=$s->fetchColumn()) log_event($pdo,'ADMIN_ACTION',($active?'Activación':'Desactivación').' de fuente '.$k,'SUCCESS','medium',(int)current_user()['id'],current_user()['username']);
        header('Location: fuentes.php');exit;
    }
    if($action==='regenerate'){
        $id=(int)($_POST['id']??0);$plain='SW-'.bin2hex(random_bytes(16));
        $s=$pdo->prepare('SELECT source_key FROM sources WHERE id=?');$s->execute([$id]);$key=$s->fetchColumn();
        if($key){$pdo->prepare('UPDATE sources SET api_key_hash=? WHERE id=?')->execute([hash('sha256',$plain),$id]);$_SESSION['new_source_key']=['source'=>$key,'key'=>$plain];log_event($pdo,'ADMIN_ACTION','Rotación de API Key de la fuente '.$key,'SUCCESS','medium',(int)current_user()['id'],current_user()['username']);}
        header('Location: fuentes.php');exit;
    }
}

$items=$pdo->query("SELECT s.*,
 (SELECT COUNT(*) FROM events e WHERE e.source_id=s.id AND DATE(e.created_at)=CURDATE()) events_today,
 (SELECT COUNT(*) FROM alerts a WHERE a.source_id=s.id AND DATE(a.created_at)=CURDATE()) alerts_today
 FROM sources s ORDER BY s.id")->fetchAll();
require __DIR__.'/includes/header.php';
$scheme=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http';
$host=$_SERVER['HTTP_HOST']??'IP_DEL_SIEM';
$base=rtrim(dirname($_SERVER['SCRIPT_NAME']??'/SecureWatch_SIEM/fuentes.php'),'/\\');
$endpoint=$scheme.'://'.$host.$base.'/api/events.php';
?>
<div class="page-head"><div><h2>Fuentes monitorizadas</h2><p>Aplicaciones y sistemas autorizados para enviar eventos a SecureWatch.</p></div><span class="live-pill">API disponible</span></div>
<?php if($newKey): ?><div class="alert alert-warning"><strong>Guarda esta API Key ahora.</strong> Por seguridad SecureWatch no puede volver a mostrarla.<div class="api-key-box mt-2"><?= esc($newKey['source']) ?> → <?= esc($newKey['key']) ?></div></div><?php endif; ?>
<?php if($msg): ?><div class="alert alert-info"><?= esc($msg) ?></div><?php endif; ?>
<div class="panel mb-3"><div class="small text-secondary">Endpoint receptor</div><div class="api-key-box mt-2"><?= esc($endpoint) ?></div><div class="small-muted mt-2">La fuente debe enviar <code>Content-Type: application/json</code> y el encabezado <code>X-API-Key</code>.</div></div>

<?php $cs=collector_status(); ?>
<div class="panel mb-3"><div class="row g-3 align-items-start">
 <div class="col-lg-4">
  <div class="small-muted mb-1">COLECTOR SYSLOG · MIKROTIK</div>
  <div class="status-line <?= $cs['running']?'on':'' ?>"><i></i><?= $cs['running']?'Activo y escuchando':'Detenido' ?></div>
  <div class="small text-secondary mt-1"><?php if($cs['running']): ?>Recibe los logs del router en segundo plano.<?php elseif(!empty($cs['stop_reason'])): ?>Se detuvo: <?= esc((string)$cs['stop_reason']) ?> (<?= esc((string)($cs['stopped_at']??'')) ?>).<?php else: ?>Todavía no se ha ejecutado.<?php endif; ?></div>
  <?php if($canOperate): ?><form method="post" class="mt-3"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
   <?php if($cs['running']): ?><button class="btn btn-sm btn-ghost" name="action" value="collector_stop">Detener colector</button>
   <?php else: ?><button class="btn btn-sm btn-cyber" name="action" value="collector_start">Iniciar colector</button><?php endif; ?>
  </form><?php endif; ?>
 </div>
 <div class="col-lg-8"><div class="row g-2 kv">
  <div class="col-sm-6"><span class="text-secondary">Escucha</span><br><?= esc((string)($cs['listen'] ?? 'udp://0.0.0.0:514')) ?></div>
  <div class="col-sm-6"><span class="text-secondary">Remitentes autorizados</span><br><?= esc(implode(', ', (array)($cs['allowed'] ?? ['192.168.88.1']))) ?></div>
  <div class="col-sm-6"><span class="text-secondary">En ejecución desde</span><br><?= esc((string)($cs['started_at'] ?? '—')) ?><?= isset($cs['pid']) ? ' · PID '.(int)$cs['pid'] : '' ?></div>
  <div class="col-sm-6"><span class="text-secondary">Último mensaje del router</span><br><?= esc((string)($cs['last_message_at'] ?? '—')) ?></div>
  <div class="col-sm-6"><span class="text-secondary">Mensajes procesados / rechazados</span><br><?= (int)($cs['received'] ?? 0) ?> / <?= (int)($cs['rejected'] ?? 0) ?></div>
  <div class="col-sm-6"><span class="text-secondary">Base de datos</span><br><?= esc((string)($cs['db'] ?? '—')) ?></div>
 </div></div>
 <div class="col-12 small-muted">Se enciende solo al abrir SecureWatch y se apaga solo si MySQL deja de estar disponible por 5 minutos. Si lo detiene aquí, no se vuelve a encender solo hasta el día siguiente.</div>
</div></div>

<?php $tail=collector_tail(40); ?>
<div class="panel mb-3"><div class="d-flex justify-content-between align-items-center mb-2"><h5 class="mb-0">Terminal del colector</h5><a class="btn btn-sm btn-ghost" href="fuentes.php#terminal">Actualizar</a></div>
<div class="small-muted mb-2">Últimas 40 líneas, la más reciente abajo. Archivo completo: <code>storage/collector.log</code></div>
<pre class="term" id="terminal"><?php if($tail): foreach($tail as $l): $cls=str_contains($l,'>>> ALERTA')?'t-alert':(str_contains($l,'RECHAZADO')||str_contains($l,'ERROR')||str_contains($l,'Error')?'t-err':''); ?><span class="<?= $cls ?>"><?= esc($l) ?></span>
<?php endforeach; else: ?><span class="t-dim">Sin registros todavía.</span><?php endif; ?></pre></div>

<div class="row g-3 mb-3">
<?php foreach($items as $s): $online=$s['last_seen_at'] && strtotime($s['last_seen_at'])>=time()-300; ?>
<div class="col-lg-6"><div class="panel h-100">
 <div class="d-flex justify-content-between"><div><h5 class="mb-1"><span class="source-dot <?= $online?'online':'' ?>"></span><?= esc($s['name']) ?></h5><div class="small text-secondary"><?= esc($s['source_key']) ?> · <?= esc($s['source_type']) ?></div></div><span class="badge <?= $s['active']?'text-bg-success':'text-bg-secondary' ?>"><?= $s['active']?'ACTIVA':'DESACTIVADA' ?></span></div>
 <div class="row g-3 mt-2 small"><div class="col-4"><span class="text-secondary">Estado</span><br><strong><?= $online?'En línea':'Sin eventos recientes' ?></strong></div><div class="col-4"><span class="text-secondary">Eventos hoy</span><br><strong><?= (int)$s['events_today'] ?></strong></div><div class="col-4"><span class="text-secondary">Alertas hoy</span><br><strong><?= (int)$s['alerts_today'] ?></strong></div><div class="col-6"><span class="text-secondary">IP esperada</span><br><?= esc($s['expected_ip']?:'No restringida') ?></div><div class="col-6"><span class="text-secondary">Último evento</span><br><?= esc($s['last_seen_at']?:'Nunca') ?></div></div>
 <?php if($isAdmin): ?><div class="d-flex gap-2 mt-3"><form method="post"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="action" value="toggle"><input type="hidden" name="id" value="<?= (int)$s['id'] ?>"><input type="hidden" name="active" value="<?= $s['active']?0:1 ?>"><button class="btn btn-sm btn-outline-<?= $s['active']?'secondary':'success' ?>"><?= $s['active']?'Desactivar':'Activar' ?></button></form><form method="post" data-confirm="La clave anterior dejará de funcionar. ¿Continuar?"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="action" value="regenerate"><input type="hidden" name="id" value="<?= (int)$s['id'] ?>"><button class="btn btn-sm btn-outline-warning">Regenerar API Key</button></form></div><?php endif; ?>
</div></div><?php endforeach; ?>
</div>

<?php if($isAdmin): ?><div class="panel"><h5>Nueva fuente</h5><form method="post" class="row g-3"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="action" value="create"><div class="col-md-3"><label class="form-label">Identificador</label><input class="form-control" name="source_key" placeholder="WEB-SERVER-02" required></div><div class="col-md-3"><label class="form-label">Nombre</label><input class="form-control" name="name" placeholder="Portal monitorizado" required></div><div class="col-md-2"><label class="form-label">Tipo</label><input class="form-control" name="source_type" value="Aplicación Web"></div><div class="col-md-2"><label class="form-label">IP esperada</label><input class="form-control" name="expected_ip" placeholder="192.168.1.10"></div><div class="col-md-2"><label class="form-label">API Key</label><input class="form-control" name="api_key" placeholder="Vacío = automática"></div><div class="col-12"><button class="btn btn-cyber">Crear fuente</button></div></form></div><?php endif; ?>
<?php require __DIR__.'/includes/footer.php'; ?>
