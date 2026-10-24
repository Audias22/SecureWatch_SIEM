<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_login();
require_once __DIR__.'/includes/functions.php';
$pdo=db(); $title='Bloqueo de IP'; $u=current_user();
$canAct=in_array($u['role'],['admin','analyst'],true); $isAdmin=$u['role']==='admin';
$routerScript=$_SESSION['router_script']??null; unset($_SESSION['router_script']);

if($_SERVER['REQUEST_METHOD']==='POST' && $canAct){
    verify_csrf();
    $action=(string)($_POST['action']??'');
    $back=(string)($_POST['back']??'bloqueos.php');
    if(!preg_match('/^(bloqueos|alerta)\.php(\?id=\d+)?$/',$back)) $back='bloqueos.php';
    if($action==='block'){
        $hours=(int)($_POST['hours']??24); $hours=in_array($hours,[1,24,168],true)?$hours:null;
        $alertId=(int)($_POST['alert_id']??0)?:null;
        [$ok,$m]=block_ip($pdo,(string)($_POST['ip']??''),(string)($_POST['reason']??''),$hours,$alertId,$u);
        $_SESSION['flash']=[$ok?'success':'danger',$m];
    }
    if($action==='unblock'){
        $ip=unblock_ip($pdo,(int)($_POST['id']??0),$u);
        $_SESSION['flash']=$ip?['success',"IP $ip desbloqueada. El router la quita de la lista en menos de un minuto."]:['warning','Ese bloqueo ya no está activo.'];
    }
    if($action==='router_script' && $isAdmin){
        // Nueva clave para el router: el colector Syslog no la usa, así que rotarla no afecta la recepción de logs.
        $plain='SW-'.bin2hex(random_bytes(16));
        $pdo->prepare("UPDATE sources SET api_key_hash=? WHERE source_key='MIKROTIK-RB2011'")->execute([hash('sha256',$plain)]);
        log_event($pdo,'ADMIN_ACTION','Rotación de API Key de MIKROTIK-RB2011 para la lista de bloqueo','SUCCESS','medium',(int)$u['id'],$u['username']);
        $_SESSION['router_script']=$plain;
    }
    header('Location: '.$back); exit;
}
$flash=$_SESSION['flash']??null; unset($_SESSION['flash']);
$active=active_blocks($pdo);
$history=$pdo->query("SELECT b.*, u.username created_by_name, r.username removed_by_name FROM ip_blocks b
  LEFT JOIN users u ON u.id=b.created_by LEFT JOIN users r ON r.id=b.removed_by WHERE b.active=0 ORDER BY b.id DESC LIMIT 30")->fetchAll();
$pulls=blocklist_pulls();
$suggest=$pdo->query("SELECT e.ip_address, COUNT(DISTINCT a.id) alerts, MAX(a.severity='critical') has_critical, MAX(a.created_at) last_at
  FROM alerts a JOIN events e ON e.id=a.event_id
  WHERE a.created_at >= NOW() - INTERVAL 1 DAY AND a.status IN ('new','investigating') AND e.ip_address NOT IN ('127.0.0.1','::1','192.168.88.1','192.168.88.254')
    AND e.ip_address NOT IN (SELECT ip_address FROM ip_blocks WHERE active=1)
  GROUP BY e.ip_address ORDER BY has_critical DESC, alerts DESC LIMIT 5")->fetchAll();
$host=$_SERVER['HTTP_HOST']??'192.168.88.254';
if(in_array(strtolower(preg_replace('/:\d+$/','',$host)),['127.0.0.1','localhost'],true)) $host='192.168.88.254';
$base=rtrim(dirname($_SERVER['SCRIPT_NAME']??'/SecureWatch_SIEM/bloqueos.php'),'/\\');
$listUrl='http://'.$host.$base.'/api/blocklist.php';
function pull_age(?array $p): string { if(!$p) return 'Nunca'; $s=time()-strtotime($p['at']); return $s<90?"hace $s s":($s<5400?'hace '.round($s/60).' min':esc($p['at'])); }
require __DIR__.'/includes/header.php'; ?>
<div class="page-head"><div><h2>Bloqueo de IP</h2><p>Respuesta activa: una IP bloqueada aquí queda sin acceso al router y al portal. El MikroTik y el portal consultan esta lista cada minuto.</p></div></div>
<?php if($flash): ?><div class="alert alert-<?= esc($flash[0]) ?>"><?= esc($flash[1]) ?></div><?php endif; ?>

<div class="row g-3 mb-3">
 <div class="col-md-4"><div class="panel h-100"><div class="small-muted mb-1">BLOQUEOS ACTIVOS</div><div class="metric-value"><?= count($active) ?></div><div class="small text-secondary">Máximo <?= BLOCK_MAX_ACTIVE ?></div></div></div>
 <?php $mk=$pulls['MIKROTIK-RB2011']??null; $ok=$mk && time()-strtotime($mk['at'])<180; ?>
 <div class="col-md-4"><div class="panel h-100"><div class="small-muted mb-1">MIKROTIK</div><div class="status-line <?= $ok?'on':'' ?>"><i></i><?= $ok?'Sincronizado':'Sin sincronizar' ?></div><div class="small text-secondary mt-1">Última consulta: <?= pull_age($mk) ?></div></div></div>
 <?php $wp=$pulls['WEB-PORTAL']??null; $ok=$wp && time()-strtotime($wp['at'])<300; ?>
 <div class="col-md-4"><div class="panel h-100"><div class="small-muted mb-1">PORTAL WEB</div><div class="status-line <?= $ok?'on':'' ?>"><i></i><?= $ok?'Sincronizado':'Sin consultas recientes' ?></div><div class="small text-secondary mt-1">Última consulta: <?= pull_age($wp) ?></div></div></div>
</div>

<?php if($canAct): ?>
<div class="row g-3 mb-3">
 <div class="col-lg-7"><div class="panel h-100"><h5>Bloquear una IP</h5>
  <form method="post" class="row g-2"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="action" value="block">
   <div class="col-sm-4"><label class="form-label">IP</label><input class="form-control" name="ip" placeholder="192.168.88.253" required pattern="\d{1,3}(\.\d{1,3}){3}"></div>
   <div class="col-sm-3"><label class="form-label">Duración</label><select class="form-select" name="hours"><option value="1">1 hora</option><option value="24" selected>24 horas</option><option value="168">7 días</option><option value="0">Sin vencimiento</option></select></div>
   <div class="col-sm-5"><label class="form-label">Motivo</label><input class="form-control" name="reason" maxlength="255" placeholder="Escaneo y ataques al portal"></div>
   <div class="col-12"><button class="btn btn-cyber btn-sm">Bloquear</button> <span class="small-muted ms-2">No se pueden bloquear el router, el servidor ni su propio equipo.</span></div>
  </form></div></div>
 <div class="col-lg-5"><div class="panel h-100"><h5>IP con más alertas (24 h)</h5>
  <?php if(!$suggest): ?><p class="small text-secondary mb-0">No hay IP con alertas abiertas en las últimas 24 horas.</p><?php else: ?>
  <table class="table table-sm align-middle mb-0"><tbody><?php foreach($suggest as $s): ?><tr>
   <td><a href="eventos.php?ip=<?= urlencode($s['ip_address']) ?>"><?= esc($s['ip_address']) ?></a><?= $s['has_critical']?' <span class="badge text-bg-danger">CRÍTICA</span>':'' ?></td>
   <td class="small text-secondary"><?= (int)$s['alerts'] ?> alertas</td>
   <td class="text-end"><form method="post"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="action" value="block"><input type="hidden" name="ip" value="<?= esc($s['ip_address']) ?>"><input type="hidden" name="hours" value="24"><input type="hidden" name="reason" value="<?= esc((int)$s['alerts'].' alertas abiertas en 24 h') ?>"><button class="btn btn-sm btn-outline-danger">Bloquear 24 h</button></form></td>
  </tr><?php endforeach; ?></tbody></table><?php endif; ?>
 </div></div>
</div>
<?php endif; ?>

<div class="panel mb-3"><h5>Bloqueos activos</h5>
<?php if(!$active): ?><p class="small text-secondary mb-0">No hay IP bloqueadas.</p><?php else: ?>
<div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr><th>IP</th><th>Motivo</th><th>Alerta</th><th>Bloqueada</th><th>Vence</th><th>Por</th><th></th></tr></thead><tbody>
<?php foreach($active as $b): ?><tr>
 <td><strong><a href="eventos.php?ip=<?= urlencode($b['ip_address']) ?>"><?= esc($b['ip_address']) ?></a></strong></td>
 <td class="small"><?= esc($b['reason']) ?></td>
 <td class="small"><?= $b['alert_id']?'<a href="alerta.php?id='.(int)$b['alert_id'].'">#'.(int)$b['alert_id'].'</a>':'—' ?></td>
 <td class="small"><?= esc($b['created_at']) ?></td>
 <td class="small"><?= esc($b['expires_at']?:'Sin vencimiento') ?></td>
 <td class="small"><?= esc($b['created_by_name']?:'—') ?></td>
 <td class="text-end"><?php if($canAct): ?><form method="post"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="action" value="unblock"><input type="hidden" name="id" value="<?= (int)$b['id'] ?>"><button class="btn btn-sm btn-ghost">Desbloquear</button></form><?php endif; ?></td>
</tr><?php endforeach; ?></tbody></table></div><?php endif; ?>
</div>

<?php if($history): ?><div class="panel mb-3"><h5>Historial</h5><div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr><th>IP</th><th>Motivo</th><th>Bloqueada</th><th>Liberada</th><th>Cómo</th></tr></thead><tbody>
<?php foreach($history as $b): ?><tr><td><?= esc($b['ip_address']) ?></td><td class="small"><?= esc($b['reason']) ?></td><td class="small"><?= esc($b['created_at']) ?> · <?= esc($b['created_by_name']?:'—') ?></td><td class="small"><?= esc((string)$b['removed_at']) ?></td><td class="small"><?= $b['removed_by']?'Desbloqueo manual ('.esc($b['removed_by_name']).')':'Venció' ?></td></tr><?php endforeach; ?>
</tbody></table></div></div><?php endif; ?>

<?php if($isAdmin): ?>
<div class="panel"><h5>Configurar el MikroTik</h5>
<?php if($routerScript): ?>
 <div class="alert alert-warning small mb-2"><strong>Copie estos comandos ahora.</strong> La clave no se vuelve a mostrar. Péguelos en la terminal de WinBox (New Terminal).</div>
<pre class="term" id="router-cmds">/system script add name=securewatch-bloqueos policy=read,write,test source={
:do {
  :local r [/tool fetch url="<?= esc($listUrl) ?>\?source=MIKROTIK-RB2011&key=<?= esc($routerScript) ?>&format=rsc" output=user as-value]
  :if (($r->"status") = "finished") do={ :local f [:parse ($r->"data")]; $f }
} on-error={ :log warning "SecureWatch: no se pudo leer la lista de bloqueo" }
}
/system scheduler add name=securewatch-bloqueos interval=1m on-event=securewatch-bloqueos policy=read,write,test
/ip firewall filter add chain=input src-address-list=<?= BLOCK_LIST_NAME ?> action=drop comment="SecureWatch: IP bloqueada" place-before=0
/ip firewall filter add chain=forward src-address-list=<?= BLOCK_LIST_NAME ?> action=drop comment="SecureWatch: IP bloqueada" place-before=0
/system logging set [find action=remote topics=info] topics=info,!fetch</pre>
 <p class="small-muted mt-2 mb-0">La última línea evita que cada consulta del router llegue al SIEM como evento. Para comprobarlo: <code>/system script run securewatch-bloqueos</code> y luego <code>/ip firewall address-list print</code>.</p>
<?php else: ?>
 <p class="small text-secondary">Genera los comandos para que el router consulte esta lista cada minuto y descarte el tráfico de las IP bloqueadas. Se crea una clave nueva para el router (no afecta al colector Syslog).</p>
 <form method="post" data-confirm="Se generará una clave nueva para el router. Si ya lo había configurado, tendrá que pegar el script otra vez. ¿Continuar?"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="action" value="router_script"><button class="btn btn-sm btn-ghost">Generar comandos para el router</button></form>
<?php endif; ?>
</div>
<?php endif; ?>
<?php require __DIR__.'/includes/footer.php'; ?>
