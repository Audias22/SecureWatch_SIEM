<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_role(['admin']);
require_once __DIR__.'/includes/functions.php';
$pdo=db(); $title='Reglas SIEM';
if($_SERVER['REQUEST_METHOD']==='POST'){
 verify_csrf();$id=(int)($_POST['id']??0);$threshold=max(1,(int)($_POST['threshold']??1));$window=max(1,(int)($_POST['window']??5));$risk=max(0,min(100,(int)($_POST['risk']??50)));$enabled=isset($_POST['enabled'])?1:0;
 $old=$pdo->prepare('SELECT * FROM rules WHERE id=?');$old->execute([$id]);$old=$old->fetch();
 if($old){
  $pdo->prepare('UPDATE rules SET threshold_value=?,window_minutes=?,risk_score=?,enabled=? WHERE id=?')->execute([$threshold,$window,$risk,$enabled,$id]);
  $chg=[];
  if((int)$old['threshold_value']!==$threshold)$chg[]='umbral '.$old['threshold_value'].'→'.$threshold;
  if((int)$old['window_minutes']!==$window)$chg[]='ventana '.$old['window_minutes'].'→'.$window;
  if((int)$old['risk_score']!==$risk)$chg[]='risk '.$old['risk_score'].'→'.$risk;
  if((int)$old['enabled']!==$enabled)$chg[]=$enabled?'activada':'DESACTIVADA';
  if($chg)log_event($pdo,'ADMIN_ACTION','Modificación de regla '.$old['rule_key'].': '.implode(', ',$chg),'SUCCESS','medium',(int)current_user()['id'],current_user()['username']);
 }
 header('Location: reglas.php');exit;
}
$rules=$pdo->query('SELECT r.*,(SELECT COUNT(*) FROM alerts a WHERE a.rule_id=r.id) alert_count FROM rules r ORDER BY FIELD(r.severity,\'critical\',\'high\',\'medium\',\'low\'),r.id')->fetchAll();require __DIR__.'/includes/header.php'; ?>
<div class="page-head"><div><h2>Reglas de correlación</h2><p>Diez reglas defensivas para autenticación, ataques web, administración y extracción de datos.</p></div></div>
<div class="row g-3"><?php foreach($rules as $r): ?><div class="col-xl-6"><div class="panel h-100"><div class="d-flex justify-content-between gap-2"><div><div class="small-muted"><?= esc($r['rule_key']) ?></div><h5 class="mb-1"><?= esc($r['name']) ?></h5></div><span class="badge text-bg-<?= severity_badge($r['severity']) ?> align-self-start"><?= strtoupper($r['severity']) ?></span></div><p class="text-secondary small mt-2"><?= esc($r['description']) ?></p><div class="small mb-3">Alertas históricas: <strong><?= (int)$r['alert_count'] ?></strong></div><form method="post" class="row g-2 align-items-end"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="id" value="<?= (int)$r['id'] ?>"><div class="col-3"><label class="form-label small"><?= $r['rule_key']==='NIGHT_LOGIN'?'Hora límite':'Umbral' ?></label><input class="form-control" type="number" min="1" name="threshold" value="<?= (int)$r['threshold_value'] ?>"></div><div class="col-3"><label class="form-label small">Ventana min.</label><input class="form-control" type="number" min="1" name="window" value="<?= (int)$r['window_minutes'] ?>"></div><div class="col-2"><label class="form-label small">Risk</label><input class="form-control" type="number" min="0" max="100" name="risk" value="<?= (int)$r['risk_score'] ?>"></div><div class="col-2 form-check mb-2"><input class="form-check-input" type="checkbox" name="enabled" id="e<?= $r['id'] ?>" <?= $r['enabled']?'checked':'' ?>><label class="form-check-label" for="e<?= $r['id'] ?>">Activa</label></div><div class="col-2"><button class="btn btn-cyber w-100">Guardar</button></div></form></div></div><?php endforeach; ?></div>
<?php require __DIR__.'/includes/footer.php'; ?>
