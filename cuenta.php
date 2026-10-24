<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_login();
require_once __DIR__.'/includes/functions.php';
$pdo=db(); $title='Mi cuenta'; $msg=''; $ok=false; $u=current_user();

if($_SERVER['REQUEST_METHOD']==='POST'){
    verify_csrf();
    $current=(string)($_POST['current']??'');
    $new=(string)($_POST['new']??'');
    $confirm=(string)($_POST['confirm']??'');
    $row=$pdo->prepare('SELECT password_hash FROM users WHERE id=?');$row->execute([(int)$u['id']]);$hash=(string)$row->fetchColumn();
    if(!password_verify($current,$hash)){
        $msg='La contraseña actual no es correcta.';
        log_event($pdo,'PASSWORD_CHANGE_FAILED','Intento de cambio de contraseña con clave actual incorrecta','FAILED','medium',(int)$u['id'],$u['username']);
    }elseif($new!==$confirm){
        $msg='La nueva contraseña y su confirmación no coinciden.';
    }elseif(strlen($new)<10 || !preg_match('/[A-Za-z]/',$new) || !preg_match('/\d/',$new)){
        $msg='La nueva contraseña debe tener al menos 10 caracteres, con letras y números.';
    }elseif(password_verify($new,$hash) || $new==='Admin123!'){
        $msg='La nueva contraseña debe ser distinta de la anterior y de la contraseña de demostración.';
    }else{
        $pdo->prepare('UPDATE users SET password_hash=? WHERE id=?')->execute([password_hash($new,PASSWORD_DEFAULT),(int)$u['id']]);
        session_regenerate_id(true);
        $_SESSION['weak_password']=false;
        log_event($pdo,'PASSWORD_CHANGE','Cambio de contraseña propia','SUCCESS','low',(int)$u['id'],$u['username']);
        $msg='Contraseña actualizada correctamente.';$ok=true;
    }
}
require __DIR__.'/includes/header.php'; ?>
<div class="page-head"><div><h2>Mi cuenta</h2><p><?= esc($u['full_name']) ?> · <?= esc($u['username']) ?> · <?= esc($u['role']) ?></p></div></div>
<?php if($msg): ?><div class="alert alert-<?= $ok?'success':'danger' ?>"><?= esc($msg) ?></div><?php endif; ?>
<div class="row"><div class="col-lg-5"><div class="panel"><h5>Cambiar contraseña</h5>
<form method="post"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
<label class="form-label">Contraseña actual</label><input class="form-control mb-2" type="password" name="current" autocomplete="current-password" required>
<label class="form-label">Nueva contraseña</label><input class="form-control mb-2" type="password" name="new" minlength="10" autocomplete="new-password" required>
<label class="form-label">Confirmar nueva contraseña</label><input class="form-control mb-3" type="password" name="confirm" minlength="10" autocomplete="new-password" required>
<div class="small-muted mb-3">Mínimo 10 caracteres, con letras y números.</div>
<button class="btn btn-cyber w-100">Guardar</button></form></div></div></div>
<?php require __DIR__.'/includes/footer.php'; ?>
