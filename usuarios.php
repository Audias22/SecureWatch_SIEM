<?php
declare(strict_types=1);
require_once __DIR__.'/includes/auth.php'; require_role(['admin']);
require_once __DIR__.'/includes/functions.php';
$pdo=db();$title='Usuarios';$msg='';
if($_SERVER['REQUEST_METHOD']==='POST'){
 verify_csrf();$action=(string)($_POST['action']??'create');
 if($action==='create'){
   $username=trim((string)($_POST['username']??''));$name=trim((string)($_POST['full_name']??''));$email=trim((string)($_POST['email']??''))?:null;$password=(string)($_POST['password']??'');$role=(string)($_POST['role']??'auditor');
   if(!in_array($role,['admin','analyst','auditor'],true))$role='auditor';
   if(strlen($username)>=3&&strlen($password)>=8&&$name!==''){
    try{$pdo->prepare('INSERT INTO users(username,full_name,email,password_hash,role) VALUES(?,?,?,?,?)')->execute([$username,$name,$email,password_hash($password,PASSWORD_DEFAULT),$role]);$msg='Usuario creado.';log_event($pdo,'ADMIN_ACTION','Creación de usuario '.$username,'SUCCESS','medium',(int)current_user()['id'],current_user()['username']);}catch(PDOException $e){$msg='No se pudo crear el usuario. Revisa que no esté repetido.';}
   }else{$msg='Usuario, nombre o contraseña no cumplen los requisitos.';}
 }
 if($action==='update'){
   $id=(int)($_POST['id']??0);$role=(string)($_POST['role']??'auditor');$active=isset($_POST['active'])?1:0;
   if(!in_array($role,['admin','analyst','auditor'],true))$role='auditor';
   if($id===(int)current_user()['id']&&$active===0){$msg='No puedes desactivar tu propia cuenta.';}
   else{
    $old=$pdo->prepare('SELECT username,role,active FROM users WHERE id=?');$old->execute([$id]);$old=$old->fetch();
    if($old){$pdo->prepare('UPDATE users SET role=?,active=? WHERE id=?')->execute([$role,$active,$id]);if($old['role']!==$role)log_event($pdo,'ROLE_CHANGED','Cambio de rol de '.$old['username'].' a '.$role,'SUCCESS','medium',(int)current_user()['id'],current_user()['username']);else log_event($pdo,'ADMIN_ACTION','Actualización de estado de '.$old['username'],'SUCCESS','medium',(int)current_user()['id'],current_user()['username']);$msg='Usuario actualizado.';}
   }
 }
 if($action==='password'){
   $id=(int)($_POST['id']??0);$password=(string)($_POST['password']??'');
   if(strlen($password)>=8){$t=$pdo->prepare('SELECT username FROM users WHERE id=?');$t->execute([$id]);$target=$t->fetchColumn();if($target){$pdo->prepare('UPDATE users SET password_hash=? WHERE id=?')->execute([password_hash($password,PASSWORD_DEFAULT),$id]);log_event($pdo,'PASSWORD_RESET','Restablecimiento de contraseña del usuario '.$target,'SUCCESS','medium',(int)current_user()['id'],current_user()['username']);$msg='Contraseña restablecida.';}}
 }
}
$users=$pdo->query('SELECT id,username,full_name,email,role,active,last_login_at,created_at FROM users ORDER BY id')->fetchAll();require __DIR__.'/includes/header.php'; ?>
<div class="page-head"><div><h2>Usuarios y roles</h2><p>Control de acceso basado en roles: administrador, analista y auditor.</p></div></div>
<?php if($msg): ?><div class="alert alert-info"><?= esc($msg) ?></div><?php endif; ?>
<div class="row g-3"><div class="col-xl-4"><div class="panel"><h5>Nuevo usuario</h5><form method="post"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="action" value="create"><label class="form-label">Usuario</label><input class="form-control mb-2" name="username" required><label class="form-label">Nombre</label><input class="form-control mb-2" name="full_name" required><label class="form-label">Correo</label><input class="form-control mb-2" name="email" type="email"><label class="form-label">Contraseña</label><input class="form-control mb-2" type="password" name="password" minlength="8" required><label class="form-label">Rol</label><select class="form-select mb-3" name="role"><option value="analyst">Analista</option><option value="auditor">Auditor</option><option value="admin">Administrador</option></select><button class="btn btn-cyber w-100">Crear usuario</button></form></div></div>
<div class="col-xl-8"><div class="panel"><div class="table-responsive"><table class="table cyber-table"><thead><tr><th>Usuario</th><th>Nombre</th><th>Rol / estado</th><th>Último acceso</th><th>Acciones</th></tr></thead><tbody><?php foreach($users as $u): ?><tr><td><?= esc($u['username']) ?></td><td><?= esc($u['full_name']) ?><div class="small text-secondary"><?= esc($u['email']) ?></div></td><td><form method="post" class="d-flex gap-2 align-items-center flex-wrap"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="action" value="update"><input type="hidden" name="id" value="<?= (int)$u['id'] ?>"><select class="form-select form-select-sm" name="role" style="width:130px"><option value="admin" <?= $u['role']==='admin'?'selected':'' ?>>Admin</option><option value="analyst" <?= $u['role']==='analyst'?'selected':'' ?>>Analista</option><option value="auditor" <?= $u['role']==='auditor'?'selected':'' ?>>Auditor</option></select><label class="form-check small"><input class="form-check-input" type="checkbox" name="active" <?= $u['active']?'checked':'' ?>> Activo</label><button class="btn btn-sm btn-outline-info">Guardar</button></form></td><td><?= esc($u['last_login_at']?:'Nunca') ?></td><td><form method="post" class="d-flex gap-1"><input type="hidden" name="csrf_token" value="<?= csrf_token() ?>"><input type="hidden" name="action" value="password"><input type="hidden" name="id" value="<?= (int)$u['id'] ?>"><input class="form-control form-control-sm" type="password" name="password" minlength="8" placeholder="Nueva contraseña" style="width:155px" required><button class="btn btn-sm btn-outline-warning">Restablecer</button></form></td></tr><?php endforeach; ?></tbody></table></div></div></div></div>
<?php require __DIR__.'/includes/footer.php'; ?>
