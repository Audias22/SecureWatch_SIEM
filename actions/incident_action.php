<?php
declare(strict_types=1);
require_once __DIR__.'/../includes/auth.php';
require_once __DIR__.'/../includes/functions.php';
require_role(['admin','analyst']);
verify_csrf();

$pdo=db();
$incidentId=(int)($_POST['incident_id']??0);
$action=(string)($_POST['action']??'update');
$stmt=$pdo->prepare('SELECT * FROM incidents WHERE id=?');
$stmt->execute([$incidentId]);
$inc=$stmt->fetch();
if(!$inc){ header('Location: ../incidentes.php'); exit; }
$userId=(int)current_user()['id'];

if($action==='add_note'){
    $note=trim((string)($_POST['note']??''));
    if($note!==''){
        $pdo->prepare('INSERT INTO incident_notes(incident_id,user_id,note) VALUES(?,?,?)')->execute([$incidentId,$userId,mb_substr($note,0,5000)]);
        incident_history($pdo,$incidentId,$userId,'note_added',$inc['status'],$inc['status'],'Se agregó una nota de investigación.');
    }
    header('Location: ../incidente_detalle.php?id='.$incidentId); exit;
}

$allowed=['open','investigating','contained','resolved','closed'];
$newStatus=(string)($_POST['status']??$inc['status']);
if(!in_array($newStatus,$allowed,true)) $newStatus=$inc['status'];
$assignedRaw=(string)($_POST['assigned_to']??'');
$assignedTo=$assignedRaw===''?null:(int)$assignedRaw;
$resolution=trim((string)($_POST['resolution']??$inc['resolution']??''));

if($assignedTo!==null){
    $check=$pdo->prepare("SELECT id FROM users WHERE id=? AND active=1 AND role IN ('admin','analyst')");
    $check->execute([$assignedTo]);
    if(!$check->fetchColumn()) $assignedTo=null;
}

$sets=['status=?','assigned_to=?','resolution=?'];
$params=[$newStatus,$assignedTo,$resolution!==''?$resolution:null];
if($newStatus==='contained' && empty($inc['contained_at'])) $sets[]='contained_at=NOW()';
if($newStatus==='resolved' && empty($inc['resolved_at'])) $sets[]='resolved_at=NOW()';
if($newStatus==='closed' && empty($inc['closed_at'])) $sets[]='closed_at=NOW()';
if(in_array($newStatus,['open','investigating'],true)){
    // No borramos marcas históricas anteriores; solo cambia el estado actual.
}
$params[]=$incidentId;
$pdo->prepare('UPDATE incidents SET '.implode(',',$sets).' WHERE id=?')->execute($params);

$details=[];
if((string)$inc['status']!==$newStatus) $details[]='Estado: '.human_status((string)$inc['status']).' → '.human_status($newStatus);
if((string)($inc['assigned_to']??'')!==(string)($assignedTo??'')) $details[]='Analista asignado actualizado';
if($resolution!==trim((string)($inc['resolution']??''))) $details[]='Resolución actualizada';
incident_history($pdo,$incidentId,$userId,'updated',(string)$inc['status'],$newStatus,$details?implode(' · ',$details):'Incidente actualizado');

if($inc['alert_id']){
    if(in_array($newStatus,['resolved','closed'],true)){
        $pdo->prepare("UPDATE alerts SET status='resolved', resolved_at=COALESCE(resolved_at,NOW()) WHERE id=?")->execute([(int)$inc['alert_id']]);
    } elseif(in_array($newStatus,['investigating','contained'],true)){
        $pdo->prepare("UPDATE alerts SET status='investigating' WHERE id=?")->execute([(int)$inc['alert_id']]);
    }
}
header('Location: ../incidente_detalle.php?id='.$incidentId); exit;
