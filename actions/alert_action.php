<?php
declare(strict_types=1);
require_once __DIR__.'/../includes/auth.php';
require_once __DIR__.'/../includes/functions.php';
require_role(['admin','analyst']);
verify_csrf();

$pdo = db();
$id = (int)($_POST['alert_id'] ?? 0);
$action = (string)($_POST['action'] ?? '');
$stmt = $pdo->prepare('SELECT a.*, r.name rule_name FROM alerts a JOIN rules r ON r.id=a.rule_id WHERE a.id=?');
$stmt->execute([$id]);
$a = $stmt->fetch();
if (!$a) { header('Location: ../alertas.php'); exit; }

if ($action === 'investigate') {
    $pdo->prepare("UPDATE alerts SET status='investigating' WHERE id=? AND status='new'")->execute([$id]);
}

if ($action === 'resolve') {
    $pdo->prepare("UPDATE alerts SET status='resolved', resolved_at=NOW() WHERE id=?")->execute([$id]);
}

if ($action === 'false_positive') {
    $pdo->prepare("UPDATE alerts SET status='false_positive', resolved_at=NOW() WHERE id=?")->execute([$id]);
}

if ($action === 'incident') {
    $check = $pdo->prepare('SELECT id FROM incidents WHERE alert_id=? LIMIT 1');
    $check->execute([$id]);
    $incidentId = (int)($check->fetchColumn() ?: 0);
    if ($incidentId === 0) {
        $pdo->prepare('INSERT INTO incidents(alert_id,title,description,severity,status,created_by) VALUES(?,?,?,?,\'open\',?)')
            ->execute([$id,'Incidente: '.$a['title'],'Generado desde la alerta #'.$id.' / Regla: '.$a['rule_name'],$a['severity'],(int)current_user()['id']]);
        $incidentId = (int)$pdo->lastInsertId();
        incident_history($pdo,$incidentId,(int)current_user()['id'],'created',null,'open','Incidente creado desde alerta #'.$id);
    }
    $pdo->prepare("UPDATE alerts SET status='investigating' WHERE id=?")->execute([$id]);
    header('Location: ../incidente_detalle.php?id='.$incidentId);
    exit;
}

header('Location: ../alertas.php');
