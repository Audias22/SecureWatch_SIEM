<?php
declare(strict_types=1);
require_once __DIR__ . '/../config/database.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
try {
    db()->query('SELECT 1');
    echo json_encode(['success'=>true,'service'=>'SecureWatch SIEM','status'=>'online','time'=>date(DATE_ATOM)]);
} catch (Throwable $e) {
    http_response_code(503);
    echo json_encode(['success'=>false,'service'=>'SecureWatch SIEM','status'=>'database_unavailable']);
}
