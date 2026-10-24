<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

const DB_HOST = '127.0.0.1';
const DB_PORT = '3307';
const DB_NAME = 'securewatch_siem';
// Usuario propio con permisos mínimos (SELECT, INSERT, UPDATE). Ver database/laboratorio_v2.sql
const DB_USER = 'securewatch_app';
const DB_PASS = 'CAMBIE_ESTA_CLAVE';

function db(bool $reconnect = false): PDO
{
    static $pdo = null;
    if ($reconnect) $pdo = null;   // usado por el colector Syslog si se pierde la conexión
    if ($pdo instanceof PDO) return $pdo;

    $dsn = 'mysql:host=' . DB_HOST . ';port=' . DB_PORT . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    $pdo->exec("SET time_zone = '" . (new DateTime('now', new DateTimeZone(APP_TIMEZONE)))->format('P') . "'");
    return $pdo;
}
