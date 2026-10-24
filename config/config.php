<?php
declare(strict_types=1);

const APP_NAME = 'SecureWatch SIEM';
const APP_TIMEZONE = 'America/Guatemala';

date_default_timezone_set(APP_TIMEZONE);

const SESSION_IDLE_SECONDS = 1800; // 30 minutos de inactividad

if (PHP_SAPI !== 'cli' && session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params([
        'httponly' => true,
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'samesite' => 'Lax',
    ]);
    session_start();
}
