-- =====================================================================
-- SecureWatch SIEM — Actualización para el laboratorio real (v2)
-- Ejecutar UNA vez en phpMyAdmin (pestaña Importar) con el usuario root.
-- Es seguro volver a ejecutarlo: no borra eventos ni alertas.
-- =====================================================================
USE securewatch_siem;

-- 1. Eventos: marca real/simulado, hora informada por la fuente y sello de integridad
ALTER TABLE events
  ADD COLUMN IF NOT EXISTS is_simulation TINYINT(1) NOT NULL DEFAULT 0 AFTER severity,
  ADD COLUMN IF NOT EXISTS reported_at DATETIME NULL AFTER created_at,
  ADD COLUMN IF NOT EXISTS prev_hash CHAR(64) NULL,
  ADD COLUMN IF NOT EXISTS integrity_hash CHAR(64) NULL;
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_sim_created(is_simulation, created_at);

-- Eventos generados antes por el simulador quedan marcados como simulados
UPDATE events SET is_simulation=1
 WHERE source_key='SECUREWATCH-LAB' OR JSON_VALUE(metadata,'$.simulation')='true';

-- 2. Fuentes reales del laboratorio
--    MIKROTIK-RB2011: solo se aceptan mensajes Syslog desde 192.168.88.1
--    WEB-PORTAL: el portal corre en la misma PC, por eso la IP esperada es 127.0.0.1
INSERT INTO sources(source_key,name,source_type,expected_ip,api_key_hash,active) VALUES
 ('MIKROTIK-RB2011','MikroTik RB2011iLS-IN (Syslog)','Router / Firewall','192.168.88.1','6aba1a912d97db5010442aa62b47580e533632fdf898d1b769bbecfe7a462581',1),
 ('WEB-PORTAL','Portal web Ferretería La Montaña','Aplicación Web','127.0.0.1','8d27e65454a8ba571ca650de990bbd4b6a4f1c32be5b5ec4391e2df6f01ba447',1)
ON DUPLICATE KEY UPDATE name=VALUES(name), source_type=VALUES(source_type), expected_ip=VALUES(expected_ip), active=1;

-- La fuente de demostración tiene su API Key publicada en el README: se desactiva
UPDATE sources SET active=0 WHERE source_key='WEB-SERVER-01';

-- 3. Reglas nuevas
INSERT INTO rules(rule_key,name,description,severity,threshold_value,window_minutes,risk_score) VALUES
 ('PORT_SCAN','Escaneo de puertos','Una misma IP intenta conectarse a muchos puertos distintos del router en poco tiempo (firewall MikroTik).','high',10,2,80),
 ('API_AUTH_FAILURE','Envío de eventos no autorizado','Intentos repetidos de enviar eventos con API Key inválida o desde una IP no permitida.','high',3,5,75)
ON DUPLICATE KEY UPDATE description=VALUES(description);

UPDATE rules SET description='Cambio de rol, permisos, contraseñas, configuración del router u otra acción administrativa relevante.'
 WHERE rule_key='SENSITIVE_ADMIN';

-- 4. Usuario propio de la aplicación (en lugar de root sin contraseña)
--    Antes de importar, cambie CAMBIE_ESTA_CLAVE por una clave propia y póngala
--    también en config/database.php (DB_PASS).
--    Permisos mínimos: puede leer, insertar y actualizar, pero NO borrar.
CREATE USER IF NOT EXISTS 'securewatch_app'@'localhost' IDENTIFIED BY 'CAMBIE_ESTA_CLAVE';
CREATE USER IF NOT EXISTS 'securewatch_app'@'127.0.0.1' IDENTIFIED BY 'CAMBIE_ESTA_CLAVE';
GRANT SELECT, INSERT, UPDATE ON securewatch_siem.* TO 'securewatch_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON securewatch_siem.* TO 'securewatch_app'@'127.0.0.1';
FLUSH PRIVILEGES;
