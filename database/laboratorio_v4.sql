-- =====================================================================
-- SecureWatch SIEM — v4
--  * Técnicas MITRE ATT&CK en cada regla
--  * Regla de correlación entre fuentes (ataque en varias etapas)
--  * Tabla de IP bloqueadas (respuesta en el MikroTik y en el portal)
-- Ejecutar UNA vez en phpMyAdmin (pestaña SQL). Es seguro repetirlo.
-- =====================================================================
USE securewatch_siem;
SET NAMES utf8mb4;

ALTER TABLE rules
  ADD COLUMN IF NOT EXISTS mitre_id VARCHAR(20) NULL AFTER risk_score,
  ADD COLUMN IF NOT EXISTS mitre_name VARCHAR(120) NULL AFTER mitre_id,
  ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(80) NULL AFTER mitre_name;

INSERT INTO rules(rule_key,name,description,severity,threshold_value,window_minutes,risk_score) VALUES
 ('MULTI_STAGE','Ataque en varias etapas','La misma IP genera alertas en distintas fuentes (por ejemplo, escaneo en el router y ataque al portal). El umbral es el número de fuentes.','critical',2,60,98)
ON DUPLICATE KEY UPDATE description=VALUES(description);

UPDATE rules SET mitre_id='T1110.001', mitre_name='Brute Force: Password Guessing',  mitre_tactic='Acceso a credenciales' WHERE rule_key='BRUTE_FORCE';
UPDATE rules SET mitre_id='T1110.003', mitre_name='Brute Force: Password Spraying',  mitre_tactic='Acceso a credenciales' WHERE rule_key='PASSWORD_SPRAY';
UPDATE rules SET mitre_id='T1110',     mitre_name='Brute Force',                     mitre_tactic='Acceso a credenciales' WHERE rule_key IN ('API_AUTH_FAILURE','RESET_ABUSE');
UPDATE rules SET mitre_id='T1078',     mitre_name='Valid Accounts',                  mitre_tactic='Escalada de privilegios' WHERE rule_key='ACCESS_DENIED';
UPDATE rules SET mitre_id='T1078',     mitre_name='Valid Accounts',                  mitre_tactic='Acceso inicial' WHERE rule_key='NIGHT_LOGIN';
UPDATE rules SET mitre_id='T1059.007', mitre_name='Command and Scripting Interpreter: JavaScript', mitre_tactic='Ejecución' WHERE rule_key='XSS_ATTEMPT';
UPDATE rules SET mitre_id='T1190',     mitre_name='Exploit Public-Facing Application', mitre_tactic='Acceso inicial' WHERE rule_key='SQL_INJECTION';
UPDATE rules SET mitre_id='T1083',     mitre_name='File and Directory Discovery',    mitre_tactic='Descubrimiento' WHERE rule_key='PATH_TRAVERSAL';
UPDATE rules SET mitre_id='T1595.003', mitre_name='Active Scanning: Wordlist Scanning', mitre_tactic='Reconocimiento' WHERE rule_key='ROUTE_SCAN';
UPDATE rules SET mitre_id='T1046',     mitre_name='Network Service Discovery',       mitre_tactic='Descubrimiento' WHERE rule_key='PORT_SCAN';
UPDATE rules SET mitre_id='T1098',     mitre_name='Account Manipulation',            mitre_tactic='Persistencia' WHERE rule_key='SENSITIVE_ADMIN';
UPDATE rules SET mitre_id='T1213',     mitre_name='Data from Information Repositories', mitre_tactic='Recolección' WHERE rule_key='MASS_DOWNLOAD';
UPDATE rules SET mitre_id='T1565.001', mitre_name='Data Manipulation: Stored Data Manipulation', mitre_tactic='Impacto'
 WHERE rule_key IN ('PRICE_MANIPULATION','PRICE_DROP_SALE','VOID_ABUSE','NEGATIVE_ADJUSTMENT');
UPDATE rules SET mitre_id=NULL, mitre_name='Correlación de varias técnicas', mitre_tactic='Varias tácticas' WHERE rule_key='MULTI_STAGE';

CREATE TABLE IF NOT EXISTS ip_blocks (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip_address VARCHAR(45) NOT NULL,
  reason VARCHAR(255) NOT NULL,
  alert_id INT UNSIGNED NULL,
  created_by INT UNSIGNED NULL,
  created_at DATETIME NOT NULL,
  expires_at DATETIME NULL,
  active TINYINT(1) NOT NULL DEFAULT 1,
  removed_by INT UNSIGNED NULL,
  removed_at DATETIME NULL,
  INDEX idx_blocks_active (active, ip_address)
) ENGINE=InnoDB;
