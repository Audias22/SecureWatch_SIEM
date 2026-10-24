USE securewatch_siem;

-- Ejecutar UNA sola vez sobre la base de datos del MVP anterior.
CREATE TABLE sources (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  source_key VARCHAR(80) NOT NULL UNIQUE,
  name VARCHAR(120) NOT NULL,
  source_type VARCHAR(60) NOT NULL DEFAULT 'Aplicación Web',
  expected_ip VARCHAR(45) NULL,
  api_key_hash CHAR(64) NOT NULL,
  active TINYINT(1) NOT NULL DEFAULT 1,
  last_seen_at DATETIME NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

ALTER TABLE rules
  ADD COLUMN window_minutes INT NOT NULL DEFAULT 5 AFTER threshold_value,
  ADD COLUMN risk_score TINYINT UNSIGNED NOT NULL DEFAULT 50 AFTER window_minutes;

ALTER TABLE events
  ADD COLUMN source_id INT UNSIGNED NULL AFTER id,
  ADD COLUMN source_key VARCHAR(80) NOT NULL DEFAULT 'SECUREWATCH-INTERNAL' AFTER source_id,
  ADD COLUMN external_event_id VARCHAR(120) NULL AFTER source_key,
  ADD COLUMN http_method VARCHAR(12) NULL AFTER ip_address,
  ADD COLUMN endpoint VARCHAR(500) NULL AFTER http_method,
  ADD COLUMN request_data TEXT NULL AFTER endpoint,
  ADD INDEX idx_ip_created(ip_address,created_at),
  ADD INDEX idx_source_created(source_key,created_at),
  ADD UNIQUE KEY uq_source_external(source_id,external_event_id),
  ADD CONSTRAINT fk_events_source FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE SET NULL;

ALTER TABLE alerts
  ADD COLUMN source_id INT UNSIGNED NULL AFTER rule_id,
  ADD COLUMN context_key VARCHAR(190) NOT NULL DEFAULT '' AFTER risk_score,
  ADD INDEX idx_alert_context(rule_id,context_key,created_at),
  ADD CONSTRAINT fk_alert_source FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE SET NULL;

CREATE TABLE alert_events (
  alert_id BIGINT UNSIGNED NOT NULL,
  event_id BIGINT UNSIGNED NOT NULL,
  relation_type VARCHAR(30) NOT NULL DEFAULT 'evidence',
  PRIMARY KEY(alert_id,event_id),
  CONSTRAINT fk_ae_alert FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
  CONSTRAINT fk_ae_event FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
) ENGINE=InnoDB;

ALTER TABLE incidents
  ADD COLUMN resolution TEXT NULL AFTER created_by,
  ADD COLUMN contained_at DATETIME NULL AFTER resolution,
  ADD COLUMN resolved_at DATETIME NULL AFTER contained_at,
  ADD COLUMN closed_at DATETIME NULL AFTER resolved_at;

CREATE TABLE incident_notes (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  incident_id BIGINT UNSIGNED NOT NULL,
  user_id INT UNSIGNED NOT NULL,
  note TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_note_inc FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
  CONSTRAINT fk_note_user FOREIGN KEY(user_id) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE TABLE incident_history (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  incident_id BIGINT UNSIGNED NOT NULL,
  user_id INT UNSIGNED NULL,
  action VARCHAR(80) NOT NULL,
  from_status VARCHAR(30) NULL,
  to_status VARCHAR(30) NULL,
  details VARCHAR(255) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_hist_inc FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
  CONSTRAINT fk_hist_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

INSERT INTO sources(source_key,name,source_type,api_key_hash,active) VALUES
('WEB-SERVER-01','Sitio Web Monitorizado','Aplicación Web','6f53adf9ef2371ab555fa12638ad7ca82021b8b8c810cc0d29627ef2190c1349',1);

UPDATE rules SET description='5 intentos fallidos contra el mismo usuario desde la misma IP dentro de la ventana.', severity='critical', threshold_value=5, window_minutes=2, risk_score=90 WHERE rule_key='BRUTE_FORCE';
UPDATE rules SET rule_key='ACCESS_DENIED', name='Acceso no autorizado repetido', description='Varios ACCESS_DENIED desde la misma IP dentro de la ventana.', severity='high', threshold_value=3, window_minutes=5, risk_score=75 WHERE rule_key='UNAUTHORIZED_ADMIN';
UPDATE rules SET description='Inicio de sesión exitoso entre medianoche y la hora indicada por el umbral.', severity='medium', threshold_value=5, window_minutes=5, risk_score=50 WHERE rule_key='NIGHT_LOGIN';
UPDATE rules SET name='Descarga o exportación masiva', description='Muchas descargas o exportaciones desde el mismo origen en poco tiempo.', severity='high', threshold_value=20, window_minutes=15, risk_score=85 WHERE rule_key='MASS_DOWNLOAD';

INSERT INTO rules(rule_key,name,description,severity,threshold_value,window_minutes,risk_score,enabled) VALUES
('PASSWORD_SPRAY','Password spraying','La misma IP intenta autenticarse contra varios usuarios en poco tiempo.','high',3,5,85,1),
('XSS_ATTEMPT','Intento de XSS','Solicitud HTTP con patrones típicos de Cross-Site Scripting.','high',1,5,80,1),
('SQL_INJECTION','Intento de SQL Injection','Solicitud HTTP con patrones típicos de inyección SQL.','critical',1,5,95,1),
('PATH_TRAVERSAL','Intento de Path Traversal','Solicitud con secuencias de navegación fuera del directorio permitido.','high',1,5,85,1),
('ROUTE_SCAN','Escaneo de rutas sensibles','Múltiples solicitudes a rutas sensibles desde la misma IP.','high',5,5,75,1),
('SENSITIVE_ADMIN','Acción administrativa sensible','Cambio de rol, permisos, eliminación de usuario u otra acción administrativa relevante.','high',1,5,70,1)
ON DUPLICATE KEY UPDATE name=VALUES(name),description=VALUES(description),severity=VALUES(severity),threshold_value=VALUES(threshold_value),window_minutes=VALUES(window_minutes),risk_score=VALUES(risk_score);

-- Vincula cada alerta histórica con su evento disparador como evidencia inicial.
INSERT IGNORE INTO alert_events(alert_id,event_id,relation_type)
SELECT id,event_id,'trigger' FROM alerts;
