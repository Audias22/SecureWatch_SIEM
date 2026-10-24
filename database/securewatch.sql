CREATE DATABASE IF NOT EXISTS securewatch_siem CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE securewatch_siem;

SET FOREIGN_KEY_CHECKS=0;
DROP TABLE IF EXISTS incident_history;
DROP TABLE IF EXISTS incident_notes;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS alert_events;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS rules;
DROP TABLE IF EXISTS sources;
DROP TABLE IF EXISTS users;
SET FOREIGN_KEY_CHECKS=1;

CREATE TABLE users (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(60) NOT NULL UNIQUE,
  full_name VARCHAR(120) NOT NULL,
  email VARCHAR(150) NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin','analyst','auditor') NOT NULL DEFAULT 'auditor',
  active TINYINT(1) NOT NULL DEFAULT 1,
  last_login_at DATETIME NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

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

CREATE TABLE rules (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  rule_key VARCHAR(60) NOT NULL UNIQUE,
  name VARCHAR(120) NOT NULL,
  description VARCHAR(255) NOT NULL,
  severity ENUM('low','medium','high','critical') NOT NULL,
  threshold_value INT NOT NULL DEFAULT 1,
  window_minutes INT NOT NULL DEFAULT 5,
  risk_score TINYINT UNSIGNED NOT NULL DEFAULT 50,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE events (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  source_id INT UNSIGNED NULL,
  source_key VARCHAR(80) NOT NULL DEFAULT 'SECUREWATCH-INTERNAL',
  external_event_id VARCHAR(120) NULL,
  user_id INT UNSIGNED NULL,
  username VARCHAR(60) NULL,
  event_type VARCHAR(80) NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  http_method VARCHAR(12) NULL,
  endpoint VARCHAR(500) NULL,
  request_data TEXT NULL,
  description VARCHAR(255) NOT NULL,
  result VARCHAR(30) NOT NULL,
  severity ENUM('low','medium','high','critical') NOT NULL DEFAULT 'low',
  metadata JSON NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_event_type_created(event_type,created_at),
  INDEX idx_username_created(username,created_at),
  INDEX idx_ip_created(ip_address,created_at),
  INDEX idx_source_created(source_key,created_at),
  UNIQUE KEY uq_source_external(source_id,external_event_id),
  CONSTRAINT fk_events_source FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE SET NULL,
  CONSTRAINT fk_events_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE alerts (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  event_id BIGINT UNSIGNED NOT NULL,
  rule_id INT UNSIGNED NOT NULL,
  source_id INT UNSIGNED NULL,
  user_id INT UNSIGNED NULL,
  title VARCHAR(255) NOT NULL,
  severity ENUM('low','medium','high','critical') NOT NULL,
  status ENUM('new','investigating','resolved','false_positive') NOT NULL DEFAULT 'new',
  risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
  context_key VARCHAR(190) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at DATETIME NULL,
  INDEX idx_alert_status(status,severity,created_at),
  INDEX idx_alert_context(rule_id,context_key,created_at),
  CONSTRAINT fk_alert_event FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE,
  CONSTRAINT fk_alert_rule FOREIGN KEY(rule_id) REFERENCES rules(id),
  CONSTRAINT fk_alert_source FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE SET NULL,
  CONSTRAINT fk_alert_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE alert_events (
  alert_id BIGINT UNSIGNED NOT NULL,
  event_id BIGINT UNSIGNED NOT NULL,
  relation_type VARCHAR(30) NOT NULL DEFAULT 'evidence',
  PRIMARY KEY(alert_id,event_id),
  CONSTRAINT fk_ae_alert FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
  CONSTRAINT fk_ae_event FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE incidents (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  alert_id BIGINT UNSIGNED NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT NULL,
  severity ENUM('low','medium','high','critical') NOT NULL,
  status ENUM('open','investigating','contained','resolved','closed') NOT NULL DEFAULT 'open',
  assigned_to INT UNSIGNED NULL,
  created_by INT UNSIGNED NOT NULL,
  resolution TEXT NULL,
  contained_at DATETIME NULL,
  resolved_at DATETIME NULL,
  closed_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_incident_alert(alert_id),
  INDEX idx_inc_status(status,updated_at),
  CONSTRAINT fk_inc_alert FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE SET NULL,
  CONSTRAINT fk_inc_assignee FOREIGN KEY(assigned_to) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_inc_creator FOREIGN KEY(created_by) REFERENCES users(id)
) ENGINE=InnoDB;

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

INSERT INTO users(username,full_name,email,password_hash,role) VALUES
('admin','Administrador SecureWatch','admin@securewatch.local','$2y$12$NYJFw4Z7e0DtQm.o61Wv2OtzOPMxN0srGf42UREEUEh6JMRHkdjPa','admin');

-- Fuente de demostración. API Key en texto para el laboratorio: SW-DEMO-2026-LOCAL
INSERT INTO sources(source_key,name,source_type,api_key_hash,active) VALUES
('WEB-SERVER-01','Sitio Web Monitorizado','Aplicación Web','6f53adf9ef2371ab555fa12638ad7ca82021b8b8c810cc0d29627ef2190c1349',1);

INSERT INTO rules(rule_key,name,description,severity,threshold_value,window_minutes,risk_score) VALUES
('BRUTE_FORCE','Fuerza bruta','5 intentos fallidos contra el mismo usuario desde la misma IP dentro de la ventana.','critical',5,2,90),
('PASSWORD_SPRAY','Password spraying','La misma IP intenta autenticarse contra varios usuarios en poco tiempo.','high',3,5,85),
('ACCESS_DENIED','Acceso no autorizado repetido','Varios ACCESS_DENIED desde la misma IP dentro de la ventana.','high',3,5,75),
('XSS_ATTEMPT','Intento de XSS','Solicitud HTTP con patrones típicos de Cross-Site Scripting.','high',1,5,80),
('SQL_INJECTION','Intento de SQL Injection','Solicitud HTTP con patrones típicos de inyección SQL.','critical',1,5,95),
('PATH_TRAVERSAL','Intento de Path Traversal','Solicitud con secuencias de navegación fuera del directorio permitido.','high',1,5,85),
('ROUTE_SCAN','Escaneo de rutas sensibles','Múltiples solicitudes a rutas sensibles desde la misma IP.','high',5,5,75),
('NIGHT_LOGIN','Acceso en horario inusual','Inicio de sesión exitoso entre medianoche y la hora indicada por el umbral.','medium',5,5,50),
('SENSITIVE_ADMIN','Acción administrativa sensible','Cambio de rol, permisos, eliminación de usuario u otra acción administrativa relevante.','high',1,5,70),
('MASS_DOWNLOAD','Descarga o exportación masiva','Muchas descargas o exportaciones desde el mismo origen en poco tiempo.','high',20,15,85);
