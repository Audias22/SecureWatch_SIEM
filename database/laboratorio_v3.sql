-- =====================================================================
-- SecureWatch SIEM — Reglas de negocio para el portal de la ferretería (v3)
-- Ejecutar UNA vez en phpMyAdmin (pestaña Importar). Es seguro repetirlo.
-- =====================================================================
USE securewatch_siem;

INSERT INTO rules(rule_key,name,description,severity,threshold_value,window_minutes,risk_score) VALUES
 ('PRICE_MANIPULATION','Rebaja de precio sospechosa','Un producto baja de precio en el porcentaje indicado por el umbral o más.','high',50,60,75),
 ('PRICE_DROP_SALE','Venta tras rebaja de precio','Se vende un producto cuyo precio fue rebajado (umbral en %) dentro de la ventana. Posible fraude interno.','critical',50,60,95),
 ('VOID_ABUSE','Anulaciones repetidas','Un mismo usuario anula varias ventas en poco tiempo.','high',3,60,80),
 ('NEGATIVE_ADJUSTMENT','Ajuste negativo de inventario','Se descuentan del inventario tantas unidades o más (umbral) en un solo ajuste.','medium',10,60,60),
 ('RESET_ABUSE','Abuso de recuperación de contraseña','Muchas solicitudes de recuperación o enlaces inválidos desde la misma IP.','high',5,10,70)
ON DUPLICATE KEY UPDATE description=VALUES(description);
