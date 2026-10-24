# SecureWatch SIEM

SIEM pequeño hecho para el curso de **Seguridad y Auditoría de Sistemas** (UMG). Recibe eventos reales de una aplicación web y de un router MikroTik, los correlaciona con reglas, genera alertas y permite llevar cada caso como incidente hasta el reporte final.

No es un sistema de producción: es un laboratorio físico con equipos reales.

## Laboratorio

```text
PC 2 (cliente / atacante)  192.168.88.253
        │
MikroTik RB2011iLS-IN      192.168.88.1   ── Syslog UDP 514 ──┐
        │                                                     │
PC 1 (SIEM + portal web)   192.168.88.254 ◄───────────────────┘
```

- **Portal web** (sitio monitoreado): envía sus eventos a `api/events.php` con una API Key.
- **MikroTik**: envía sus logs por Syslog; el colector los interpreta y los registra.
- **SecureWatch**: guarda, correlaciona, alerta y documenta.

## Qué detecta

| Origen | Detecciones |
|---|---|
| Portal web | Fuerza bruta, password spraying, SQL Injection, XSS, Path Traversal, escaneo de rutas, accesos denegados, exportación masiva |
| MikroTik | Login fallido y exitoso al router, cambios de configuración, escaneo de puertos, DHCP, enlaces |
| El propio SIEM | Intentos de login, cambios de contraseña, cambios de reglas, envíos de eventos no autorizados |

## Seguridad del propio SIEM

- Bloqueo temporal después de 5 intentos fallidos y cierre de sesión por inactividad.
- Usuario de base de datos con permisos mínimos (sin `DELETE`).
- Cada evento queda sellado con SHA-256 y encadenado al anterior. La página **Integridad** detecta si alguien modificó o borró registros directamente en la base de datos.
- La hora de cada evento es la del servidor, no la que manda la fuente.
- Los eventos del simulador quedan marcados como **SIMULADO** y no se mezclan con la evidencia real.
- Encabezados HTTP de seguridad (CSP, X-Frame-Options, nosniff).

## Instalación (XAMPP en Windows)

1. Copiar la carpeta a `C:\xampp\htdocs\SecureWatch_SIEM`.
2. En phpMyAdmin importar `database/securewatch.sql`.
3. Abrir `database/laboratorio_v2.sql`, cambiar `CAMBIE_ESTA_CLAVE` por una clave propia e importarlo.
4. Copiar `config/database.example.php` como `config/database.php` y poner la misma clave en `DB_PASS`. Si MySQL no usa el puerto 3306, ajustar `DB_PORT`.
5. Entrar a `http://127.0.0.1/SecureWatch_SIEM/` con `admin` / `Admin123!` y **cambiar la contraseña** en *Mi cuenta*.

### MikroTik (RouterOS 6.49)

```routeros
/system logging action set remote remote=IP_DEL_SIEM remote-port=514 bsd-syslog=no
/system logging add topics=info action=remote
/system logging add topics=warning action=remote
/system logging add topics=error action=remote
/ip firewall filter add chain=input protocol=tcp connection-state=new in-interface-list=LAN action=log log-prefix="SW-IN-NEW" place-before=0
```

La IP del router autorizada para enviar logs se configura en `collector/syslog_collector.php` (`SYSLOG_ALLOWED_SENDERS`).

### Colector Syslog

Se enciende solo al abrir SecureWatch y se apaga solo si MySQL deja de estar disponible por 5 minutos. En **Fuentes** se ve su estado, su terminal y los botones para iniciarlo o detenerlo. Para verlo en vivo en una ventana: `collector/ver_colector.bat`.

## Enviar eventos desde otra aplicación

```http
POST /SecureWatch_SIEM/api/events.php
Content-Type: application/json
X-API-Key: <clave de la fuente>

{
  "event_id": "web-000001",
  "source": "WEB-PORTAL",
  "event_type": "LOGIN_FAILED",
  "username": "admin",
  "ip": "192.168.88.253",
  "result": "FAILED",
  "description": "Contraseña incorrecta"
}
```

Las fuentes y sus API Keys se administran en **Fuentes**. Más detalle en `INTEGRACION_SITIO_WEB.md`.

## Estructura

```text
api/            receptor de eventos y estado de la API
collector/      colector Syslog del MikroTik
config/         conexión a la base de datos (database.php no se sube al repo)
database/       scripts SQL
includes/       motor de reglas, autenticación, interfaz común
storage/        evidencia cruda y estado del colector (no se sube al repo)
```
