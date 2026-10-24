# Contrato de integración — Sitio Web -> SecureWatch SIEM

## Endpoint

```text
POST http://IP_SIEM/SecureWatch_SIEM/api/events.php
```

## Headers

```text
Content-Type: application/json
X-API-Key: <clave de la fuente>
```

## JSON base

```json
{
  "event_id": "id-unico-opcional-pero-recomendado",
  "source": "WEB-SERVER-01",
  "event_type": "LOGIN_FAILED",
  "username": "admin",
  "ip": "192.168.1.30",
  "result": "FAILED",
  "description": "Credenciales incorrectas",
  "timestamp": "2026-10-06T21:00:00-06:00"
}
```

## Campos extra para HTTP_REQUEST

```json
{
  "method": "GET",
  "endpoint": "/buscar.php?q=texto",
  "request_data": "datos recibidos por la aplicación"
}
```

## Tipos recomendados

```text
LOGIN_SUCCESS
LOGIN_FAILED
LOGOUT
ACCESS_DENIED
PASSWORD_CHANGE
USER_CREATED
USER_UPDATED
USER_DELETED
ROLE_CHANGED
PERMISSION_CHANGED
ADMIN_ACTION
FILE_UPLOAD
FILE_DOWNLOAD
DATA_EXPORT
HTTP_REQUEST
```

## Respuesta normal

```json
{
  "success": true,
  "message": "Event received",
  "event_id": 154,
  "alerts": [12]
}
```

## Reglas de integración

- Un `LOGIN_FAILED` por cada intento fallido.
- La IP debe ser la IP del cliente que hizo la acción.
- El sitio no genera alertas: solo envía eventos.
- No enviar contraseñas ni secretos.
- El sitio debe seguir funcionando si SecureWatch está apagado.
- Usar timeout corto al enviar los eventos.
- `event_id` evita procesar dos veces el mismo evento.
