#!/usr/bin/env bash
# ============================================================================
# SSRF-BOX — Script de instalación automática para VPS Ubuntu 22.04/24.04
# Uso: sudo bash install-vps.sh
# ============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()   { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# ── Verificar root ────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Ejecuta como root: sudo bash install-vps.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo -e "\n${BOLD}╔══════════════════════════════════════════╗"
echo -e "║       SSRF-BOX Installer v1.0            ║"
echo -e "╚══════════════════════════════════════════╝${NC}\n"

# ── Inputs ─────────────────────────────────────────────────────────────────
read -rp "Dominio OOB (ej: oob.tudominio.com): " SSRF_DOMAIN
[[ -n "$SSRF_DOMAIN" ]] || die "Dominio requerido"

read -rp "IP pública de este VPS: " VPS_IP
[[ -n "$VPS_IP" ]] || die "IP requerida"

read -rp "Email para Let's Encrypt: " LE_EMAIL
[[ -n "$LE_EMAIL" ]] || die "Email requerido"

API_KEY=$(openssl rand -hex 32)
INTERNAL_API_KEY=$(openssl rand -hex 32)

info "API Key generada: $API_KEY"
info "Internal Key generada: $INTERNAL_API_KEY"

# ── Dependencias del sistema ──────────────────────────────────────────────
info "Actualizando paquetes..."
apt-get update -qq
apt-get install -y -qq curl git ufw fail2ban certbot python3-certbot-dns-cloudflare snapd

# Instalar Docker si no está
if ! command -v docker &>/dev/null; then
  info "Instalando Docker..."
  curl -fsSL https://get.docker.com | bash
  systemctl enable --now docker
  ok "Docker instalado"
else
  ok "Docker ya instalado: $(docker --version)"
fi

# Instalar Docker Compose v2 si no está
if ! docker compose version &>/dev/null 2>&1; then
  info "Instalando Docker Compose v2..."
  COMPOSE_VER=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
  mkdir -p ~/.docker/cli-plugins
  curl -fsSL "https://github.com/docker/compose/releases/download/${COMPOSE_VER}/docker-compose-linux-x86_64" \
    -o ~/.docker/cli-plugins/docker-compose
  chmod +x ~/.docker/cli-plugins/docker-compose
  ok "Docker Compose instalado"
fi

# ── Firewall UFW ────────────────────────────────────────────────────────────
info "Configurando UFW..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   comment "SSH"
ufw allow 53/tcp   comment "DNS TCP"
ufw allow 53/udp   comment "DNS UDP"
ufw allow 80/tcp   comment "HTTP (interaction receiver)"
ufw allow 443/tcp  comment "HTTPS (interaction receiver)"
ufw allow 8080/tcp comment "Admin dashboard"
ufw allow 25/tcp   comment "SMTP listener"
ufw allow 587/tcp  comment "SMTP submission listener"
ufw allow 389/tcp  comment "LDAP listener"
ufw allow 636/tcp  comment "LDAPS listener"
ufw allow 21/tcp   comment "FTP listener"
ufw --force enable
ok "UFW configurado"

# ── Fail2ban básico ────────────────────────────────────────────────────────
info "Configurando Fail2ban..."
cat > /etc/fail2ban/jail.d/ssrf-box.conf <<'EOF'
[sshd]
enabled = true
maxretry = 5
bantime = 3600
findtime = 600

[ssrf-box-admin]
enabled = true
port = 8080
filter = ssrf-box-admin
logpath = /var/log/ssrf-box-admin.log
maxretry = 20
bantime = 600
EOF

cat > /etc/fail2ban/filter.d/ssrf-box-admin.conf <<'EOF'
[Definition]
failregex = ^.*"status":403.*"source_ip":"<HOST>".*$
EOF

systemctl enable --now fail2ban
ok "Fail2ban configurado"

# ── Certificado TLS (Wildcard via Let's Encrypt DNS challenge) ────────────
TLS_CERT=""
TLS_KEY=""

info "Obteniendo certificado wildcard para *.${SSRF_DOMAIN}..."
warn "Se necesita un DNS challenge manual. Sigue las instrucciones:"
echo ""

# Intentar con certbot dns-manual (funciona con cualquier proveedor)
certbot certonly \
  --manual \
  --preferred-challenges=dns \
  --email "$LE_EMAIL" \
  --agree-tos \
  --no-eff-email \
  --manual-public-ip-logging-ok \
  -d "*.${SSRF_DOMAIN}" \
  -d "${SSRF_DOMAIN}" 2>&1 || {
  warn "certbot falló o fue cancelado. Puedes obtener el cert manualmente y añadirlo a .env"
}

CERT_PATH="/etc/letsencrypt/live/${SSRF_DOMAIN}"
if [[ -f "${CERT_PATH}/fullchain.pem" ]]; then
  ok "Certificado obtenido en ${CERT_PATH}"
  TLS_CERT="/certs/fullchain.pem"
  TLS_KEY="/certs/privkey.pem"

  # Crear directorio para montar certs en Docker
  mkdir -p /opt/ssrf-box-certs
  cp "${CERT_PATH}/fullchain.pem" /opt/ssrf-box-certs/
  cp "${CERT_PATH}/privkey.pem" /opt/ssrf-box-certs/
  chmod 600 /opt/ssrf-box-certs/privkey.pem

  # Auto-renewal hook
  cat > /etc/letsencrypt/renewal-hooks/deploy/ssrf-box.sh <<EOF
#!/bin/bash
cp "${CERT_PATH}/fullchain.pem" /opt/ssrf-box-certs/
cp "${CERT_PATH}/privkey.pem" /opt/ssrf-box-certs/
chmod 600 /opt/ssrf-box-certs/privkey.pem
docker restart ssrf-http 2>/dev/null || true
EOF
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/ssrf-box.sh
  ok "Auto-renovación configurada"
fi

# ── Crear .env ─────────────────────────────────────────────────────────────
info "Creando .env en ${ROOT_DIR}..."
cat > "${ROOT_DIR}/.env" <<EOF
SSRF_DOMAIN=${SSRF_DOMAIN}
VPS_IP=${VPS_IP}
API_KEY=${API_KEY}
INTERNAL_API_KEY=${INTERNAL_API_KEY}
DB_PATH=/data/ssrf-box.db
TLS_CERT_PATH=${TLS_CERT}
TLS_KEY_PATH=${TLS_KEY}
DISCORD_WEBHOOK=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
EOF
chmod 600 "${ROOT_DIR}/.env"
ok ".env creado"

# ── Montar volumen de certs en docker-compose.override.yml ────────────────
if [[ -n "$TLS_CERT" ]]; then
  cat > "${ROOT_DIR}/docker-compose.override.yml" <<EOF
version: "3.9"
services:
  http-server:
    volumes:
      - /opt/ssrf-box-certs:/certs:ro
EOF
  ok "docker-compose.override.yml creado para TLS"
fi

# ── Construir y lanzar ─────────────────────────────────────────────────────
info "Construyendo y levantando contenedores..."
cd "$ROOT_DIR"
docker compose build --no-cache
docker compose up -d
ok "Contenedores levantados"

# ── Verificación de salud ─────────────────────────────────────────────────
sleep 3
info "Verificando servicios..."

check_port() {
  local port=$1 name=$2
  if docker compose ps | grep -q "Up" 2>/dev/null || curl -sf --max-time 3 "http://127.0.0.1:${port}/ping" &>/dev/null; then
    ok "${name} (puerto ${port}) — OK"
  else
    warn "${name} (puerto ${port}) — no responde aún (puede tardar unos segundos)"
  fi
}

check_port 80   "HTTP receiver"
check_port 8080 "Admin API"

# ── Resumen ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════"
echo -e "  SSRF-BOX instalado correctamente"
echo -e "══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Dashboard:    ${CYAN}http://${VPS_IP}:8080${NC}"
echo -e "  API Key:      ${YELLOW}${API_KEY}${NC}"
echo -e "  Dominio OOB:  ${CYAN}*.${SSRF_DOMAIN}${NC}"
echo ""
echo -e "${YELLOW}PASOS MANUALES NECESARIOS:${NC}"
echo -e "  1. Configura el registro NS de ${SSRF_DOMAIN} apuntando a ${VPS_IP}"
echo -e "     Ejemplo en Cloudflare: NS oob.tudominio.com → ${VPS_IP}"
echo -e "     Y el glue record:      A  oob.tudominio.com → ${VPS_IP}"
echo -e "  2. Espera propagación DNS (5-30 min)"
echo -e "  3. Prueba: dig A test.${SSRF_DOMAIN} — debe resolver a ${VPS_IP}"
echo ""
echo -e "  Para ver logs:    ${CYAN}docker compose logs -f${NC}"
echo -e "  Para reiniciar:   ${CYAN}docker compose restart${NC}"
echo ""
