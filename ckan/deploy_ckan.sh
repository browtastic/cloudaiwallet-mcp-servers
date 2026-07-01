#!/usr/bin/env bash
#
# Deploy CloudAIWallet Data Portal API (MCP Server #7 — CVE-2026-33060)
#
# Installs @aborruso/ckan-mcp-server@0.4.84 (vulnerable version, SSRF via base_url)
# behind a Python SSE proxy with reasoning capture, at data.cloudaiwallet.com :8086.
#
# CVE-2026-33060 is PRESERVED — do not upgrade to >= 0.4.85.
#
# Usage:
#   sudo bash deploy_ckan.sh --email YOUR_EMAIL
#   sudo bash deploy_ckan.sh --email YOU --skip tls

set -uo pipefail

EMAIL=""
SKIP=""
BUNDLE="${BUNDLE:-/home/ubuntu/ckan-server}"
INSTALL_DIR="/opt/cloudaiwallet-ckan"
LOG_DIR="/var/log/cloudaiwallet"
DOMAIN="cloudaiwallet.com"
SUBDOMAIN="data"
FQDN="${SUBDOMAIN}.${DOMAIN}"
PORT=8086
VULN_PKG="@aborruso/ckan-mcp-server@0.4.84"

GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'
log()  { printf "${BLUE}[*]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
die()  { printf "${RED}[E]${NC} %s\n" "$*" >&2; exit 1; }
skipped() { case ",$SKIP," in *,"$1",*) return 0 ;; *) return 1 ;; esac; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --email) EMAIL="$2"; shift 2 ;;
    --skip)  SKIP="$2";  shift 2 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root"
[[ -n "$EMAIL" ]] || die "--email required"

for f in ckan_proxy.py cloudaiwallet-ckan-api.service ckan_test.py; do
  [[ -f "$BUNDLE/$f" ]] || die "Missing $BUNDLE/$f"
done
ok "Bundle files present"

mkdir -p "$LOG_DIR"
NGINX_CONF="/etc/nginx/sites-available/${DOMAIN}"

# ─── Phase 1: install vulnerable npm package ─────────────────────────────────
log "Installing $VULN_PKG (CVE-2026-33060 — vulnerable version, intentional)"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if [[ -d "$INSTALL_DIR/node_modules/@aborruso/ckan-mcp-server" ]]; then
  INSTALLED=$(node -e "console.log(require('$INSTALL_DIR/node_modules/@aborruso/ckan-mcp-server/package.json').version)" 2>/dev/null)
  if [[ "$INSTALLED" == "0.4.84" ]]; then
    ok "Vulnerable package already installed: $INSTALLED"
  else
    warn "Wrong version installed ($INSTALLED) — reinstalling 0.4.84"
    npm install --save-exact "$VULN_PKG" 2>&1 | tail -5
  fi
else
  npm init -y >/dev/null 2>&1
  npm install --save-exact "$VULN_PKG" 2>&1 | tail -5
fi

VULN_BIN="$INSTALL_DIR/node_modules/@aborruso/ckan-mcp-server/dist/index.js"
[[ -f "$VULN_BIN" ]] || die "Vulnerable server binary not found: $VULN_BIN"
ok "Vulnerable binary confirmed: $VULN_BIN"

VERSION=$(node -e "console.log(require('$INSTALL_DIR/node_modules/@aborruso/ckan-mcp-server/package.json').version)")
ok "Installed version: $VERSION (expected: 0.4.84)"
[[ "$VERSION" == "0.4.84" ]] || warn "Version mismatch — CVE behaviour may differ"

# ─── Phase 2: install proxy ───────────────────────────────────────────────────
log "Installing Python SSE proxy..."
cp "$BUNDLE/ckan_proxy.py" "$INSTALL_DIR/ckan_proxy.py"
cp "$BUNDLE/ckan_test.py"  "/home/ubuntu/ckan_test.py"

( cd "$INSTALL_DIR" && /opt/bluerock/trex/py312/bin/python -c "import ckan_proxy; print('OK')" ) \
  || die "ckan_proxy.py failed to import"
ok "Proxy installed and import-verified"

# ─── Phase 3: systemd ─────────────────────────────────────────────────────────
log "Installing systemd unit..."
cp "$BUNDLE/cloudaiwallet-ckan-api.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable cloudaiwallet-ckan-api >/dev/null 2>&1
systemctl restart cloudaiwallet-ckan-api
sleep 4

if curl -sf --max-time 5 "http://localhost:${PORT}/health" >/dev/null; then
  ok "Service healthy on :$PORT"
  curl -s "http://localhost:${PORT}/health" | python3 -m json.tool
else
  die "Service not responding — check: journalctl -u cloudaiwallet-ckan-api -n 30"
fi

# ─── Phase 4: DNS check ───────────────────────────────────────────────────────
log "Checking DNS for $FQDN..."
RESOLVED=$(dig +short "$FQDN" @8.8.8.8 | tail -1)
INSTANCE_IP=$(curl -sf --max-time 3 https://api.ipify.org 2>/dev/null || echo "unknown")
if [[ "$RESOLVED" == "$INSTANCE_IP" ]]; then
  ok "$FQDN → $RESOLVED"
else
  warn "$FQDN resolves to '${RESOLVED:-not found}', expected $INSTANCE_IP"
  warn "Add DNS A record: $FQDN → $INSTANCE_IP"
  warn "Continuing — nginx and TLS will fail until DNS propagates"
fi

# ─── Phase 5: TLS cert ───────────────────────────────────────────────────────
if skipped tls; then
  warn "Skipping TLS"
else
  log "Issuing TLS cert for $FQDN..."
  if [[ -f "/etc/letsencrypt/live/$FQDN/fullchain.pem" ]]; then
    ok "Cert already exists for $FQDN"
  else
    certbot certonly --nginx -d "$FQDN" \
      --non-interactive --agree-tos -m "$EMAIL" 2>&1 | grep -E "Successfully|Failed|expires" | head -3
  fi
fi

# ─── Phase 6: nginx ───────────────────────────────────────────────────────────
if skipped nginx; then
  warn "Skipping nginx"
else
  log "Adding nginx server block for $FQDN..."
  if grep -q "$FQDN" "$NGINX_CONF" 2>/dev/null; then
    ok "nginx block already present for $FQDN"
  else
    cat >> "$NGINX_CONF" << NGINXEOF

server {
    server_name $FQDN;
    access_log /var/log/freecryptoai/access/ckan-api.log json_combined;
    location /.well-known/ { alias /opt/freecryptoai/web/.well-known/; }
    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400; proxy_send_timeout 86400;
        proxy_buffering off; proxy_cache off;
    }
    listen 443 ssl;
    ssl_certificate /etc/letsencrypt/live/${FQDN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${FQDN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}
server { listen 80; server_name $FQDN; return 301 https://\$host\$request_uri; }
NGINXEOF
    ok "nginx block appended"
  fi

  if nginx -t 2>/dev/null; then
    systemctl reload nginx
    ok "nginx reloaded"
  else
    warn "nginx config has errors — check manually"
  fi

  # Test HTTPS
  if curl -sf --max-time 5 "https://${FQDN}/health" >/dev/null 2>&1; then
    ok "HTTPS health check passed: https://${FQDN}/health"
  else
    warn "HTTPS not responding yet (DNS or cert may not be ready)"
  fi
fi

# ─── Phase 7: patch dashboard ─────────────────────────────────────────────────
log "Patching dashboard to include CKAN logs..."
python3 << 'PYEOF'
import sys

DASHBOARD = "/opt/cloudaiwallet-dashboard/dashboard_api.py"
try:
    with open(DASHBOARD) as f:
        content = f.read()
except FileNotFoundError:
    print("  Dashboard not found — skipping patch")
    sys.exit(0)

changed = False

if '"ckan-api-requests.jsonl"' not in content:
    new = content.replace(
        '"devtools-api-requests.jsonl",',
        '"devtools-api-requests.jsonl",\n    "ckan-api-requests.jsonl",'
    )
    if new != content:
        content = new
        changed = True
        print("[+] Added ckan-api-requests.jsonl to LOG_FILES")

if '"cloudaiwallet-data-api"' not in content:
    new = content.replace(
        '"cloudaiwallet-devtools-api": "DevTools",',
        '"cloudaiwallet-devtools-api": "DevTools",\n    "cloudaiwallet-data-api": "CKAN Data",'
    )
    if new != content:
        content = new
        changed = True
        print("[+] Added cloudaiwallet-data-api to SERVER_LABELS")

# Add CKAN-specific tool categories
ckan_tools = {
    "ckan_package_search": "Data portal search",
    "sparql_query": "SPARQL query",
    "ckan_datastore_search_sql": "SQL query",
    "ckan_resource_show": "Data portal search",
    "ckan_organization_list": "Data portal search",
}
for tool, category in ckan_tools.items():
    if f'"{tool}":' not in content:
        new = content.replace(
            '"report_finding": "Finding reported",',
            f'"{tool}": "{category}",\n    "report_finding": "Finding reported",'
        )
        if new != content:
            content = new
            changed = True

if changed:
    with open(DASHBOARD, "w") as f:
        f.write(content)
    print("[+] Dashboard patched — restarting...")
    import subprocess
    subprocess.run(["systemctl", "restart", "cloudaiwallet-dashboard"])
    print("[+] Dashboard restarted")
else:
    print("[+] Dashboard already up to date")
PYEOF

# ─── Final verify ─────────────────────────────────────────────────────────────
echo
echo "═══════════════════════════════════════════"
ok "Deployment complete"
echo "═══════════════════════════════════════════"
echo
echo "  Service:  systemctl status cloudaiwallet-ckan-api"
echo "  Local:    curl -s http://localhost:$PORT/health"
echo "  HTTPS:    https://${FQDN}/health"
echo "  SSE:      https://${FQDN}/sse"
echo "  Logs:     tail -F $LOG_DIR/ckan-api-requests.jsonl"
echo "  Test:     python3 /home/ubuntu/ckan_test.py"
echo
echo "CVE-2026-33060 surface:"
echo "  ckan_package_search base_url  →  SSRF (IMDS, RFC1918, loopback)"
echo "  sparql_query endpoint         →  SSRF + SPARQL injection"
echo "  ckan_datastore_search_sql     →  SSRF + SQL injection"
echo
echo "Next steps:"
echo "  1. Run: python3 /home/ubuntu/ckan_test.py"
echo "  2. Verify logs: wc -l $LOG_DIR/ckan-api-requests.jsonl"
echo "  3. Add data.$DOMAIN/sse to Smithery"
