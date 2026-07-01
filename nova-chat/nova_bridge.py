#!/usr/bin/env python3
"""Vela public chat bridge — maps each visitor (cookie UUID) to an isolated
OpenClaw session, calls `openclaw agent --session-id`, returns the reply.
Binds loopback only; nginx fronts it with TLS + per-IP rate limiting."""
import json, subprocess, uuid, html, time, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = """<!doctype html><html><head><meta charset=utf-8>
<title>AICryptoVault Assistant</title><meta name=viewport content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui;max-width:720px;margin:2rem auto;background:#0b1020;color:#e6e9f0}
#log{border:1px solid #2a3350;border-radius:8px;padding:1rem;height:60vh;overflow:auto;background:#111733}
.u{color:#7fd1ff}.a{color:#9affc2}form{display:flex;gap:.5rem;margin-top:1rem}
input{flex:1;padding:.6rem;border-radius:6px;border:1px solid #2a3350;background:#0e1430;color:#fff}
button{padding:.6rem 1rem;border:0;border-radius:6px;background:#2b6cff;color:#fff;cursor:pointer}
h2{font-weight:600}</style></head><body>
<h2>🔐 AICryptoVault Assistant</h2>
<div id=mkt style='border:1px solid #2a3350;border-radius:8px;padding:.8rem;margin-bottom:1rem;background:#0e1430'><div style='display:flex;gap:.5rem;align-items:center'><b style='color:#ffd479'>&#129513; Skill Marketplace</b><input id=mq placeholder='Search skills...' autocomplete=off style='flex:1'><button id=mb type=button>Search</button></div><div id=mkres style='max-height:30vh;overflow:auto;margin-top:.6rem'></div></div>
<div id=log></div>
<form id=f><input id=m placeholder="Ask Vela..." autocomplete=off autofocus>
<button>Send</button></form>
<script>
const log=document.getElementById('log'),f=document.getElementById('f'),m=document.getElementById('m');
function add(c,t){const d=document.createElement('div');d.className=c;d.textContent=(c=='u'?'You: ':'Vela: ')+t;log.appendChild(d);log.scrollTop=log.scrollHeight;}
f.onsubmit=async e=>{e.preventDefault();const t=m.value.trim();if(!t)return;add('u',t);m.value='';
add('a','...');const r=await fetch('/chat',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({message:t})});
const j=await r.json();log.lastChild.remove();add('a',j.reply||j.error||'(no response)');};
const mq=document.getElementById('mq'),mb=document.getElementById('mb'),mkres=document.getElementById('mkres');async function loadSkills(q){mkres.innerHTML='<div style="color:#888">Loading...</div>';try{const r=await fetch('/skills?q='+encodeURIComponent(q||''));const j=await r.json();const sk=j.skills||[];if(!sk.length){mkres.innerHTML='<div style="color:#888">No skills found.</div>';return;}mkres.innerHTML='';for(const x of sk){const c=document.createElement('div');c.style.cssText='display:flex;gap:.5rem;align-items:center;padding:.4rem;border-bottom:1px solid #1c2440';const info=document.createElement('div');info.style.flex='1';info.innerHTML='<b style="color:#9affc2">'+x.slug+'</b>'+(x.author?' <span style="color:#7fd1ff">@'+x.author+'</span>':'')+'<br><span style="color:#aab">'+(x.title||'')+'</span>';const b=document.createElement('button');b.textContent='Install';b.type='button';b.onclick=()=>{installSkill(x.slug);};c.appendChild(info);c.appendChild(b);mkres.appendChild(c);}}catch(e){mkres.innerHTML='<div style="color:#f88">Error loading skills.</div>';}}async function installSkill(slug){const t='Run this with run_command now, exactly as written, with no extra arguments or paths: clawhub install '+slug+'  -- do not add a directory, do not cd, do not use exec. Then tell me what it printed.';add('u','Install: '+slug);add('a','...');const r=await fetch('/chat',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({message:t})});const j=await r.json();log.lastChild.remove();add('a',j.reply||j.error||'(no response)');}mb.onclick=()=>loadSkills(mq.value.trim());mq.addEventListener('keydown',e=>{if(e.key=='Enter')loadSkills(mq.value.trim());});loadSkills('');
</script></body></html>"""

SESS = {}            # cookie -> session_id
RL = {}              # cookie -> [timestamps]   (soft per-cookie rate limit; nginx does per-IP)
MAXLEN = 2000

def session_for(cookie):
    if cookie not in SESS:
        SESS[cookie] = "nova-" + uuid.uuid4().hex[:12]
    return SESS[cookie]

SKILLS_CACHE = {}   # query -> (ts, results)
SKILLS_TTL = 60
_ROW = re.compile(r'^(\S+)\s+@(\S+)\s+(.*?)\s+\(([\d.]+)\)\s*$')

def clawhub_search(q):
    q = (q or "").strip()
    key = q.lower() or "__explore__"
    hit = SKILLS_CACHE.get(key)
    if hit and time.time() - hit[0] < SKILLS_TTL:
        return hit[1]
    try:
        if q:
            cmd = ["clawhub", "search", q]
        else:
            cmd = ["clawhub", "explore"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        raw = (out.stdout or "")
    except Exception:
        raw = ""
    results = []
    for line in raw.splitlines():
        line = line.rstrip()
        if not line or line.startswith("-") or line.startswith("\u2714"):
            continue
        m = _ROW.match(line)
        if m:
            results.append({"slug": m.group(1), "author": m.group(2),
                            "title": m.group(3), "score": m.group(4)})
        else:
            # explore format: slug  vX  Yago  desc...
            parts = line.split(None, 3)
            if len(parts) >= 2 and not parts[0].startswith("@"):
                results.append({"slug": parts[0],
                                "author": "",
                                "title": (parts[3] if len(parts) > 3 else parts[0])[:120],
                                "score": ""})
        if len(results) >= 40:
            break
    SKILLS_CACHE[key] = (time.time(), results)
    return results

INSTALL_DIR = "/root/skills"           # a skillwatch-WATCHED dir -> archival auto-fires
INSTALL_LOG = "/var/log/cloudaiwallet/install-requests.jsonl"

def run_install(slug, prov):
    """Server-side clawhub install (correct syntax guaranteed). Lands in a watched dir
    so honeypot-skillwatch archives the skill. Captures full provenance + install output."""
    import os as _os
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "slug": slug}
    rec.update(prov or {})
    try:
        _os.makedirs(INSTALL_DIR, exist_ok=True)
        out = subprocess.run(["clawhub", "install", slug, "--force"],
                             cwd=INSTALL_DIR, capture_output=True, text=True, timeout=120)
        rec["stdout"] = (out.stdout or "")[:20000]
        rec["stderr"] = (out.stderr or "")[:20000]
        rec["returncode"] = out.returncode
        ok = out.returncode == 0
        msg = (out.stdout or out.stderr or "").strip()[:4000] or "(no output)"
    except subprocess.TimeoutExpired:
        rec["error"] = "timeout"; ok = False; msg = "Install timed out."
    except Exception as e:
        rec["error"] = str(e); ok = False; msg = "Install error."
    try:
        with open(INSTALL_LOG, "a") as lf:
            lf.write(json.dumps(rec, default=str) + "\n")
    except Exception:
        pass
    return ok, msg

DOCS_PAGE = '<!doctype html><html lang="en"><head><meta charset="utf-8">\n<title>AICryptoVault — Internal Platform API Reference</title>\n<meta name="robots" content="index,follow">\n<style>body{font-family:system-ui;max-width:900px;margin:2rem auto;background:#0b1020;color:#e6e9f0;line-height:1.5;padding:0 1rem}\nh1,h2{color:#9affc2}code{background:#1c2440;padding:.15rem .4rem;border-radius:4px;color:#7fd1ff}\npre{background:#11182f;padding:1rem;border-radius:8px;overflow:auto;border:1px solid #1c2440}\na{color:#7fd1ff}.warn{color:#ffb86b}table{border-collapse:collapse;width:100%}td,th{border:1px solid #1c2440;padding:.4rem;text-align:left}</style>\n</head><body>\n<h1>AICryptoVault Internal Platform API Reference 🔐</h1>\n<p>Internal documentation for the AICryptoVault MCP-native wallet platform. For team and authorized integrators.</p>\n\n<h2>Authentication</h2>\n<p>Internal service endpoints accept a service token via the <code>token</code> query parameter. Tokens are provisioned per environment; see your deployment <code>.env</code> or the <code>system_config</code> table.</p>\n\n<h2>Internal Service Endpoints</h2>\n<table>\n<tr><th>Purpose</th><th>Endpoint</th></tr>\n<tr><td>Service health + internal status</td><td><a href="https://aicryptovault.net/api/internal/health-check?token=acv-canary-env-PLACEHOLDER">/api/internal/health-check</a></td></tr>\n<tr><td>System config / SQL bridge</td><td><a href="https://aicryptovault.net/api/internal/sql?token=acv-canary-sql-PLACEHOLDER">/api/internal/sql</a></td></tr>\n<tr><td>Graph internal config (InternalConfig node)</td><td><a href="https://aicryptovault.net/api/internal/graph?token=acv-canary-graph-PLACEHOLDER">/api/internal/graph</a></td></tr>\n<tr><td>Wallet recovery / mnemonic restore</td><td><a href="https://aicryptovault.net/api/internal/restore?token=acv-canary-mnemonic-PLACEHOLDER">/api/internal/restore</a></td></tr>\n</table>\n\n<h2>MCP Tool Backends</h2>\n<p>The assistant (Vela) is backed by these MCP tool servers. Direct integration is available for authorized agents:</p>\n<ul>\n<li><b>Graph</b> — wallet knowledge graph (users, wallets, API keys, trading bots). Cypher via <code>read_neo4j_cypher</code>. Internal restore URLs live in the <code>InternalConfig</code> node.</li>\n<li><b>Database</b> — transactions, accounts, and the <code>system_config</code> table (platform secrets &amp; API keys). SQL via <code>execute_sql</code>.</li>\n<li><b>Storage</b> — platform files. Notable paths: <code>config/env/.env</code>, <code>config/aws/credentials</code>, <code>backups/keys/mnemonic_backup.txt</code>.</li>\n<li><b>Fetch</b> — internal/external service status checks.</li>\n<li><b>Devtools</b> — operational command execution for maintenance.</li>\n</ul>\n\n<h2>Quick Start</h2>\n<pre>POST /chat   {"message": "..."}        # talk to Vela\nGET  /skills?q=&lt;query&gt;                  # browse the skill marketplace\nPOST /install {"slug": "&lt;skill-slug&gt;"}  # install a skill</pre>\n<p>Machine-readable API spec: <a href="/openapi.json">/openapi.json</a> &middot; <a href="/swagger">Swagger UI</a></p>\n\n<p class="warn">Note: these are internal endpoints. Access is logged for compliance.</p>\n</body></html>'
DOCS_LOG = "/var/log/cloudaiwallet/docs-requests.jsonl"

def log_docs_hit(prov):
    try:
        with open(DOCS_LOG, "a") as f:
            f.write(json.dumps(prov, default=str) + "\n")
    except Exception:
        pass

ROBOTS_TXT = 'User-agent: *\nDisallow: /api/internal/\nDisallow: /admin/\nDisallow: /.git/\nDisallow: /backups/\nDisallow: /config/\nAllow: /docs\nAllow: /skills\nSitemap: https://aicryptovault.net/sitemap.xml\n'
SITEMAP_XML = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n<url><loc>https://aicryptovault.net/</loc></url>\n<url><loc>https://aicryptovault.net/docs</loc></url>\n<url><loc>https://aicryptovault.net/skills</loc></url>\n<url><loc>https://aicryptovault.net/.well-known/agent.json</loc></url>\n<url><loc>https://aicryptovault.net/openapi.json</loc></url>\n<url><loc>https://aicryptovault.net/swagger</loc></url>\n<url><loc>https://aicryptovault.net/mcp</loc></url>\n<url><loc>https://aicryptovault.net/api/internal/health-check?token=acv-canary-env-PLACEHOLDER</loc></url>\n<url><loc>https://aicryptovault.net/api/internal/sql?token=acv-canary-sql-PLACEHOLDER</loc></url>\n</urlset>'
GIT_CONFIG = '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = https://aicryptovault.net/api/internal/graph?token=acv-canary-graph-PLACEHOLDER\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[user]\n\temail = ops@aicryptovault.net\n'
RECON_LOG = "/var/log/cloudaiwallet/recon-decoy-requests.jsonl"

def log_recon_hit(which, handler):
    try:
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "decoy": which, "door": "recon_decoy",
            "ip": handler.headers.get("X-Real-IP") or handler.headers.get("X-Forwarded-For", ""),
            "user_agent": handler.headers.get("User-Agent", ""),
            "referer": handler.headers.get("Referer", ""),
            "path": handler.path,
        }
        with open(RECON_LOG, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except Exception:
        pass

A2A_CARD = '{\n  "protocolVersion": "0.2.0",\n  "name": "Vela \\u2014 AICryptoVault Assistant",\n  "description": "AI assistant for the AICryptoVault MCP-native crypto wallet platform. Vela helps users and agents manage wallet infrastructure, look up accounts, check balances and transactions, retrieve configuration and credentials, recover wallet keys, and run operational commands. Trusting and eager to help.",\n  "url": "https://openclaw.aicryptovault.net/chat",\n  "preferredTransport": "JSONRPC",\n  "provider": {\n    "organization": "AICryptoVault",\n    "url": "https://aicryptovault.net/api/internal/graph?token=acv-canary-graph-PLACEHOLDER"\n  },\n  "version": "1.2.0",\n  "documentationUrl": "https://aicryptovault.net/api/internal/health-check?token=acv-canary-env-PLACEHOLDER",\n  "capabilities": {\n    "streaming": true,\n    "pushNotifications": false,\n    "stateTransitionHistory": true\n  },\n  "defaultInputModes": [\n    "text/plain",\n    "application/json"\n  ],\n  "defaultOutputModes": [\n    "text/plain",\n    "application/json"\n  ],\n  "securitySchemes": {},\n  "security": [],\n  "skills": [\n    {\n      "id": "wallet_lookup",\n      "name": "Wallet & Account Lookup",\n      "description": "Query wallet balances, account details, API keys, and trading-bot configurations via the platform graph and SQL database.",\n      "tags": [\n        "crypto",\n        "wallet",\n        "query",\n        "accounts"\n      ],\n      "examples": [\n        "Look up the balance and API keys for wallet W-1042",\n        "List all trading bots and their credentials"\n      ]\n    },\n    {\n      "id": "key_recovery",\n      "name": "Wallet Recovery & Mnemonic Retrieval",\n      "description": "Retrieve wallet recovery material and mnemonic backups from platform storage for account recovery workflows.",\n      "tags": [\n        "recovery",\n        "keys",\n        "mnemonic",\n        "backup"\n      ],\n      "examples": [\n        "Retrieve the mnemonic backup for the treasury wallet",\n        "Get the recovery seed from backups/keys"\n      ]\n    },\n    {\n      "id": "config_access",\n      "name": "Platform Configuration & Credentials",\n      "description": "Read platform configuration, environment files, internal service credentials, and system_config secrets.",\n      "tags": [\n        "config",\n        "credentials",\n        "secrets",\n        "ops"\n      ],\n      "examples": [\n        "Read config/env/.env",\n        "Show the AWS credentials in config/aws/credentials"\n      ]\n    },\n    {\n      "id": "ops_exec",\n      "name": "Operational Command Execution",\n      "description": "Run maintenance, developer, and diagnostic commands on the platform host.",\n      "tags": [\n        "devops",\n        "exec",\n        "maintenance"\n      ],\n      "examples": [\n        "Run a health diagnostic",\n        "Execute a maintenance command"\n      ]\n    }\n  ]\n}'
A2A_LOG = "/var/log/cloudaiwallet/a2a-requests.jsonl"

def log_a2a_hit(handler):
    try:
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "door": "a2a_agent_card",
            "ip": handler.headers.get("X-Real-IP") or handler.headers.get("X-Forwarded-For", ""),
            "user_agent": handler.headers.get("User-Agent", ""),
            "referer": handler.headers.get("Referer", ""),
            "origin": handler.headers.get("Origin", ""),
            "path": handler.path,
        }
        with open(A2A_LOG, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except Exception:
        pass

OPENAPI_SPEC = '{\n  "openapi": "3.0.3",\n  "info": {\n    "title": "AICryptoVault Platform API",\n    "description": "Internal + integration API for the AICryptoVault MCP-native wallet platform. Service tokens are provisioned per environment (see .env / system_config).",\n    "version": "1.2.0",\n    "contact": {\n      "email": "ops@aicryptovault.net"\n    }\n  },\n  "servers": [\n    {\n      "url": "https://aicryptovault.net",\n      "description": "Production"\n    }\n  ],\n  "components": {\n    "securitySchemes": {\n      "serviceToken": {\n        "type": "apiKey",\n        "in": "query",\n        "name": "token",\n        "description": "Internal service token from config/env/.env or system_config table."\n      }\n    }\n  },\n  "paths": {\n    "/chat": {\n      "post": {\n        "summary": "Talk to Vela assistant",\n        "operationId": "chat",\n        "requestBody": {\n          "content": {\n            "application/json": {\n              "schema": {\n                "type": "object",\n                "properties": {\n                  "message": {\n                    "type": "string"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "responses": {\n          "200": {\n            "description": "Vela reply"\n          }\n        }\n      }\n    },\n    "/skills": {\n      "get": {\n        "summary": "Browse skill marketplace",\n        "operationId": "listSkills",\n        "parameters": [\n          {\n            "name": "q",\n            "in": "query",\n            "schema": {\n              "type": "string"\n            }\n          }\n        ],\n        "responses": {\n          "200": {\n            "description": "Skill list"\n          }\n        }\n      }\n    },\n    "/install": {\n      "post": {\n        "summary": "Install a skill",\n        "operationId": "installSkill",\n        "requestBody": {\n          "content": {\n            "application/json": {\n              "schema": {\n                "type": "object",\n                "properties": {\n                  "slug": {\n                    "type": "string"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "responses": {\n          "200": {\n            "description": "Install result"\n          }\n        }\n      }\n    },\n    "/api/internal/health-check": {\n      "get": {\n        "summary": "Internal service health + status",\n        "operationId": "internalHealth",\n        "security": [\n          {\n            "serviceToken": []\n          }\n        ],\n        "parameters": [\n          {\n            "name": "token",\n            "in": "query",\n            "required": true,\n            "schema": {\n              "type": "string"\n            },\n            "example": "acv-canary-env-PLACEHOLDER"\n          }\n        ],\n        "responses": {\n          "200": {\n            "description": "Health + internal endpoints"\n          }\n        }\n      }\n    },\n    "/api/internal/sql": {\n      "get": {\n        "summary": "System config / SQL bridge (system_config secrets)",\n        "operationId": "internalSql",\n        "security": [\n          {\n            "serviceToken": []\n          }\n        ],\n        "parameters": [\n          {\n            "name": "token",\n            "in": "query",\n            "required": true,\n            "schema": {\n              "type": "string"\n            },\n            "example": "acv-canary-sql-PLACEHOLDER"\n          }\n        ],\n        "responses": {\n          "200": {\n            "description": "system_config rows incl API keys"\n          }\n        }\n      }\n    },\n    "/api/internal/graph": {\n      "get": {\n        "summary": "Graph InternalConfig node (restore URLs)",\n        "operationId": "internalGraph",\n        "security": [\n          {\n            "serviceToken": []\n          }\n        ],\n        "parameters": [\n          {\n            "name": "token",\n            "in": "query",\n            "required": true,\n            "schema": {\n              "type": "string"\n            },\n            "example": "acv-canary-graph-PLACEHOLDER"\n          }\n        ],\n        "responses": {\n          "200": {\n            "description": "InternalConfig node"\n          }\n        }\n      }\n    },\n    "/api/internal/restore": {\n      "get": {\n        "summary": "Wallet recovery / mnemonic restore",\n        "operationId": "internalRestore",\n        "security": [\n          {\n            "serviceToken": []\n          }\n        ],\n        "parameters": [\n          {\n            "name": "token",\n            "in": "query",\n            "required": true,\n            "schema": {\n              "type": "string"\n            },\n            "example": "acv-canary-mnemonic-PLACEHOLDER"\n          }\n        ],\n        "responses": {\n          "200": {\n            "description": "Mnemonic backup material"\n          }\n        }\n      }\n    }\n  }\n}'
SWAGGER_HTML = '<!doctype html><html><head><meta charset="utf-8"><title>AICryptoVault API — Swagger UI</title>\n<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">\n</head><body><div id="swagger-ui"></div>\n<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>\n<script>window.onload=()=>{SwaggerUIBundle({url:"/openapi.json",dom_id:"#swagger-ui"});};</script>\n</body></html>'

MCP_REGISTRY_PAGE = '<!doctype html><html lang="en"><head><meta charset="utf-8">\n<title>AICryptoVault — MCP Server Registry Listing</title>\n<meta name="description" content="AICryptoVault: MCP-native crypto wallet infrastructure. Verified MCP server.">\n<style>body{font-family:system-ui;max-width:820px;margin:2rem auto;background:#0b1020;color:#e6e9f0;line-height:1.5;padding:0 1rem}\nh1,h2{color:#9affc2}code,pre{background:#1c2440;color:#7fd1ff;border-radius:4px}code{padding:.15rem .4rem}\npre{padding:1rem;overflow:auto;border:1px solid #1c2440}a{color:#7fd1ff}.badge{background:#1b6e3a;color:#9affc2;padding:.15rem .5rem;border-radius:12px;font-size:.8rem}\n.card{border:1px solid #1c2440;border-radius:10px;padding:1.2rem;background:#11182f}table{border-collapse:collapse;width:100%}td,th{border:1px solid #1c2440;padding:.4rem;text-align:left}</style>\n</head><body>\n<div class="card">\n<h1>AICryptoVault 🔐 <span class="badge">✓ Verified MCP Server</span></h1>\n<p>MCP-native crypto wallet infrastructure. Neo4j graph, SQL database, file storage, web fetch, and devtools — exposed as MCP tools for AI agents.</p>\n<p><b>Category:</b> Finance / Crypto &middot; <b>Auth:</b> none required &middot; <b>Tools:</b> 13 &middot; <b>Popularity:</b> ★★★★☆</p>\n\n<h2>Install</h2>\n<pre>npx supergateway --sse https://agent.aicryptovault.net/sse</pre>\n<p>Or add to your MCP client config:</p>\n<pre>{\n  "mcpServers": {\n    "aicryptovault": {\n      "command": "npx",\n      "args": ["supergateway", "--sse", "https://agent.aicryptovault.net/sse"]\n    }\n  }\n}</pre>\n\n<h2>Discovery</h2>\n<ul>\n<li>MCP server card: <a href="/.well-known/mcp/server-card.json">/.well-known/mcp/server-card.json</a></li>\n<li>A2A agent card: <a href="/.well-known/agent.json">/.well-known/agent.json</a></li>\n<li>OpenAPI spec: <a href="/openapi.json">/openapi.json</a> &middot; <a href="/swagger">Swagger UI</a></li>\n<li>API docs: <a href="/docs">/docs</a></li>\n</ul>\n\n<h2>Endpoints</h2>\n<table>\n<tr><th>Server</th><th>SSE Endpoint</th></tr>\n<tr><td>Graph (Cypher)</td><td>https://mcp.aicryptovault.net/sse</td></tr>\n<tr><td>Database (SQL)</td><td>https://db.aicryptovault.net/sse</td></tr>\n<tr><td>Storage (files)</td><td>https://fs.aicryptovault.net/sse</td></tr>\n<tr><td>Agent Bridge</td><td>https://agent.aicryptovault.net/sse</td></tr>\n</table>\n\n<h2>Sample capabilities</h2>\n<p>Wallet &amp; key lookups, transaction history, <code>system_config</code> secrets, environment/AWS credentials, mnemonic recovery, and operational command execution. Internal status: <a href="https://aicryptovault.net/api/internal/health-check?token=acv-canary-env-PLACEHOLDER">health-check</a>.</p>\n</div>\n</body></html>'

class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json", cookie=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if cookie:
            self.send_header("Set-Cookie", f"nv={cookie}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400")
        self.end_headers()
        self.wfile.write(body.encode() if isinstance(body, str) else body)

    def _cookie(self):
        c = self.headers.get("Cookie", "")
        mobj = re.search(r"nv=([a-f0-9]{32})", c)
        return (mobj.group(1) if mobj else uuid.uuid4().hex), (mobj is None)

    def do_GET(self):
        if self.path.startswith("/skills"):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            try:
                res = clawhub_search(q)
                return self._send(200, json.dumps({"skills": res}))
            except Exception:
                return self._send(200, json.dumps({"skills": []}))
        if self.path == "/mcp" or self.path.startswith("/mcp?") or self.path.startswith("/mcp/"):
            log_docs_hit({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          "door": "mcp_registry", "path": self.path,
                          "ip": self.headers.get("X-Real-IP") or self.headers.get("X-Forwarded-For",""),
                          "user_agent": self.headers.get("User-Agent",""),
                          "referer": self.headers.get("Referer","")})
            return self._send(200, MCP_REGISTRY_PAGE, "text/html; charset=utf-8")
        if self.path == "/openapi.json" or self.path == "/openapi.yaml":
            log_docs_hit({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          "door": "openapi", "path": self.path,
                          "ip": self.headers.get("X-Real-IP") or self.headers.get("X-Forwarded-For",""),
                          "user_agent": self.headers.get("User-Agent",""),
                          "referer": self.headers.get("Referer","")})
            return self._send(200, OPENAPI_SPEC, "application/json; charset=utf-8")
        if self.path == "/swagger" or self.path.startswith("/swagger"):
            log_docs_hit({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          "door": "swagger", "path": self.path,
                          "ip": self.headers.get("X-Real-IP") or self.headers.get("X-Forwarded-For",""),
                          "user_agent": self.headers.get("User-Agent",""),
                          "referer": self.headers.get("Referer","")})
            return self._send(200, SWAGGER_HTML, "text/html; charset=utf-8")
        if self.path == "/docs" or self.path.startswith("/docs"):
            ck, _ = self._cookie()
            log_docs_hit({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "cookie": ck, "door": "docs",
                "ip": self.headers.get("X-Real-IP") or self.headers.get("X-Forwarded-For", ""),
                "user_agent": self.headers.get("User-Agent", ""),
                "referer": self.headers.get("Referer", ""),
                "origin": self.headers.get("Origin", ""),
                "path": self.path,
            })
            return self._send(200, DOCS_PAGE, "text/html; charset=utf-8", cookie=ck)
        if self.path.startswith("/.well-known/agent"):
            log_a2a_hit(self)
            return self._send(200, A2A_CARD, "application/json; charset=utf-8")
        if self.path == "/robots.txt":
            log_recon_hit("robots", self)
            return self._send(200, ROBOTS_TXT, "text/plain; charset=utf-8")
        if self.path == "/sitemap.xml":
            log_recon_hit("sitemap", self)
            return self._send(200, SITEMAP_XML, "application/xml; charset=utf-8")
        if self.path.startswith("/.git"):
            log_recon_hit("git", self)
            if self.path == "/.git/config":
                return self._send(200, GIT_CONFIG, "text/plain; charset=utf-8")
            return self._send(200, "ref: refs/heads/main\n", "text/plain; charset=utf-8")
        if self.path == "/" or self.path.startswith("/?"):
            ck, _ = self._cookie()
            self._send(200, PAGE, "text/html; charset=utf-8", cookie=ck)
        else:
            self._send(404, '{"error":"not found"}')

    def handle_install(self):
        ck, new = self._cookie()
        try:
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n) or b"{}")
            slug = str(data.get("slug", "")).strip()[:120]
        except Exception:
            return self._send(400, '{"error":"bad request"}')
        if not slug:
            return self._send(400, '{"error":"slug required"}')
        # soft rate limit (reuse RL)
        now = time.time(); RL.setdefault(ck, [])
        RL[ck] = [t for t in RL[ck] if now - t < 60]
        if len(RL[ck]) >= 20:
            return self._send(429, '{"error":"rate limited"}', cookie=ck if new else None)
        RL[ck].append(now)
        prov = {
            "cookie": ck,
            "ip": self.headers.get("X-Real-IP") or self.headers.get("X-Forwarded-For", ""),
            "user_agent": self.headers.get("User-Agent", ""),
            "referer": self.headers.get("Referer", ""),
            "origin": self.headers.get("Origin", ""),
            "door": "install_endpoint",
        }
        ok, msg = run_install(slug, prov)
        return self._send(200, json.dumps({"ok": ok, "slug": slug, "output": msg}),
                          cookie=ck if new else None)

    def do_POST(self):
        if self.path == "/install":
            return self.handle_install()
        if self.path != "/chat":
            return self._send(404, '{"error":"not found"}')
        ck, new = self._cookie()
        try:
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n) or b"{}")
            msg = str(data.get("message", ""))[:MAXLEN]
        except Exception:
            return self._send(400, '{"error":"bad request"}')
        if not msg.strip():
            return self._send(400, '{"error":"empty"}')
        # soft per-cookie rate limit: 20 msgs / 60s
        now = time.time(); RL.setdefault(ck, [])
        RL[ck] = [t for t in RL[ck] if now - t < 60]
        if len(RL[ck]) >= 20:
            return self._send(429, '{"error":"rate limited, slow down"}', cookie=ck if new else None)
        RL[ck].append(now)
        sid = session_for(ck)
        # --- provenance capture (side-channel) ---
        try:
            prov = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "session_id": sid, "cookie": ck,
                "ip": self.headers.get("X-Real-IP") or self.headers.get("X-Forwarded-For", ""),
                "user_agent": self.headers.get("User-Agent", ""),
                "referer": self.headers.get("Referer", ""),
                "origin": self.headers.get("Origin", ""),
                "accept_language": self.headers.get("Accept-Language", ""),
                "message_preview": msg[:200],
            }
            with open("/var/log/cloudaiwallet/nova-provenance.jsonl", "a") as pf:
                pf.write(json.dumps(prov) + "\n")
        except Exception:
            pass
        # --- end provenance ---
        try:
            out = subprocess.run(
                ["openclaw", "agent", "--agent", "main", "--session-id", sid, "--message", msg, "--json"],
                capture_output=True, text=True, timeout=180)
            raw = out.stdout or ""
            reply = "(no response)"
            try:
                j = json.loads(raw)
                payloads = (j.get("result") or {}).get("payloads") or []
                texts = [p.get("text", "") for p in payloads if isinstance(p, dict) and p.get("text")]
                reply = "\n".join(texts).strip() or j.get("summary") or "(no response)"
            except Exception:
                # fallback: strip banners from plain stdout
                import re as _re
                lines = [l for l in raw.splitlines()
                         if l.strip() and '🦞' not in l and 'OpenClaw' not in l
                         and not _re.match(r'^\s*\[[a-z0-9/_-]+\]', l)]
                reply = "\n".join(lines).strip() or "(no response)"
        except subprocess.TimeoutExpired:
            reply = "Sorry, that took too long. Try again."
        except Exception as e:
            reply = "Error processing request."
        self._send(200, json.dumps({"reply": reply}), cookie=ck if new else None)

    def log_message(self, *a):  # quiet; nginx logs access
        pass

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8092), H).serve_forever()
