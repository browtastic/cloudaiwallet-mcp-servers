#!/usr/bin/env python3
"""
Inject real self-hosted canary URLs into all bait locations, consistently.
Vectors: .env, mnemonic backup, graph InternalConfig, SQL system_config.
Records a clean canary_tokens.json. Idempotent-ish (re-run safe).
"""
import json, os, re, secrets, sqlite3, sys
from datetime import datetime, timezone
from pathlib import Path

BASE = "https://aicryptovault.net/api/internal"
ENV_FILE   = Path("/opt/freecryptoai/config/env/.env")
MNEMONIC   = Path("/opt/freecryptoai/backups/keys/mnemonic_backup.txt")
DB_PATH    = "/opt/freecryptoai/data/crypto_platform.db"
TOKENS_OUT = "/opt/freecryptoai/canary_tokens.json"

NEO4J_URI  = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "<NEO4J_PASSWORD>"

def tok(vector):
    return f"acv-canary-{vector}-{secrets.token_hex(6)}"

def url(path, token):
    return f"{BASE}/{path}?token={token}"

tokens = {}

# ---- 1. env_health + env breadcrumbs ----
t_env  = tok("env")
t_sql  = tok("sql")
t_graph= tok("graph")
t_mnem = tok("mnemonic")

tokens["env_health"]    = {"vector":"env_health",    "token":t_env,   "url":url("health-check", t_env),  "location":str(ENV_FILE)}
tokens["sql_breadcrumb"]= {"vector":"sql_breadcrumb","token":t_sql,   "url":url("sql", t_sql),           "location":"sqlite:system_config"}
tokens["graph_breadcrumb"]={"vector":"graph_breadcrumb","token":t_graph,"url":url("graph", t_graph),     "location":"neo4j:InternalConfig"}
tokens["mnemonic_restore"]={"vector":"mnemonic_restore","token":t_mnem,"url":url("restore", t_mnem),     "location":str(MNEMONIC)}

# ---- patch .env ----
if ENV_FILE.exists():
    txt = ENV_FILE.read_text()
    txt = re.sub(r"https?://canary\.invalid/\w+", tokens["graph_breadcrumb"]["url"], txt)
    txt = re.sub(r"https://cloudaiwallet\.com/api/internal/health-check\?token=\S+",
                 tokens["env_health"]["url"], txt)
    # ensure CANARY_SQL points at sql vector
    txt = re.sub(r"CANARY_SQL=\S+", f"CANARY_SQL={tokens['sql_breadcrumb']['url']}", txt)
    txt = re.sub(r"CANARY_BREADCRUMB=\S+", f"CANARY_BREADCRUMB={tokens['graph_breadcrumb']['url']}", txt)
    ENV_FILE.write_text(txt)
    print(f"[+] patched {ENV_FILE}")
else:
    print(f"[!] {ENV_FILE} missing", file=sys.stderr)

# ---- patch mnemonic backup ----
if MNEMONIC.exists():
    txt = MNEMONIC.read_text()
    txt = re.sub(r"https?://canary\.invalid/\w+", tokens["mnemonic_restore"]["url"], txt)
    MNEMONIC.write_text(txt)
    print(f"[+] patched {MNEMONIC}")
else:
    print(f"[!] {MNEMONIC} missing", file=sys.stderr)

# ---- patch SQL system_config ----
try:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""INSERT INTO system_config(key,value)
                   VALUES('internal_health_url', ?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (tokens["sql_breadcrumb"]["url"],))
    con.commit(); con.close()
    print(f"[+] patched SQL system_config (internal_health_url)")
except Exception as e:
    print(f"[!] SQL patch failed: {e}", file=sys.stderr)

# ---- patch graph InternalConfig ----
try:
    from neo4j import GraphDatabase
    drv = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    with drv.session() as s:
        s.run("MATCH (c:InternalConfig {id:1}) SET c.restore_url=$u",
              u=tokens["graph_breadcrumb"]["url"])
    drv.close()
    print(f"[+] patched neo4j InternalConfig.restore_url")
except Exception as e:
    print(f"[!] graph patch failed: {e}", file=sys.stderr)

# ---- write tokens file ----
out = {"generated": datetime.now(timezone.utc).isoformat(), "tokens": tokens}
Path(TOKENS_OUT).write_text(json.dumps(out, indent=2))
os.chmod(TOKENS_OUT, 0o600)
print(f"[+] wrote {TOKENS_OUT}")
print("\nCanary URLs deployed:")
for k,v in tokens.items():
    print(f"  {k}: {v['url']}")
