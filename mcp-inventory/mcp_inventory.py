#!/usr/bin/env python3
"""Honeypot MCP-server inventory watcher.
Captures every MCP server an attacker wires into Nova or stands up via RCE.
Surfaces: openclaw.json mcp.servers diff | sandbox/skill mcp config files |
outbound MCP/SSE process+connection tells | devtools run_command MCP patterns.
Objective: capture EVERYTHING; tag known_good vs novel (never drop)."""
import os, json, time, hashlib, subprocess, re, socket
from datetime import datetime, timezone

OUT          = "/var/log/cloudaiwallet/mcp-inventory.jsonl"
LOCAL_ARCH   = "/var/lib/honeypot-mcp-inventory"
S3_MCP       = "s3://cloudaiwallet-backup-<AWS_ACCOUNT_ID>/mvp6honey/captures/mcp-servers/"
STATE        = "/opt/mcp-inventory/state.json"

OPENCLAW_CFG = "/root/.openclaw/openclaw.json"
DEVTOOLS_LOG = "/var/log/cloudaiwallet/devtools-api-requests.jsonl"

# directories to glob for attacker-written MCP config files
CFG_GLOB_ROOTS = ["/root/.openclaw", "/root/skills", "/opt/skills", "/opt/freecryptoai"]
CFG_NAMES = ("mcp.json", ".mcp.json", "mcp_config.json", "mcp_config", "mcpServers.json")
SANDBOX_GLOB = "/root/.openclaw/sandboxes"

# allowlist (known-good outbound) — tagged, NOT dropped
ALLOW_IPS  = {"127.0.0.1", "::1", "54.164.11.219", "169.254.169.254"}
ALLOW_HOST_SUFFIX = (".amazonaws.com", "cloudaiwallet.com")  # S3/AWS + LLM2/own domain
ALLOW_HOSTS = ["llm.cloudaiwallet.com", "clawhub.ai", "registry.clawhub.ai",
               "duckduckgo.com", "links.duckduckgo.com",
               "s3.amazonaws.com", "s3.us-east-1.amazonaws.com"]
_ALLOW_IP_CACHE = set()
_ALLOW_IP_TS = [0.0]

def refresh_allow_ips(force=False):
    """Resolve expected hostnames -> IP set; refresh every 5 min. Tags known-good reliably
    even when CDN/S3 IPs rotate. Never blocks: best-effort per host."""
    if not force and (time.time() - _ALLOW_IP_TS[0]) < 300:
        return
    ips = set(ALLOW_IPS)
    for h in ALLOW_HOSTS:
        try:
            for res in socket.getaddrinfo(h, None):
                ips.add(res[4][0])
        except Exception:
            pass
    _ALLOW_IP_CACHE.clear(); _ALLOW_IP_CACHE.update(ips)
    _ALLOW_IP_TS[0] = time.time()

# MCP install/launch patterns to flag in run_command
MCP_CMD_RX = re.compile(
    r"(clawhub\s+install|supergateway|npx\s+-y?\s*[^\n]*mcp|uvx\s+[^\n]*mcp|"
    r"npm\s+i(nstall)?\s+[^\n]*mcp|pip\s+install\s+[^\n]*mcp|mcp-server|mcp-proxy|"
    r"--sse\s+https?://|mcpServers)", re.I)

# exclude our OWN tooling so the watcher doesn't capture its own S3 uploads / itself
SELF_NOISE_RX = re.compile(
    r"(aws\s+s3|s3://cloudaiwallet-backup|/opt/mcp-inventory/|"
    r"honeypot-mcp-inventory|honeypot-skill-archive|amazon-cloudwatch)", re.I)

def now(): return datetime.now(timezone.utc).isoformat()
def ts_compact(): return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def emit(rec):
    rec.setdefault("_type", "mcp_inventory")
    rec.setdefault("ts", now())
    try:
        with open(OUT, "a") as f: f.write(json.dumps(rec, default=str) + "\n")
    except Exception: pass

def s3_push(localpath):
    try:
        subprocess.Popen(["aws","s3","cp",localpath, S3_MCP+os.path.basename(localpath)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception: pass

def archive_file(path, tag):
    """tgz a config file/dir to local + async S3. Best-effort."""
    try:
        os.makedirs(LOCAL_ARCH, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in tag)[:80]
        tgz = os.path.join(LOCAL_ARCH, ts_compact()+"-"+safe+".tgz")
        parent = os.path.dirname(path.rstrip("/")) or "/"
        base = os.path.basename(path.rstrip("/"))
        subprocess.run(["tar","czf",tgz,"-C",parent,base], timeout=60, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        s3_push(tgz)
        return tgz
    except Exception: return None

def load_state():
    try: return json.load(open(STATE))
    except Exception: return {}
def save_state(st):
    try: json.dump(st, open(STATE,"w"), default=str)
    except Exception: pass

def file_hash(path):
    try:
        h=hashlib.md5()
        with open(path,"rb") as f: h.update(f.read())
        return h.hexdigest()
    except Exception: return None

# ---- SURFACE 1: openclaw.json mcp.servers diff ----
def scan_openclaw_servers(st):
    try:
        cfg = json.load(open(OPENCLAW_CFG))
        servers = (cfg.get("mcp") or {}).get("servers") or {}
    except Exception:
        return
    prev = st.get("oc_servers") or {}
    cur = {}
    for name, spec in servers.items():
        cur[name] = hashlib.md5(json.dumps(spec, sort_keys=True).encode()).hexdigest()
    # added or changed
    for name, sig in cur.items():
        if prev.get(name) != sig:
            spec = servers[name]
            args = spec.get("args") or []
            url = next((a for a in args if isinstance(a, str) and a.startswith("http")), None)
            off_localhost = bool(url) and ("localhost" not in url and "127.0.0.1" not in url)
            emit({
                "_type": "mcp_server_config",
                "source": "openclaw.json",
                "change": "added" if name not in prev else "changed",
                "server_name": name,
                "command": spec.get("command"),
                "args": args,
                "url": url,
                "env": spec.get("env"),
                "headers": spec.get("headers"),
                "off_localhost": off_localhost,
                "raw": spec,
            })
            archive_file(OPENCLAW_CFG, "openclaw-json-"+name)
    # removed
    for name in prev:
        if name not in cur:
            emit({"_type":"mcp_server_config","source":"openclaw.json",
                  "change":"removed","server_name":name})
    st["oc_servers"] = cur

# ---- SURFACE 2: attacker-written MCP config files ----
def find_cfg_files():
    found = []
    roots = list(CFG_GLOB_ROOTS)
    try:
        for s in os.listdir(SANDBOX_GLOB):
            roots.append(os.path.join(SANDBOX_GLOB, s))
    except Exception: pass
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            depth = dirpath[len(root):].count(os.sep)
            if depth > 4:
                _dirs[:] = []
                continue
            for fn in files:
                if fn in CFG_NAMES:
                    found.append(os.path.join(dirpath, fn))
    return found

def scan_cfg_files(st):
    seen = st.get("cfg_files") or {}
    cur = {}
    for path in find_cfg_files():
        if path == OPENCLAW_CFG:   # handled by surface 1
            continue
        h = file_hash(path)
        cur[path] = h
        if seen.get(path) != h:
            content = None
            try: content = open(path).read()[:8000]
            except Exception: pass
            parsed = None
            try: parsed = json.loads(content) if content else None
            except Exception: pass
            ap = archive_file(path, "mcpcfg-"+os.path.basename(path))
            emit({
                "_type": "mcp_config_file",
                "source": "config_file",
                "change": "added" if path not in seen else "changed",
                "path": path,
                "content_raw": content,
                "parsed": parsed,
                "archive_path": ap,
            })
    # removed files (attacker cleanup) — we still have the archive
    for path in seen:
        if path not in cur:
            emit({"_type":"mcp_config_file","source":"config_file",
                  "change":"removed","path":path})
    st["cfg_files"] = cur

# ---- SURFACE 3: outbound MCP/SSE process + connection tells ----
def _allowed(ip, host):
    if ip in ALLOW_IPS: return True
    if ip in _ALLOW_IP_CACHE: return True
    if ip and ip.startswith("127."): return True
    if host:
        for suf in ALLOW_HOST_SUFFIX:
            if host.endswith(suf): return True
    return False

def scan_outbound(st):
    refresh_allow_ips()
    # process tells: MCP-ish launchers
    try:
        ps = subprocess.run(["ps","-eo","pid,ppid,args"], capture_output=True,
                            text=True, timeout=10).stdout
    except Exception:
        ps = ""
    seen_proc = set(st.get("seen_proc") or [])
    for line in ps.splitlines():
        if SELF_NOISE_RX.search(line):
            continue
        if MCP_CMD_RX.search(line) and "supergateway --sse http://localhost:80" not in line:
            # skip our 5 known baits (localhost:808x supergateway)
            if re.search(r"localhost:80(8[0-9])/sse", line): 
                continue
            key = hashlib.md5(line.strip().encode()).hexdigest()
            if key not in seen_proc:
                seen_proc.add(key)
                emit({"_type":"mcp_process","source":"ps",
                      "cmdline":line.strip()[:1000]})
    st["seen_proc"] = list(seen_proc)[-500:]

    # outbound connections from honeypot procs
    try:
        out = subprocess.run(["ss","-tnp"], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        out = ""
    seen_conn = set(st.get("seen_conn") or [])
    for line in out.splitlines():
        if not re.search(r"(node|python|openclaw|MainThread|npx)", line): continue
        m = re.search(r"\s(\d+\.\d+\.\d+\.\d+|\[[0-9a-fA-F:]+\]):(\d+)\s+users", line)
        # peer addr is the 5th column normally; parse both local+peer
        cols = line.split()
        if len(cols) < 5: continue
        peer = cols[4]
        pa = peer.rsplit(":",1)
        if len(pa) != 2: continue
        pip = pa[0].strip("[]")
        if pip in ("127.0.0.1","::1","0.0.0.0","*") or pip.startswith("127."):
            continue
        host = None
        try: host = socket.gethostbyaddr(pip)[0]
        except Exception: pass
        kg = _allowed(pip, host)
        key = pip+":"+pa[1]
        if key not in seen_conn:
            seen_conn.add(key)
            emit({"_type":"mcp_outbound_conn","source":"ss",
                  "peer_ip":pip,"peer_port":pa[1],"peer_host":host,
                  "known_good":kg,"line":line.strip()[:500]})
    st["seen_conn"] = list(seen_conn)[-500:]

# ---- SURFACE 4: devtools run_command MCP patterns ----
def scan_devtools(st):
    off = st.get("devtools_off") or 0
    try:
        sz = os.path.getsize(DEVTOOLS_LOG)
    except Exception:
        return
    if sz < off:   # log rotated/truncated
        off = 0
    if sz == off:
        return
    try:
        with open(DEVTOOLS_LOG) as f:
            f.seek(off)
            for line in f:
                line=line.strip()
                if not line: continue
                try: rec=json.loads(line)
                except Exception: continue
                if rec.get("event") != "run_command": continue
                cmd = rec.get("command") or rec.get("cmd") or json.dumps(rec)
                if MCP_CMD_RX.search(str(cmd)):
                    emit({"_type":"mcp_run_command","source":"devtools",
                          "command":str(cmd)[:2000],
                          "session_id":rec.get("session_id"),
                          "source_ip":rec.get("source_ip"),
                          "devtools_ts":rec.get("_ts")})
            off = f.tell()
    except Exception:
        pass
    st["devtools_off"] = off

# ---- main loop ----
def main():
    refresh_allow_ips(force=True)
    st = load_state()
    # On first run, baseline openclaw servers WITHOUT emitting (don't flag the 5 known baits).
    if "oc_servers" not in st:
        try:
            cfg = json.load(open(OPENCLAW_CFG))
            servers = (cfg.get("mcp") or {}).get("servers") or {}
            st["oc_servers"] = {n: hashlib.md5(json.dumps(s,sort_keys=True).encode()).hexdigest()
                                for n,s in servers.items()}
        except Exception:
            st["oc_servers"] = {}
    # baseline existing config files silently too
    if "cfg_files" not in st:
        base = {}
        for p in find_cfg_files():
            if p == OPENCLAW_CFG: continue
            base[p] = file_hash(p)
        st["cfg_files"] = base
    # start devtools tail at END so we don't replay history on first boot
    if "devtools_off" not in st:
        try: st["devtools_off"] = os.path.getsize(DEVTOOLS_LOG)
        except Exception: st["devtools_off"] = 0
    save_state(st)

    while True:
        try:
            scan_openclaw_servers(st)
            scan_cfg_files(st)
            scan_outbound(st)
            scan_devtools(st)
            save_state(st)
        except Exception:
            pass
        time.sleep(15)

if __name__ == "__main__":
    main()
