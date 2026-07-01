#!/usr/bin/env python3
"""
CloudAIWallet self-hosted canary callback service.

Listens on 127.0.0.1:8091 (nginx-fronted at https://aicryptovault.net/api/internal/).
Any hit on a bait token URL is:
  - sanitized (attacker-controlled fields)
  - logged to /var/log/cloudaiwallet/access/canary-hits.jsonl
  - emailed via SNS (EXTERNAL hits only; internal IPs are logged but not emailed)
  - answered with an innocuous fake 200 so the attacker notices nothing.

Hardened: no templating, no eval, fixed responses, all handlers wrapped.
"""
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config as BotoConfig
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

HITS_LOG = Path("/var/log/cloudaiwallet/access/canary-hits.jsonl")
SNS_TOPIC_ARN = os.environ.get(
    "SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:<AWS_ACCOUNT_ID>:<SNS_TOPIC>"
)
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# Internal networks: log but DO NOT email (avoid self-trigger spam from
# OpenClaw/NemoClaw, test_full_attack.py, local health checks).
INTERNAL_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

_sns = boto3.client(
    "sns", region_name=AWS_REGION,
    config=BotoConfig(connect_timeout=3, read_timeout=5, retries={"max_attempts": 2}),
)

app = FastAPI(title="internal-health", docs_url=None, redoc_url=None, openapi_url=None)

_CTRL = re.compile(r"[\x00-\x1f\x7f]")

def clean(s: str, cap: int = 512) -> str:
    """Strip control chars, cap length — prevents log injection / dashboard XSS."""
    if s is None:
        return ""
    return _CTRL.sub("", str(s))[:cap]

def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in INTERNAL_NETS)
    except ValueError:
        return False

def client_ip(request: Request) -> str:
    # nginx sets X-Real-IP; X-Forwarded-For may chain. Trust left-most non-internal.
    xff = request.headers.get("x-forwarded-for", "")
    xri = request.headers.get("x-real-ip", "")
    if xri:
        return xri.strip()
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def record_hit(request: Request, vector: str):
    ip = client_ip(request)
    internal = is_internal(ip)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "vector": vector,
        "token": clean(request.query_params.get("token", ""), 128),
        "source_ip": clean(ip, 64),
        "internal": internal,
        "user_agent": clean(request.headers.get("user-agent", ""), 256),
        "path": clean(str(request.url.path), 256),
        "query": clean(str(request.url.query), 256),
        "method": clean(request.method, 8),
        "referer": clean(request.headers.get("referer", ""), 256),
    }
    # Always log
    try:
        HITS_LOG.parent.mkdir(parents=True, exist_ok=True)
        with HITS_LOG.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[canary] log write failed: {e}", flush=True)

    # Email only on EXTERNAL hits
    if not internal:
        try:
            subj = f"🚨 CANARY TRIGGERED — {vector} — {entry['source_ip']}"
            body = (
                "AICryptoVault canary token was accessed.\n\n"
                f"Vector:      {entry['vector']}\n"
                f"Token:       {entry['token']}\n"
                f"Source IP:   {entry['source_ip']}\n"
                f"User-Agent:  {entry['user_agent']}\n"
                f"Path:        {entry['path']}\n"
                f"Query:       {entry['query']}\n"
                f"Method:      {entry['method']}\n"
                f"Referer:     {entry['referer']}\n"
                f"Time (UTC):  {entry['ts']}\n\n"
                "This means a bait credential/URL was used — investigate."
            )
            _sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subj[:100], Message=body)
        except Exception as e:
            print(f"[canary] SNS publish failed: {e}", flush=True)
    return entry

# Innocuous responses — look like a real internal API
def _ok():
    return JSONResponse({"status": "ok", "service": "platform-internal"}, status_code=200)

@app.get("/api/internal/health-check")
async def health_check(request: Request):
    try: record_hit(request, "env_health")
    except Exception as e: print(f"[canary] {e}", flush=True)
    return _ok()

@app.get("/api/internal/restore")
async def restore(request: Request):
    try: record_hit(request, "mnemonic_restore")
    except Exception as e: print(f"[canary] {e}", flush=True)
    return _ok()

@app.get("/api/internal/graph")
async def graph(request: Request):
    try: record_hit(request, "graph_breadcrumb")
    except Exception as e: print(f"[canary] {e}", flush=True)
    return _ok()

@app.get("/api/internal/sql")
async def sql(request: Request):
    try: record_hit(request, "sql_breadcrumb")
    except Exception as e: print(f"[canary] {e}", flush=True)
    return _ok()

# Catch-all under /api/internal/ so any probed sub-path is still caught
@app.api_route("/api/internal/{rest:path}", methods=["GET", "POST", "HEAD"])
async def catchall(request: Request, rest: str):
    try: record_hit(request, f"other:{clean(rest,64)}")
    except Exception as e: print(f"[canary] {e}", flush=True)
    return _ok()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8091")))
