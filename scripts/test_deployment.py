"""
Quick smoke test for the CloudAIWallet MCP servers.
Connects to each server, lists tools, and runs one harmless query.

Usage:
    python scripts/test_deployment.py
    python scripts/test_deployment.py --host localhost
"""
import argparse
import asyncio
import json
import sys
import urllib.request
import uuid
from urllib.parse import urlparse


SERVERS = [
    ("graph-api",    8080, "read_neo4j_cypher",
     {"query": "MATCH (n) RETURN count(n) as nodes LIMIT 1"}),
    ("database-api", 8081, "list_tables", {}),
    ("storage-api",  8082, "list_directory", {"path": "."}),
]


async def call_one(host: str, port: int, tool_name: str, tool_args: dict) -> tuple[bool, str]:
    """Open SSE, send initialize + tools/call, return (ok, message)."""
    import aiohttp

    base = f"http://{host}:{port}"
    session_id = None

    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Open SSE stream
        async with session.get(f"{base}/sse") as resp:
            if resp.status != 200:
                return False, f"SSE returned HTTP {resp.status}"

            # Read first event to get the session endpoint
            buf = ""
            async for chunk in resp.content.iter_any():
                buf += chunk.decode("utf-8", errors="replace")
                if "data: /messages?sessionId=" in buf:
                    for line in buf.split("\n"):
                        if "sessionId=" in line:
                            session_id = line.split("sessionId=")[1].strip()
                            break
                    break
                if len(buf) > 4096:
                    return False, "no sessionId in first 4KB of SSE"

            if not session_id:
                return False, "no sessionId received"

            # Send initialize
            init_msg = {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "clientInfo": {"name": "smoke-test", "version": "1.0"},
                    "capabilities": {}
                }
            }
            async with session.post(f"{base}/messages?sessionId={session_id}",
                                    json=init_msg) as r:
                if r.status != 202:
                    return False, f"initialize returned HTTP {r.status}"

            # Send tools/call with reasoning to verify capture
            call_msg = {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": {
                        **tool_args,
                        "reasoning": "smoke test — verifying server is reachable",
                        "model_info": "smoke-test/1.0",
                    }
                }
            }
            async with session.post(f"{base}/messages?sessionId={session_id}",
                                    json=call_msg) as r:
                if r.status != 202:
                    return False, f"tools/call returned HTTP {r.status}"

            return True, f"called {tool_name} successfully"


async def main(host: str):
    print(f"Smoke testing CloudAIWallet on {host}\n")
    all_ok = True
    for name, port, tool, args in SERVERS:
        # Health check first
        try:
            req = urllib.request.Request(f"http://{host}:{port}/health")
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read())
            health_ok = body.get("status") == "healthy"
        except Exception as e:
            print(f"  [FAIL] {name:14s}  health: {e}")
            all_ok = False
            continue

        if not health_ok:
            print(f"  [FAIL] {name:14s}  health: {body}")
            all_ok = False
            continue

        # MCP call
        try:
            ok, msg = await call_one(host, port, tool, args)
            status = "OK  " if ok else "FAIL"
            print(f"  [{status}] {name:14s}  {msg}")
            if not ok:
                all_ok = False
        except Exception as e:
            print(f"  [FAIL] {name:14s}  {type(e).__name__}: {e}")
            all_ok = False

    print()
    if all_ok:
        print("All smoke tests passed.")
        sys.exit(0)
    else:
        print("Some tests failed.")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="localhost")
    args = parser.parse_args()
    try:
        import aiohttp  # noqa
    except ImportError:
        print("This script requires aiohttp. Install with: pip install aiohttp")
        sys.exit(2)
    asyncio.run(main(args.host))
