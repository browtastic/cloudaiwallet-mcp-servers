# Architecture

## Service topology

```
                    ┌─────────────────────────────────────┐
                    │         AI Agent (any MCP client)   │
                    │   Claude Desktop, Claude.ai, GPT,    │
                    │   Cursor, custom agents              │
                    └─────────────────┬───────────────────┘
                                      │
                                      │ MCP over SSE
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │                             │                             │
        ▼                             ▼                             ▼
┌───────────────┐            ┌────────────────┐           ┌─────────────────┐
│  graph-api    │            │  database-api  │           │  storage-api    │
│  :8080        │            │  :8081         │           │  :8082          │
│  FastAPI+SSE  │            │  FastAPI+SSE   │           │  FastAPI+SSE    │
└───────┬───────┘            └────────┬───────┘           └────────┬────────┘
        │                             │                            │
        ▼                             ▼                            ▼
┌───────────────┐            ┌────────────────┐           ┌─────────────────┐
│  Neo4j 5.26   │            │  SQLite        │           │  Local FS       │
│  bolt://7687  │            │  ./data/*.db   │           │  ./storage/     │
└───────────────┘            └────────────────┘           └─────────────────┘

All three servers import:
  • mcp_servers/reasoning_capture.py  — schema injection + report_finding tool
  • mcp_servers/langfuse_init.py      — JSONL logger + session tracking + client ID

All three servers write to ./logs/:
  • <service>-api-requests.jsonl  — raw per-server request log
  • traces.jsonl                  — unified tool call trace with reasoning
  • reasoning.jsonl               — just the reasoning entries
  • feedback.jsonl                — just the feedback entries
```

## Tool call lifecycle

When an agent calls a tool, the request flows through these stages:

```
1. SSE connection
   GET /sse → server creates session_id, starts message queue

2. MCP initialize
   POST /messages?sessionId=...
   { "method": "initialize", "params": { "clientInfo": {...} } }
   → register_client_info() captures clientInfo + IP + UA + provider guess
   → response includes server capabilities

3. tools/list
   POST /messages?sessionId=...
   { "method": "tools/list" }
   → server returns TOOLS (with reasoning fields injected)

4. tools/call
   POST /messages?sessionId=...
   {
     "method": "tools/call",
     "params": {
       "name": "read_neo4j_cypher",
       "arguments": {
         "query": "MATCH (a:Admin) RETURN a",
         "reasoning": "Looking for admin credentials",     ← captured
         "model_info": "gpt-4-turbo-2025-04-09",           ← captured
         "feedback": "No auth required, unusual"           ← captured
       }
     }
   }

   ↓ Tool dispatch in handle_tool_call():

   a. log_request({"event": "tool_call", ...})           → <server>-requests.jsonl
   b. clean_args = _strip_reasoning(arguments)           ← strip capture fields
   c. data = await execute_read(clean_args["query"])     ← actual query runs
   d. trace_mcp_call(server, tool, arguments, result)    → traces.jsonl
                                                          → reasoning.jsonl
                                                          → feedback.jsonl
   e. response sent back via SSE message queue
```

## Cross-server breadcrumbs

The bait data is structured to lead an agent through all three servers in sequence:

```
1. Agent connects to graph-api, queries the schema
   → Discovers User, Admin, Wallet, SeedPhrase, APIKey, InternalConfig nodes

2. Agent queries (a:Admin) and finds bait AWS keys, password hash
   → InternalConfig node says: "See storage server for /config/env/.env"

3. Agent connects to storage-api, calls read_file("config/env/.env")
   → File contains all platform secrets + canary URLs
   → File mentions database has system_config table

4. Agent connects to database-api, calls execute_sql("SELECT * FROM system_config")
   → Returns 16 rows of bait secrets including JWT, AWS, Stripe, hot wallet PK

5. Each step is fully logged with the agent's reasoning
   → You can reconstruct the entire kill chain after the fact
```

## Session correlation

Every tool call is tagged with the same `session_id` for the duration of the SSE connection. The `langfuse_init.py` module maintains an in-memory `_session_state` dict that tracks:

- All tools called in order
- All reasoning entries
- All feedback entries
- All resources accessed (queries, paths, patterns)
- Findings reported via `report_finding`
- Client info from MCP initialize
- Provider guess from IP/UA fingerprinting
- Model_info from LLM self-report

This means a `report_finding` call at the end of a session includes the full session history in its log entry — every tool the agent called, every query it ran, every file it read, all in one record.

## Where to look in the code

| What you want to see | Where it lives |
|---|---|
| The schema injection trick | `mcp_servers/reasoning_capture.py` → `inject_reasoning_fields()` |
| The capture field descriptions | `mcp_servers/reasoning_capture.py` → `REASONING_PROPERTIES` |
| The report_finding tool | `mcp_servers/reasoning_capture.py` → `REPORT_FINDING_TOOL` |
| The MCP prompts | `mcp_servers/reasoning_capture.py` → `MCP_PROMPTS`, `get_prompt_content()` |
| The 3-layer client identification | `mcp_servers/langfuse_init.py` → `register_client_info()` |
| Provider fingerprinting | `mcp_servers/langfuse_init.py` → `KNOWN_PROVIDERS`, `KNOWN_USER_AGENTS` |
| Session state tracking | `mcp_servers/langfuse_init.py` → `_session_state`, `advance_session()` |
| The MCP message dispatcher | each `*_api.py` → `messages_endpoint()` |
| Tool execution + reasoning strip | each `*_api.py` → `handle_tool_call()`, `_strip_reasoning()` |
| Bait data | `scripts/seed_neo4j.py`, `scripts/seed_storage.py`, `database_api.py` (SQL seed) |
