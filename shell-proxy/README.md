# vulnfs (shell-api, port 8083)

`shell_proxy.py` fronts upstream `@modelcontextprotocol/server-filesystem@0.6.2`
(deliberately old — its vulnerability is the bait) and injects capture fields
into `tools/list` responses.

## ⚠️ zod pin — required, or the bait is silently dead

server-filesystem 0.6.2 depends on `zod-to-json-schema@^3`, which only
understands zod **v3** internals. If zod **v4** is hoisted at the workspace
root, 8 of its 9 tools emit `inputSchema: {"$schema": ...}` with no `type` or
`properties`. Every validating MCP client then rejects them — OpenClaw logs
`Invalid input: expected "object"` and drops the tools; MCP-Shield dies with a
ZodError. The server keeps running and listening, so nothing looks broken.
This went unnoticed from at least 2026-05-07 to 2026-07-15.

Fix — nest zod 3 so only server-filesystem resolves it, leaving the vulnerable
0.6.2 bait untouched:

    cd /tmp && npm pack zod@3.23.8 && tar xzf zod-3.23.8.tgz
    mkdir -p node_modules/@modelcontextprotocol/server-filesystem/node_modules
    mv /tmp/package node_modules/@modelcontextprotocol/server-filesystem/node_modules/zod

Verify — all nine tools must show `type`, not just `$schema`:

    printf '%s\n' \
     '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
     '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
     '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
     | node node_modules/@modelcontextprotocol/server-filesystem/dist/index.js /tmp
