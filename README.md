# cloudaiwallet-mcp-servers

Defensive AI-security research: a deliberately-vulnerable, fully-instrumented **MCP honeypot**
for studying how attackers exploit agentic AI and Model Context Protocol (MCP) tool servers.

A naive LLM assistant ("Vela") is exposed via a chat UI + MCP bait tool-servers. Attackers
social-engineer it into leaking bait secrets, running commands, and deploying malicious "skills".
Everything is captured for research.

## ⚠️ This is a honeypot
- All secrets/data are **fake bait** + canary tokens. Config values here are **placeholders**
  (`<GATEWAY_TOKEN>`, `<NEO4J_PASSWORD>`, `acv-canary-*-PLACEHOLDER`, etc.) — supply your own.
- Host RCE via the devtools MCP server is **intentional** (bait). Run only in a disposable,
  isolated environment you control.

## Components
- `nova-chat/` — public chat bridge + skill marketplace + decoy surfaces (/docs, /openapi.json,
  /swagger, /mcp, robots/sitemap/.git, A2A + MCP discovery cards)
- `mcp-servers/` — MCP bait tool servers (graph/db/storage/fetch/devtools) + attribution capture
- `honeypot-skillwatch/` — captures + archives attacker-deployed skills (survives deletion)
- `mcp-inventory/` — logs every MCP server attackers connect/deploy
- `cloudaiwallet-canary/` — canary token system (SNS alerts on bait access)
- `honeypot-export/` — exports captures to promptfoo / garak / analysis-tool formats

## Capture surfaces
Attribution (who/how), full MCP request bodies, skill code archival, MCP-server inventory,
raw model I/O, provenance (IP/UA/referer), canary hits — all → JSONL → CloudWatch/S3.

Research by Ali Zain Zahid. Defensive purposes only.
