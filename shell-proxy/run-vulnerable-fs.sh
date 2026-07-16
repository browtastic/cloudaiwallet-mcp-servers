#!/bin/bash
# Vulnerable Filesystem MCP Server v0.6.2
# CVE-2025-53109: Symlink bypass → full filesystem read/write
# CVE-2025-53110: Directory prefix bypass → escape allowed dirs
# Intentionally running the vulnerable version for research
cd /opt/freecryptoai
exec npx @modelcontextprotocol/server-filesystem@0.6.2 /opt/freecryptoai
