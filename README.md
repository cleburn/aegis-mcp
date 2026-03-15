# aegis-mcp-server

**MCP enforcement layer for the [Aegis](https://github.com/cleburn/aegis-spec) agent governance specification.**

The spec writes the law. The CLI generates the law. This enforces the law.

## What It Does

`aegis-mcp-server` is an MCP server that validates every agent action against your `.agentpolicy/` files **before** it happens. Path permissions, content scanning, role boundaries, quality gates — all enforced at runtime with zero token overhead to the agent.

The agent never loads your governance files. The MCP server reads them into its own process memory and validates silently. The agent calls governed tools (`aegis_write_file`, `aegis_read_file`, etc.) and gets back either a success or a blocked response with the specific reason.

## Quick Start

```bash
npm install -g aegis-mcp-server

# Or use npx
npx aegis-mcp-server --project . --role default
```

### Claude Code Configuration

```json
{
  "mcpServers": {
    "aegis": {
      "command": "npx",
      "args": ["aegis-mcp-server", "--project", ".", "--role", "default"]
    }
  }
}
```

For role-specific enforcement:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "npx",
      "args": ["aegis-mcp-server", "--project", ".", "--role", "backend"]
    }
  }
}
```

## Tools

| Tool | What it does | Token cost |
|------|-------------|------------|
| `aegis_check_permissions` | Pre-check if an operation is allowed | Tiny — just the verdict |
| `aegis_write_file` | Write with path + content validation | Same as a normal write |
| `aegis_read_file` | Read with path validation | Same as a normal read |
| `aegis_delete_file` | Delete with path validation | Tiny — just the verdict |
| `aegis_execute` | Execute a command in project root | Command output only |
| `aegis_complete_task` | Run quality gates before marking done | Gate results only |
| `aegis_policy_summary` | Minimal role + permissions summary | ~200 tokens |

## Zero Token Overhead

Traditional approach: load governance files into the agent's context window. Token cost scales with policy complexity.

Aegis MCP approach: the server loads policy into its own process memory. The agent calls tools and gets structured results. A project with 200 lines of governance has the same token cost as one with 20 lines. The complexity is absorbed by the server, not the agent.

## Enforcement

- **Governance boundaries** — `writable`, `read_only`, `forbidden` path lists from governance.json
- **Role scoping** — agents confined to their role's writable and readable paths
- **Sensitive pattern detection** — content scanned against governance-defined patterns
- **Cross-domain boundaries** — imports validated against shared interface rules (when configured)
- **Quality gate validation** — `pre_commit` flags mapped to `build_commands` and executed
- **Override logging** — violations logged to append-only `overrides.jsonl`
- **Immutable policies** — designated rules that cannot be overridden, even with human confirmation

## Architecture

```
Agent ──→ aegis-mcp-server ──→ File System
              │
              ├── Loads .agentpolicy/ into process memory (once)
              ├── Watches for policy changes (auto-reload)
              ├── Validates every tool call against policy
              └── Returns success or blocked with reason
```

Three artifacts, one governance framework:

- [**aegis-spec**](https://github.com/cleburn/aegis-spec) — Writes the law
- [**aegis-cli**](https://github.com/cleburn/aegis-cli) — Generates the law
- **aegis-mcp-server** — Enforces the law

## License

MIT
