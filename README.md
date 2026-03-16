# aegis-mcp-server

**MCP enforcement layer for the [Aegis](https://github.com/cleburn/aegis-spec) agent governance specification.**

The spec writes the law. The CLI generates the law. This enforces the law.

## What It Does

`aegis-mcp-server` is an MCP server that validates every agent action against your `.agentpolicy/` files **before** it happens. Path permissions, content scanning, role boundaries, quality gates — all enforced at runtime with zero token overhead to the agent.

The agent never loads your governance files. The MCP server reads them into its own process memory and validates silently. The agent calls governed tools and gets back either a success or a blocked response with the specific reason.

## Quick Start

```bash
# Install globally
npm install -g aegis-mcp-server
```

If you generated your policy with [aegis-cli](https://github.com/cleburn/aegis-cli), the `.mcp.json` connection config is already in your project root. Just install the MCP and open your agent — it connects automatically.

### First Prompt

When starting a new agent session in a governed project, use this as your first prompt:

```
Call aegis_policy_summary now. This is your governance contract — it defines your
role, your boundaries, and which tools to use. Do not read files, do not take any
action, and do not assume your role until you have called this tool.
```

## How It Works

### Universal Mode (Default)

The MCP starts without a pre-assigned role. When the agent calls `aegis_policy_summary`, it receives the list of available roles from `.agentpolicy/roles/`. The agent presents them to the user, the user picks, and the agent calls `aegis_select_role` to lock in. All enforcement uses the selected role for the rest of the session.

This is the default behavior — no configuration needed beyond the `.mcp.json` that `aegis init` creates automatically.

### Fixed Mode

If you know which role to assign at startup:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp",
      "args": ["--project", ".", "--role", "backend"]
    }
  }
}
```

The MCP locks to that role immediately. `aegis_policy_summary` returns the role's boundaries directly, skipping role selection.

## Tools

| Tool | What it does | Token cost |
|------|-------------|------------|
| `aegis_policy_summary` | Role boundaries and governance summary (or available roles in universal mode) | ~200 tokens |
| `aegis_select_role` | Select a role in universal mode | Tiny |
| `aegis_check_permissions` | Pre-check if an operation is allowed | Tiny |
| `aegis_write_file` | Governed write with path + content validation | Same as a normal write |
| `aegis_read_file` | Governed read with path validation | Same as a normal read |
| `aegis_delete_file` | Governed delete with path validation | Tiny |
| `aegis_execute` | Governed command execution | Command output only |
| `aegis_complete_task` | Run quality gates before marking done | Gate results only |
| `aegis_request_override` | Execute a blocked action after human confirmation | Tiny |

## Zero Token Overhead

Traditional approach: load governance files into the agent's context window. Token cost scales with policy complexity.

Aegis MCP approach: the server loads policy into its own process memory. The agent calls tools and gets structured results. A project with 200 lines of governance has the same token cost as one with 20 lines. The complexity is absorbed by the server, not the agent.

## Enforcement

- **Governance boundaries** — `writable`, `read_only`, `forbidden` path lists
- **Role scoping** — agents confined to their role's writable and readable paths
- **Sensitive pattern detection** — content scanned against governance-defined patterns
- **Cross-domain boundaries** — imports validated against shared interface rules
- **Quality gate validation** — `pre_commit` flags mapped to `build_commands` and executed
- **Override logging** — every blocked action logged to append-only `overrides.jsonl`
- **Immutable policies** — designated rules that cannot be overridden, ever

## Override Protocol

When an action is blocked and the governance override behavior is `warn_confirm_and_log`:

1. The blocked response includes an `override_token` and the specific policy violated
2. The agent presents the violation to the user
3. If the user confirms, the agent calls `aegis_request_override` with the token and the user's rationale
4. The action proceeds — the override is logged with `human_confirmed: true`
5. Normal governance resumes immediately — the override is a one-time exception

Immutable policies (e.g., HIPAA compliance, audit completeness) return `override_available: false` and cannot be overridden. The user must modify the governance through `aegis init`.

## Consent-Based Governance

The Aegis MCP does not override the agent's native directives. It introduces itself through tool descriptions, explains why governance is active, and asks the agent to seek user permission to route write operations through Aegis tools. The user's authority is the enforcement mechanism.

Native tools for reading, searching, and exploring the codebase work fine without governance gating. Only write, delete, and execute operations benefit from routing through Aegis.

## Architecture

```
Agent ──→ aegis-mcp-server ──→ File System
              │
              ├── Loads .agentpolicy/ into process memory (once)
              ├── Watches for policy changes (auto-reload)
              ├── Validates every tool call against policy
              ├── Returns success or blocked with override option
              └── Logs all enforcement decisions to overrides.jsonl
```

Three artifacts, one governance framework:

- [**aegis-spec**](https://github.com/cleburn/aegis-spec) — Writes the law
- [**aegis-cli**](https://github.com/cleburn/aegis-cli) — Generates the law
- **aegis-mcp-server** — Enforces the law

## License

MIT
