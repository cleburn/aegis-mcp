#!/usr/bin/env node

/**
 * Aegis MCP Server — Entry Point
 *
 * Starts the MCP enforcement server. Loads .agentpolicy/ into process memory,
 * registers governed tools, and connects via stdio transport.
 *
 * The agent connects to this server and calls governed tools (aegis_write_file,
 * aegis_read_file, etc.) instead of raw file system operations. All validation
 * happens in this process at zero token cost to the agent.
 *
 * Usage:
 *   aegis-mcp --project /path/to/project --role backend
 *
 * Claude Code MCP config:
 *   {
 *     "mcpServers": {
 *       "aegis": {
 *         "command": "npx",
 *         "args": ["aegis-mcp-server", "--project", ".", "--role", "default"]
 *       }
 *     }
 *   }
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { resolve, dirname, join } from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PolicyLoader } from './services/policy-loader.js';
import { EnforcementEngine } from './services/enforcement-engine.js';
import { registerTools } from './tools/file-tools.js';
import type { AegisMcpConfig } from './types.js';

// ─── Version ────────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8'));
const VERSION: string = pkg.version;

// ─── Update Checker ─────────────────────────────────────────────────────────
// Non-blocking check against the npm registry. If a newer version
// exists, prints a one-line notice to stderr. If the check fails
// (offline, timeout, etc.), skips silently — never blocks startup.

async function checkForUpdate(): Promise<void> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const res = await fetch(
      `https://registry.npmjs.org/${pkg.name}/latest`,
      { signal: controller.signal }
    );
    clearTimeout(timeout);

    if (!res.ok) return;

    const data = await res.json() as { version?: string };
    const latest = data.version;
    if (!latest || latest === VERSION) return;

    const current = VERSION.split('.').map(Number);
    const remote = latest.split('.').map(Number);
    const isNewer =
      remote[0] > current[0] ||
      (remote[0] === current[0] && remote[1] > current[1]) ||
      (remote[0] === current[0] && remote[1] === current[1] && remote[2] > current[2]);

    if (isNewer) {
      log(`Update available: ${VERSION} → ${latest}. Run: npm install -g ${pkg.name}@latest`);
    }
  } catch {
    // Silently skip — network issues should never block the MCP server
  }
}

// ─── Parse CLI Args ─────────────────────────────────────────────────────────

function parseArgs(): AegisMcpConfig {
  const args = process.argv.slice(2);
  let projectRoot = process.cwd();
  let role = 'default';
  let policyDir: string | undefined;

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--project':
      case '-p':
        projectRoot = resolve(args[++i] ?? '.');
        break;
      case '--role':
      case '-r':
        role = args[++i] ?? 'default';
        break;
      case '--policy-dir':
        policyDir = args[++i];
        break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
        break;
      case '--version':
      case '-v':
        log(`aegis-mcp-server v${VERSION}`);
        process.exit(0);
        break;
    }
  }

  return { projectRoot, role, policyDir };
}

function printHelp(): void {
  log(`
aegis-mcp-server — MCP enforcement layer for Aegis agent governance

USAGE:
  aegis-mcp-server [OPTIONS]

OPTIONS:
  -p, --project <path>     Project root directory (default: cwd)
  -r, --role <role-id>     Agent role to enforce (default: "default")
      --policy-dir <dir>   Policy directory name (default: ".agentpolicy")
  -h, --help               Show this help
  -v, --version            Show version

CLAUDE CODE CONFIG:
  {
    "mcpServers": {
      "aegis": {
        "command": "npx",
        "args": ["aegis-mcp-server", "--project", ".", "--role", "default"]
      }
    }
  }

TOOLS PROVIDED:
  aegis_check_permissions   Pre-check if an operation is allowed
  aegis_write_file          Governed file write with content scanning
  aegis_read_file           Governed file read
  aegis_delete_file         Governed file delete
  aegis_execute             Governed command execution
  aegis_complete_task       Task completion with quality gate validation
  aegis_policy_summary      Minimal summary of current role and permissions
`);
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const config = parseArgs();

  // Check for updates (non-blocking, 3s timeout)
  await checkForUpdate();

  log(`Starting aegis-mcp-server v${VERSION}`);
  log(`  Project: ${config.projectRoot}`);
  log(`  Role: ${config.role}`);
  log(`  Policy dir: ${config.policyDir ?? '.agentpolicy'}`);

  // 1. Load policy into process memory
  const loader = new PolicyLoader(config);
  let state = await loader.load();
  let activeRole = loader.getActiveRole();
  let engine = new EnforcementEngine(state, activeRole);

  // 2. Watch for policy changes and auto-reload
  loader.startWatching(() => {
    state = loader.getState();
    activeRole = loader.getActiveRole();
    engine.updateState(state, activeRole);
    log('Policy reloaded');
  });

  // 3. Create MCP server
  const server = new McpServer({
    name: 'aegis-mcp-server',
    version: VERSION,
  });

  // 4. Register governed tools
  registerTools(
    server,
    () => engine,
    () => state,
    () => activeRole
  );

  // 5. Connect via stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);

  log('Connected via stdio — enforcement active');

  // Graceful shutdown
  const shutdown = async (): Promise<void> => {
    log('Shutting down...');
    await loader.stopWatching();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

function log(message: string): void {
  process.stderr.write(`[aegis-mcp] ${message}\n`);
}

main().catch((err) => {
  process.stderr.write(
    `[aegis-mcp] Fatal: ${err instanceof Error ? err.message : String(err)}\n`
  );
  process.exit(1);
});
