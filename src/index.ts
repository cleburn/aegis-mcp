#!/usr/bin/env node

/**
 * Aegis MCP Server — Entry Point
 *
 * Starts the MCP enforcement server. Loads .agentpolicy/ into process memory,
 * registers governed tools, and connects via stdio transport.
 *
 * Universal mode (default): No --role flag. The agent calls aegis_policy_summary
 * on connection, sees available roles, presents them to the user, and the user
 * selects a role. The MCP locks to that role for the session.
 *
 * Fixed mode: --role <id> locks to a specific role at startup.
 *
 * Usage:
 *   aegis-mcp --project /path/to/project
 *   aegis-mcp --project /path/to/project --role backend
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
    // Silently skip
  }
}

// ─── Parse CLI Args ─────────────────────────────────────────────────────────

function parseArgs(): AegisMcpConfig {
  const args = process.argv.slice(2);
  let projectRoot = process.cwd();
  let role = 'auto'; // Universal mode by default
  let policyDir: string | undefined;

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--project':
      case '-p':
        projectRoot = resolve(args[++i] ?? '.');
        break;
      case '--role':
      case '-r':
        role = args[++i] ?? 'auto';
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
  -r, --role <role-id>     Agent role to enforce (default: "auto" — agent selects at runtime)
      --policy-dir <dir>   Policy directory name (default: ".agentpolicy")
  -h, --help               Show this help
  -v, --version            Show version

UNIVERSAL MODE (default):
  aegis-mcp --project .

  No --role flag. The agent calls aegis_policy_summary, sees available roles,
  presents them to the user, and the user selects. The MCP locks to that role
  for the session.

FIXED MODE:
  aegis-mcp --project . --role backend

  Locks to a specific role at startup.

TOOLS PROVIDED:
  aegis_check_permissions   Pre-check if an operation is allowed
  aegis_write_file          Governed file write with content scanning
  aegis_read_file           Governed file read
  aegis_delete_file         Governed file delete
  aegis_execute             Governed command execution
  aegis_complete_task       Task completion with quality gate validation
  aegis_policy_summary      Role boundaries and governance summary
  aegis_select_role         Select a role (universal mode only)
  aegis_request_override    Execute a blocked action with human confirmation
`);
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const config = parseArgs();

  await checkForUpdate();

  log(`Starting aegis-mcp-server v${VERSION}`);
  log(`  Project: ${config.projectRoot}`);
  log(`  Role: ${config.role === 'auto' ? 'auto (agent selects at runtime)' : config.role}`);
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

  // 4. Register governed tools — pass loader for role selection support
  registerTools(
    server,
    () => engine,
    () => state,
    () => activeRole,
    loader,
    (role) => {
      // Callback when role is selected in auto mode
      activeRole = role;
      engine.updateState(state, role);
      log(`Role locked: ${role.id}`);
    }
  );

  // 5. Connect via stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);

  log('Connected via stdio — enforcement active');

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
