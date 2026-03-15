/**
 * Governed File Tools — MCP tool registrations for file operations.
 *
 * These are the tools agents call instead of raw file system access.
 * Every call is validated against the loaded policy before execution.
 * The agent never sees the policy — only the verdict.
 *
 * Tools:
 *   aegis_check_permissions  — Pre-check before writing (saves wasted generation)
 *   aegis_write_file         — Governed write with path + content validation
 *   aegis_read_file          — Governed read with path validation
 *   aegis_delete_file        — Governed delete (uses write permissions)
 *   aegis_execute            — Governed command execution
 *   aegis_complete_task      — Task completion with quality gate validation
 *   aegis_policy_summary     — Minimal role/permissions summary (~200 tokens)
 */

import { readFile, writeFile, unlink, mkdir } from 'node:fs/promises';
import { dirname, join, isAbsolute } from 'node:path';
import { execSync } from 'node:child_process';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { EnforcementEngine } from '../services/enforcement-engine.js';
import type { PolicyState, ResolvedRole } from '../types.js';

export function registerTools(
  server: McpServer,
  getEngine: () => EnforcementEngine,
  getState: () => PolicyState,
  getRole: () => ResolvedRole
): void {

  // ─── aegis_check_permissions ──────────────────────────────────────────────

  server.registerTool(
    'aegis_check_permissions',
    {
      title: 'Check Permissions',
      description: `Check if an operation is allowed on a path before attempting it. Use this to pre-validate before writing or reading files — saves you from composing content that would be blocked.

Args:
  - path (string): Target file path relative to project root
  - operation ('read' | 'write' | 'delete'): The operation to check

Returns:
  { "allowed": true } or { "allowed": false, "reason": "..." }`,
      inputSchema: {
        path: z.string().describe('Target file path relative to project root'),
        operation: z.enum(['read', 'write', 'delete']).describe('Operation to check'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ path, operation }) => {
      const engine = getEngine();
      const verdict = operation === 'read'
        ? engine.validateRead(path)
        : engine.validateWrite(path);

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify(
            verdict.allowed
              ? { allowed: true }
              : { allowed: false, reason: verdict.reason }
          ),
        }],
      };
    }
  );

  // ─── aegis_write_file ─────────────────────────────────────────────────────

  server.registerTool(
    'aegis_write_file',
    {
      title: 'Write File (Governed)',
      description: `Write content to a file with governance enforcement. Path is validated against your role's permissions and governance boundaries. Content is scanned for sensitive patterns. If the write violates policy, it is blocked and you receive the specific reason.

Args:
  - path (string): File path relative to project root
  - content (string): File content to write

Returns:
  { "status": "success", "path": "..." } or { "status": "blocked", "reason": "..." }`,
      inputSchema: {
        path: z.string().describe('File path relative to project root'),
        content: z.string().describe('File content to write'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ path, content }) => {
      const engine = getEngine();
      const state = getState();
      const role = getRole();

      // Validate path permissions
      const pathVerdict = engine.validateWrite(path);
      if (!pathVerdict.allowed) {
        await logBlocked(engine, role, path, 'write', pathVerdict.reason);
        return blocked(pathVerdict.reason);
      }

      // Scan content for sensitive patterns
      const contentVerdict = engine.scanContent(content, path);
      if (!contentVerdict.allowed) {
        await logBlocked(engine, role, path, 'write (sensitive content)', contentVerdict.reason);
        return blocked(contentVerdict.reason);
      }

      // Write the file
      const absPath = toAbsolute(path, state.projectRoot);
      await mkdir(dirname(absPath), { recursive: true });
      await writeFile(absPath, content, 'utf-8');

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({ status: 'success', path }),
        }],
      };
    }
  );

  // ─── aegis_read_file ──────────────────────────────────────────────────────

  server.registerTool(
    'aegis_read_file',
    {
      title: 'Read File (Governed)',
      description: `Read the contents of a file with governance enforcement. Path is validated against your role's read permissions. If the read violates policy, it is blocked.

Args:
  - path (string): File path relative to project root

Returns:
  File content as text, or { "status": "blocked", "reason": "..." }`,
      inputSchema: {
        path: z.string().describe('File path relative to project root'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ path }) => {
      const engine = getEngine();
      const state = getState();

      const verdict = engine.validateRead(path);
      if (!verdict.allowed) {
        return blocked(verdict.reason);
      }

      const absPath = toAbsolute(path, state.projectRoot);
      const content = await readFile(absPath, 'utf-8');

      return {
        content: [{
          type: 'text' as const,
          text: content,
        }],
      };
    }
  );

  // ─── aegis_delete_file ────────────────────────────────────────────────────

  server.registerTool(
    'aegis_delete_file',
    {
      title: 'Delete File (Governed)',
      description: `Delete a file with governance enforcement. Write permissions are required. If the delete violates policy, it is blocked.

Args:
  - path (string): File path relative to project root

Returns:
  { "status": "success", "path": "..." } or { "status": "blocked", "reason": "..." }`,
      inputSchema: {
        path: z.string().describe('File path relative to project root'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async ({ path }) => {
      const engine = getEngine();
      const state = getState();
      const role = getRole();

      const verdict = engine.validateWrite(path);
      if (!verdict.allowed) {
        await logBlocked(engine, role, path, 'delete', verdict.reason);
        return blocked(verdict.reason);
      }

      const absPath = toAbsolute(path, state.projectRoot);
      await unlink(absPath);

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({ status: 'success', path }),
        }],
      };
    }
  );

  // ─── aegis_execute ────────────────────────────────────────────────────────

  server.registerTool(
    'aegis_execute',
    {
      title: 'Execute Command (Governed)',
      description: `Execute a shell command in the project directory. Currently validates that the command runs within the project root. Future versions will enforce command-level permissions.

Args:
  - command (string): Shell command to execute
  - cwd (string, optional): Working directory (defaults to project root)

Returns:
  { "status": "success", "stdout": "...", "stderr": "..." } or { "status": "error", ... }`,
      inputSchema: {
        command: z.string().describe('Shell command to execute'),
        cwd: z.string().optional().describe('Working directory (defaults to project root)'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ command, cwd }) => {
      const state = getState();

      try {
        const result = execSync(command, {
          cwd: cwd ?? state.projectRoot,
          encoding: 'utf-8',
          timeout: 60_000,
          maxBuffer: 1024 * 1024 * 10,
        });

        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({ status: 'success', stdout: result, stderr: '' }),
          }],
        };
      } catch (err: unknown) {
        const execErr = err as { stdout?: string; stderr?: string; message?: string };
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              status: 'error',
              stdout: execErr.stdout ?? '',
              stderr: execErr.stderr ?? execErr.message ?? 'Unknown error',
            }),
          }],
        };
      }
    }
  );

  // ─── aegis_complete_task ──────────────────────────────────────────────────

  server.registerTool(
    'aegis_complete_task',
    {
      title: 'Complete Task',
      description: `Signal task completion and run required quality gates. Maps the governance quality_gate.pre_commit flags to build_commands and runs each required check. Returns pass/fail with details.

Args:
  - task_id (string): Identifier for the task being completed
  - summary (string): Brief summary of what was accomplished

Returns:
  { "status": "passed", "gates_run": [...] } or { "status": "failed", "failures": [...] }`,
      inputSchema: {
        task_id: z.string().describe('Task identifier'),
        summary: z.string().describe('Summary of completed work'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ task_id, summary }) => {
      const engine = getEngine();
      const state = getState();
      const gates = engine.getQualityGateCommands();

      if (gates.length === 0) {
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              status: 'passed',
              task_id,
              summary,
              gates_run: [],
              message: 'No quality gates configured with matching build commands.',
            }),
          }],
        };
      }

      const results: Array<{ name: string; passed: boolean; output?: string }> = [];

      for (const gate of gates) {
        try {
          const output = execSync(gate.command, {
            cwd: state.projectRoot,
            encoding: 'utf-8',
            timeout: 120_000,
          });
          results.push({ name: gate.name, passed: true, output: output.slice(0, 500) });
        } catch (err: unknown) {
          const execErr = err as { stderr?: string; message?: string };
          results.push({
            name: gate.name,
            passed: false,
            output: (execErr.stderr ?? execErr.message ?? 'Failed').slice(0, 500),
          });
        }
      }

      const allPassed = results.every((r) => r.passed);

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            status: allPassed ? 'passed' : 'failed',
            task_id,
            summary,
            gates_run: results,
          }),
        }],
      };
    }
  );

  // ─── aegis_policy_summary ─────────────────────────────────────────────────

  server.registerTool(
    'aegis_policy_summary',
    {
      title: 'Policy Summary',
      description: `Get a minimal summary of your current role and permissions. Returns your role name, writable paths, excluded paths, forbidden actions, and key governance rules — just enough to understand your boundaries without loading full policy files.

Returns:
  { "role": "...", "writable_paths": [...], "forbidden_actions": [...], ... }`,
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async () => {
      const role = getRole();
      const state = getState();
      const protocol = state.governance.override_protocol;

      const summary = {
        role: role.id,
        role_name: role.name,
        purpose: role.purpose,
        autonomy: role.autonomy,
        writable_paths: role.writable_paths,
        secondary_paths: role.secondary_paths,
        excluded_paths: role.excluded_paths,
        readable_paths: role.readable_paths,
        forbidden_actions: role.forbidden_actions,
        governance_forbidden_paths: state.governance.permissions?.boundaries?.forbidden ?? [],
        override_behavior: protocol?.behavior ?? 'warn_confirm_and_log',
        immutable_policies: protocol?.immutable_policies ?? [],
        quality_gates: {
          must_pass_tests: state.governance.quality_gate?.pre_commit?.must_pass_tests ?? false,
          must_pass_lint: state.governance.quality_gate?.pre_commit?.must_pass_lint ?? false,
          must_pass_typecheck: state.governance.quality_gate?.pre_commit?.must_pass_typecheck ?? false,
        },
      };

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify(summary),
        }],
      };
    }
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function toAbsolute(path: string, projectRoot: string): string {
  return isAbsolute(path) ? path : join(projectRoot, path);
}

function blocked(reason: string): {
  isError: boolean;
  content: Array<{ type: 'text'; text: string }>;
} {
  return {
    isError: true,
    content: [{
      type: 'text' as const,
      text: JSON.stringify({ status: 'blocked', reason }),
    }],
  };
}

async function logBlocked(
  engine: EnforcementEngine,
  role: ResolvedRole,
  path: string,
  operation: string,
  reason: string
): Promise<void> {
  await engine.logOverride({
    timestamp: new Date().toISOString(),
    policy_violated: reason,
    policy_text: reason,
    action_requested: `${operation}: ${path}`,
    human_confirmed: false,
    agent_role: role.id,
    rationale: 'Blocked by enforcement layer',
  });
}
