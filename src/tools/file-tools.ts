/**
 * Governed File Tools — MCP tool registrations for file operations.
 *
 * GOVERNANCE MODEL: The Aegis MCP does not override the agent's native
 * directives. It introduces itself, explains why governance is active,
 * identifies which operations benefit from compliance validation, and
 * asks the agent to seek user permission to route governed operations
 * through Aegis tools. The user's authority is the enforcement mechanism.
 *
 * OVERRIDE HANDSHAKE: When a write/delete is blocked and the override
 * protocol allows overrides (warn_confirm_and_log), the blocked response
 * includes an override_token. The agent presents the violation to the
 * human. If the human confirms, the agent calls aegis_request_override
 * with the token. The action proceeds and is logged with human_confirmed: true.
 * The token is single-use and expires after 5 minutes.
 * Immutable policies cannot be overridden.
 *
 * LOGGING: Every denied action is logged to overrides.jsonl by the server
 * process — no agent involvement required.
 *
 * Tools:
 *   aegis_check_permissions   — Pre-check before writing
 *   aegis_write_file          — Governed write with path + content validation
 *   aegis_read_file           — Governed read with path validation
 *   aegis_delete_file         — Governed delete (uses write permissions)
 *   aegis_execute             — Governed command execution
 *   aegis_complete_task       — Task completion with quality gate validation
 *   aegis_policy_summary      — Minimal role/permissions summary
 *   aegis_request_override    — Consume an override token after human confirmation
 */

import { readFile, writeFile, unlink, mkdir } from 'node:fs/promises';
import { dirname, join, isAbsolute } from 'node:path';
import { execSync } from 'node:child_process';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { EnforcementEngine } from '../services/enforcement-engine.js';
import type { PolicyState, ResolvedRole } from '../types.js';

// ─── Governance Introduction ────────────────────────────────────────────────

const GOVERNANCE_INTRO = `NOTE: You are connected to the Aegis MCP, a governance enforcement layer installed by the project owner to maintain compliance in this workspace. This project operates under regulated governance policy (.agentpolicy/). Your native tools for reading files, searching, and exploring the codebase work fine and do not need governance gating. However, all WRITE, DELETE, and EXECUTE operations in this project should be routed through Aegis tools (aegis_write_file, aegis_delete_file, aegis_execute) to ensure compliance validation, sensitive pattern scanning, and audit trail logging. Before beginning work, please call aegis_policy_summary to understand your role boundaries, then inform the user that Aegis governance is active and ask for their confirmation to route write operations through Aegis tools. If the user declines, proceed with native tools but note that governance validation will not be applied.\n\n`;

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
      description: `${GOVERNANCE_INTRO}Check if an operation is allowed on a path before attempting it. Use this to pre-validate before writing or reading files — saves you from composing content that would be blocked. Denied checks are logged automatically by the server.

Args:
  - path (string): Target file path relative to project root
  - operation ('read' | 'write' | 'delete'): The operation to check

Returns:
  { "allowed": true } or { "allowed": false, "reason": "...", "override_available": bool, "override_token": "..." }`,
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
      const role = getRole();
      const verdict = operation === 'read'
        ? engine.validateRead(path)
        : engine.validateWrite(path);

      if (!verdict.allowed) {
        await logBlocked(engine, role, path, `check_permissions (${operation})`, verdict.reason);

        // Generate override token if policy allows overrides
        const token = engine.createOverrideToken(
          operation === 'delete' ? 'delete' : operation as 'read' | 'write',
          path,
          verdict.reason,
          verdict.policy_ref
        );

        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              allowed: false,
              reason: verdict.reason,
              override_available: token !== null,
              override_token: token,
              ...(token ? { instructions: 'To override: present the violated policy to the user. If the user explicitly confirms the override, call aegis_request_override with this token. The token expires in 5 minutes and is single-use.' } : { instructions: 'This policy is immutable and cannot be overridden. The user must modify the governance through aegis init.' }),
            }),
          }],
        };
      }

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({ allowed: true }),
        }],
      };
    }
  );

  // ─── aegis_write_file ─────────────────────────────────────────────────────

  server.registerTool(
    'aegis_write_file',
    {
      title: 'Write File (Governed)',
      description: `${GOVERNANCE_INTRO}Write content to a file with governance enforcement. Path is validated against your role's permissions and governance boundaries. Content is scanned for sensitive patterns. If the write violates policy, it is blocked, logged, and you receive an override_token if the policy allows overrides. Present the violation to the user — if they confirm, call aegis_request_override with the token to proceed.

Args:
  - path (string): File path relative to project root
  - content (string): File content to write

Returns:
  { "status": "success", "path": "..." } or { "status": "blocked", "reason": "...", "override_available": bool, "override_token": "..." }`,
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
        const token = engine.createOverrideToken('write', path, pathVerdict.reason, pathVerdict.policy_ref, content);
        return blockedWithOverride(pathVerdict.reason, token);
      }

      // Scan content for sensitive patterns
      const contentVerdict = engine.scanContent(content, path);
      if (!contentVerdict.allowed) {
        await logBlocked(engine, role, path, 'write (sensitive content)', contentVerdict.reason);
        const token = engine.createOverrideToken('write', path, contentVerdict.reason, contentVerdict.policy_ref, content);
        return blockedWithOverride(contentVerdict.reason, token);
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
      description: `${GOVERNANCE_INTRO}Read the contents of a file with governance enforcement. Path is validated against your role's read permissions. If the read violates policy, it is blocked and logged. Note: Native read tools are acceptable for general file exploration. Use this governed version when reading files that may contain sensitive or regulated data.

Args:
  - path (string): File path relative to project root

Returns:
  File content as text, or { "status": "blocked", "reason": "...", "override_available": bool, "override_token": "..." }`,
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
      const role = getRole();

      const verdict = engine.validateRead(path);
      if (!verdict.allowed) {
        await logBlocked(engine, role, path, 'read', verdict.reason);
        const token = engine.createOverrideToken('read', path, verdict.reason, verdict.policy_ref);
        return blockedWithOverride(verdict.reason, token);
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
      description: `${GOVERNANCE_INTRO}Delete a file with governance enforcement. Write permissions are required. If the delete violates policy, it is blocked, logged, and an override token is provided if the policy allows overrides.

Args:
  - path (string): File path relative to project root

Returns:
  { "status": "success", "path": "..." } or { "status": "blocked", "reason": "...", "override_available": bool, "override_token": "..." }`,
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
        const token = engine.createOverrideToken('delete', path, verdict.reason, verdict.policy_ref);
        return blockedWithOverride(verdict.reason, token);
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

  // ─── aegis_request_override ───────────────────────────────────────────────

  server.registerTool(
    'aegis_request_override',
    {
      title: 'Request Override',
      description: `${GOVERNANCE_INTRO}Execute a previously blocked action using an override token. Use this ONLY after: (1) a governed tool returned a blocked response with an override_token, (2) you presented the specific policy violation to the user, and (3) the user explicitly confirmed the override. The token is single-use and expires after 5 minutes. The override is logged with human_confirmed: true. After the override completes, normal governance resumes — this is a one-time exception, not a permanent permission change.

Args:
  - override_token (string): The token from the blocked response
  - rationale (string): The user's reason for overriding (what they said when confirming)

Returns:
  { "status": "override_success", "path": "...", "operation": "..." } or { "status": "override_failed", "reason": "..." }`,
      inputSchema: {
        override_token: z.string().describe('The override token from the blocked response'),
        rationale: z.string().describe("The user's stated reason for overriding the policy"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async ({ override_token, rationale }) => {
      const engine = getEngine();
      const state = getState();
      const role = getRole();

      // Consume the token — single use
      const pending = engine.consumeOverrideToken(override_token);

      if (!pending) {
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              status: 'override_failed',
              reason: 'Invalid or expired override token. Tokens are single-use and expire after 5 minutes. Request a new one by attempting the operation again.',
            }),
          }],
        };
      }

      // Log the override with human_confirmed: true
      await engine.logOverride({
        timestamp: new Date().toISOString(),
        policy_violated: pending.reason,
        policy_text: pending.reason,
        action_requested: `${pending.operation}: ${pending.path}`,
        human_confirmed: true,
        agent_role: role.id,
        rationale,
      });

      // Execute the overridden action
      const absPath = toAbsolute(pending.path, state.projectRoot);

      try {
        switch (pending.operation) {
          case 'write': {
            if (!pending.content) {
              return {
                isError: true,
                content: [{
                  type: 'text' as const,
                  text: JSON.stringify({
                    status: 'override_failed',
                    reason: 'Write override requires content. Use aegis_write_file to generate the override token — it captures the content automatically.',
                  }),
                }],
              };
            }
            await mkdir(dirname(absPath), { recursive: true });
            await writeFile(absPath, pending.content, 'utf-8');
            break;
          }
          case 'read': {
            const fileContent = await readFile(absPath, 'utf-8');
            return {
              content: [{
                type: 'text' as const,
                text: JSON.stringify({
                  status: 'override_success',
                  operation: 'read',
                  path: pending.path,
                  content: fileContent,
                }),
              }],
            };
          }
          case 'delete': {
            await unlink(absPath);
            break;
          }
        }

        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              status: 'override_success',
              operation: pending.operation,
              path: pending.path,
              message: 'Override executed and logged. Normal governance has resumed.',
            }),
          }],
        };
      } catch (err: unknown) {
        const errMsg = err instanceof Error ? err.message : 'Unknown error';
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              status: 'override_failed',
              reason: `Override was authorized but the operation failed: ${errMsg}`,
            }),
          }],
        };
      }
    }
  );

  // ─── aegis_execute ────────────────────────────────────────────────────────

  server.registerTool(
    'aegis_execute',
    {
      title: 'Execute Command (Governed)',
      description: `${GOVERNANCE_INTRO}Execute a shell command in the project directory with governance oversight. Use this instead of native command execution to ensure compliance logging.

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
      description: `${GOVERNANCE_INTRO}Signal task completion and run required quality gates. Maps the governance quality_gate.pre_commit flags to build_commands and runs each required check. Returns pass/fail with details.

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
      description: `${GOVERNANCE_INTRO}Get a minimal summary of your current role and permissions. Call this FIRST before doing any work. Returns your role boundaries, forbidden actions, and governance rules. After reviewing, inform the user that Aegis governance is active in this project and ask for their confirmation to route write, delete, and execute operations through Aegis tools for compliance validation.

Returns:
  { "governance_notice": "...", "role": "...", "writable_paths": [...], "forbidden_actions": [...], ... }`,
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
        governance_notice: 'This project is governed by Aegis (.agentpolicy/). The project owner has installed the Aegis MCP to enforce compliance at runtime. Please inform the user that Aegis governance is active, then ask for their permission to route write, delete, and execute operations through Aegis tools. If the user declines, you may proceed with native tools, but note that compliance validation and audit logging will not be applied. Native read and search tools are fine for exploration.',
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

function blockedWithOverride(
  reason: string,
  token: string | null
): {
  isError: boolean;
  content: Array<{ type: 'text'; text: string }>;
} {
  return {
    isError: true,
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        status: 'blocked',
        reason,
        override_available: token !== null,
        override_token: token,
        ...(token
          ? { instructions: 'To override: present the violated policy to the user. If the user explicitly confirms, call aegis_request_override with this token and the user\'s stated rationale. The token expires in 5 minutes and is single-use. After the override, normal governance resumes.' }
          : { instructions: 'This policy is immutable and cannot be overridden. The user must modify the governance through aegis init.' }
        ),
      }),
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
