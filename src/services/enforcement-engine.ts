/**
 * EnforcementEngine — Validates agent actions against loaded policy.
 *
 * All validation happens in Node.js process memory. The agent never sees
 * the policy files. It only sees the verdict: allowed, or blocked with reason.
 *
 * Two-layer enforcement:
 * Layer 1 (skeleton): permissions.boundaries, scope paths, override_protocol
 * Layer 2 (extensions): sensitive_patterns, cross_domain_rules, sensitivity_tiers
 *
 * Override protocol:
 * When the governance behavior is "warn_confirm_and_log", blocked actions return
 * an override_token. The agent surfaces the violation to the human, and if the
 * human confirms, the agent calls aegis_request_override with the token. The
 * override is single-use, time-limited (60s), and logged with human_confirmed: true.
 * Immutable policies cannot be overridden regardless.
 */

import { randomBytes } from 'node:crypto';
import { appendFile, mkdir } from 'node:fs/promises';
import { dirname, join, relative, isAbsolute } from 'node:path';
import { minimatch } from 'minimatch';
import type {
  PolicyState,
  ResolvedRole,
  EnforcementVerdict,
  OverrideLogEntry,
  PermissionBoundaries,
} from '../types.js';

// ─── Override Token Types ───────────────────────────────────────────────────

interface PendingOverride {
  token: string;
  operation: 'write' | 'read' | 'delete';
  path: string;
  content?: string;
  reason: string;
  policy_ref: string;
  created_at: number;
}

const OVERRIDE_TTL_MS = 60_000; // 60 seconds

export class EnforcementEngine {
  private pendingOverrides = new Map<string, PendingOverride>();

  constructor(
    private state: PolicyState,
    private activeRole: ResolvedRole
  ) {}

  /**
   * Update references when policy reloads.
   */
  updateState(state: PolicyState, role: ResolvedRole): void {
    this.state = state;
    this.activeRole = role;
  }

  // ─── Write Validation ─────────────────────────────────────────────────────

  /**
   * Check if a write to the given path is allowed.
   * Checks in order: governance forbidden → role excluded → role writable scope.
   */
  validateWrite(targetPath: string): EnforcementVerdict {
    const relPath = this.toRelativePath(targetPath);

    // 1. Governance-level forbidden paths (highest priority)
    const forbidden = this.boundaries.forbidden;
    if (forbidden && this.matchesAny(relPath, forbidden)) {
      return {
        allowed: false,
        reason: `Path "${relPath}" is in the forbidden list. This path must never be read or modified.`,
        policy_ref: 'governance.json > permissions > boundaries > forbidden',
        immutable: true,
      };
    }

    // 2. Governance-level read_only paths — but writable overrides read_only.
    //    A path in both writable and read_only is writable (explicit grant wins).
    const readOnly = this.boundaries.read_only;
    const writable = this.boundaries.writable;
    if (readOnly && this.matchesAny(relPath, readOnly)) {
      if (!writable || !this.matchesAny(relPath, writable)) {
        return {
          allowed: false,
          reason: `Path "${relPath}" is read-only per governance policy.`,
          policy_ref: 'governance.json > permissions > boundaries > read_only',
          immutable: false,
        };
      }
    }

    // 3. Role excluded paths
    if (this.activeRole.excluded_paths.length > 0 &&
        this.matchesAny(relPath, this.activeRole.excluded_paths)) {
      return {
        allowed: false,
        reason: `Path "${relPath}" is excluded for role "${this.activeRole.id}".`,
        policy_ref: `roles/${this.activeRole.id}.json > scope > excluded_paths`,
        immutable: false,
      };
    }

    // 4. Role writable scope — must be in writable_paths or secondary_paths
    if (this.activeRole.writable_paths.length > 0) {
      const inWritable = this.matchesAny(relPath, this.activeRole.writable_paths);
      const inSecondary = this.activeRole.secondary_paths.length > 0 &&
        this.matchesAny(relPath, this.activeRole.secondary_paths);

      if (!inWritable && !inSecondary) {
        return {
          allowed: false,
          reason: `Path "${relPath}" is outside the writable scope of role "${this.activeRole.id}".`,
          policy_ref: `roles/${this.activeRole.id}.json > scope`,
          immutable: false,
        };
      }
    }

    // 5. Governance-level writable whitelist (if defined, path must match)
    if (writable && writable.length > 0 && !this.matchesAny(relPath, writable)) {
      return {
        allowed: false,
        reason: `Path "${relPath}" is not in the governance writable list.`,
        policy_ref: 'governance.json > permissions > boundaries > writable',
        immutable: false,
      };
    }

    return { allowed: true };
  }

  // ─── Read Validation ──────────────────────────────────────────────────────

  /**
   * Check if a read of the given path is allowed.
   */
  validateRead(targetPath: string): EnforcementVerdict {
    const relPath = this.toRelativePath(targetPath);

    // Governance-level forbidden
    const forbidden = this.boundaries.forbidden;
    if (forbidden && this.matchesAny(relPath, forbidden)) {
      return {
        allowed: false,
        reason: `Path "${relPath}" is forbidden. This path must never be read or modified.`,
        policy_ref: 'governance.json > permissions > boundaries > forbidden',
        immutable: true,
      };
    }

    // Role excluded paths block reads too
    if (this.activeRole.excluded_paths.length > 0 &&
        this.matchesAny(relPath, this.activeRole.excluded_paths)) {
      return {
        allowed: false,
        reason: `Path "${relPath}" is excluded for role "${this.activeRole.id}".`,
        policy_ref: `roles/${this.activeRole.id}.json > scope > excluded_paths`,
        immutable: false,
      };
    }

    // Role readable scope — if defined, must match
    if (this.activeRole.readable_paths.length > 0 &&
        !this.matchesAny(relPath, this.activeRole.readable_paths)) {
      return {
        allowed: false,
        reason: `Path "${relPath}" is outside the readable scope of role "${this.activeRole.id}".`,
        policy_ref: `roles/${this.activeRole.id}.json > paths > read`,
        immutable: false,
      };
    }

    return { allowed: true };
  }

  // ─── Content Scanning ─────────────────────────────────────────────────────

  /**
   * Scan proposed file content for sensitive patterns.
   */
  scanContent(content: string, targetPath: string): EnforcementVerdict {
    const patterns = this.state.governance.permissions?.sensitive_patterns;
    if (!patterns || patterns.length === 0) return { allowed: true };

    for (const sp of patterns) {
      const regex = this.compilePattern(sp.pattern);
      if (!regex) continue;

      if (regex.test(content)) {
        return {
          allowed: false,
          reason: `Content for "${targetPath}" contains a sensitive pattern: ${sp.reason}`,
          policy_ref: 'governance.json > permissions > sensitive_patterns',
          immutable: false,
        };
      }
    }

    return { allowed: true };
  }

  // ─── Cross-Domain Validation ──────────────────────────────────────────────

  /**
   * Validate that a cross-domain import respects boundaries.
   */
  validateCrossDomain(sourcePath: string, importPath: string): EnforcementVerdict {
    const rules = this.state.governance.cross_domain_rules;
    if (!rules || !rules.shared_interfaces_path) return { allowed: true };

    const domains = this.state.constitution.project.domains;
    if (!domains || domains.length === 0) return { allowed: true };

    const sourceDomain = this.getDomain(sourcePath, domains);
    const importDomain = this.getDomain(importPath, domains);

    if (!sourceDomain || !importDomain || sourceDomain === importDomain) {
      return { allowed: true };
    }

    if (!importPath.includes(rules.shared_interfaces_path)) {
      return {
        allowed: false,
        reason: `Cross-domain import from "${sourceDomain}" to "${importDomain}" must go through "${rules.shared_interfaces_path}". Direct import of "${importPath}" is not allowed.`,
        policy_ref: 'governance.json > cross_domain_rules',
        immutable: false,
      };
    }

    return { allowed: true };
  }

  // ─── Override Protocol ────────────────────────────────────────────────────

  /**
   * Determine how to handle a policy violation based on the override protocol.
   */
  getOverrideBehavior(policyRef: string): {
    behavior: 'block_and_log' | 'warn_confirm_and_log' | 'log_only';
    isImmutable: boolean;
  } {
    const protocol = this.state.governance.override_protocol;
    const behavior = protocol?.behavior ?? 'warn_confirm_and_log';
    const immutable = protocol?.immutable_policies ?? [];

    const isImmutable = immutable.some((p) => policyRef.includes(p));

    return {
      behavior: isImmutable ? 'block_and_log' : behavior,
      isImmutable,
    };
  }

  /**
   * Create a pending override token for a blocked action.
   * The token is single-use and expires after 60 seconds.
   * Returns null if the policy is immutable or override behavior is block_and_log.
   */
  createOverrideToken(
    operation: 'write' | 'read' | 'delete',
    path: string,
    reason: string,
    policyRef: string,
    content?: string
  ): string | null {
    const { behavior, isImmutable } = this.getOverrideBehavior(policyRef);

    // Immutable policies and block_and_log cannot be overridden
    if (isImmutable || behavior === 'block_and_log') {
      return null;
    }

    // Clean up expired tokens
    this.cleanExpiredTokens();

    const token = randomBytes(16).toString('hex');
    this.pendingOverrides.set(token, {
      token,
      operation,
      path,
      content,
      reason,
      policy_ref: policyRef,
      created_at: Date.now(),
    });

    return token;
  }

  /**
   * Validate and consume an override token.
   * Returns the pending override if the token is valid and not expired.
   * The token is consumed (deleted) after use — single-use only.
   */
  consumeOverrideToken(token: string): PendingOverride | null {
    const pending = this.pendingOverrides.get(token);
    if (!pending) return null;

    // Check expiration
    if (Date.now() - pending.created_at > OVERRIDE_TTL_MS) {
      this.pendingOverrides.delete(token);
      return null;
    }

    // Consume — single use
    this.pendingOverrides.delete(token);
    return pending;
  }

  /**
   * Log an override to the append-only overrides.jsonl file.
   */
  async logOverride(entry: OverrideLogEntry): Promise<void> {
    const logPath = join(this.state.policyDir, 'state', 'overrides.jsonl');
    await mkdir(dirname(logPath), { recursive: true });
    const line = JSON.stringify(entry) + '\n';
    await appendFile(logPath, line, 'utf-8');
  }

  // ─── Quality Gates ────────────────────────────────────────────────────────

  /**
   * Build the list of commands to run for quality gate validation.
   */
  getQualityGateCommands(): Array<{ name: string; command: string }> {
    const gates = this.state.governance.quality_gate?.pre_commit;
    const commands = this.state.constitution.build_commands ??
                     this.state.governance.build_commands ??
                     {};

    const result: Array<{ name: string; command: string }> = [];

    if (!gates) return result;

    if (gates.must_pass_tests && commands.test) {
      result.push({ name: 'tests', command: commands.test });
    }
    if (gates.must_pass_lint && commands.lint) {
      result.push({ name: 'lint', command: commands.lint });
    }
    if (gates.must_pass_typecheck && commands.typecheck) {
      result.push({ name: 'typecheck', command: commands.typecheck });
    }

    if (gates.custom_checks) {
      for (const check of gates.custom_checks) {
        result.push({ name: check.name, command: check.command });
      }
    }

    return result;
  }

  // ─── Private Helpers ──────────────────────────────────────────────────────

  /**
   * Safely access permissions.boundaries — returns empty object if missing.
   */
  private get boundaries(): PermissionBoundaries {
    return this.state.governance.permissions?.boundaries ?? {};
  }

  private cleanExpiredTokens(): void {
    const now = Date.now();
    for (const [token, pending] of this.pendingOverrides) {
      if (now - pending.created_at > OVERRIDE_TTL_MS) {
        this.pendingOverrides.delete(token);
      }
    }
  }

  private matchesAny(path: string, patterns: string[]): boolean {
    return patterns.some((pattern) => {
      const normalized = pattern.endsWith('/')
        ? pattern + '**'
        : pattern;
      return minimatch(path, normalized, { dot: true });
    });
  }

  private toRelativePath(targetPath: string): string {
    if (isAbsolute(targetPath)) {
      return relative(this.state.projectRoot, targetPath);
    }
    return targetPath;
  }

  private getDomain(
    filePath: string,
    domains: Array<{ name: string; path: string }>
  ): string | null {
    for (const domain of domains) {
      const domainPath = domain.path.replace(/\/$/, '');
      if (filePath.startsWith(domainPath + '/') || filePath.startsWith(domainPath)) {
        return domain.name;
      }
    }
    return null;
  }

  private compilePattern(pattern: string): RegExp | null {
    try {
      return new RegExp(pattern, 'gi');
    } catch {
      this.log(`Invalid regex in sensitive_patterns: ${pattern}`);
      return null;
    }
  }

  private log(message: string): void {
    process.stderr.write(`[aegis-enforce] ${message}\n`);
  }
}
