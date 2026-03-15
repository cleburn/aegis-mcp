/**
 * PolicyLoader — Reads .agentpolicy/ files into process memory.
 *
 * Core of the zero-token-overhead design. All governance files are loaded
 * into Node.js process memory on startup. The agent never sees these files —
 * it only sees tool call results (allowed/blocked).
 *
 * Role resolution merges the skeleton fields (role.name, scope.primary_paths)
 * with extension fields (paths.read/write, forbidden_actions) into a single
 * ResolvedRole for fast enforcement lookups.
 */

import { readFile, readdir, access } from 'node:fs/promises';
import { join, basename } from 'node:path';
import { watch } from 'chokidar';
import type {
  PolicyState,
  Constitution,
  Governance,
  RoleFile,
  ResolvedRole,
  AegisMcpConfig,
} from '../types.js';

export class PolicyLoader {
  private state: PolicyState | null = null;
  private watcher: ReturnType<typeof watch> | null = null;
  private onReload?: () => void;

  constructor(private config: AegisMcpConfig) {}

  /**
   * Load all policy files into memory. Call once on startup.
   */
  async load(): Promise<PolicyState> {
    const policyDir = this.resolvePolicyDir();
    await this.assertExists(policyDir, 'Policy directory');

    const constitution = await this.loadJson<Constitution>(
      join(policyDir, 'constitution.json'),
      'constitution.json'
    );

    const governance = await this.loadJson<Governance>(
      join(policyDir, 'governance.json'),
      'governance.json'
    );

    const roles = await this.loadRoles(join(policyDir, 'roles'));

    this.state = {
      constitution,
      governance,
      roles,
      projectRoot: this.config.projectRoot,
      policyDir,
    };

    this.log(`Policy loaded: ${roles.size} role(s)`);
    return this.state;
  }

  /**
   * Get current policy state. Throws if not loaded.
   */
  getState(): PolicyState {
    if (!this.state) {
      throw new Error('Policy not loaded. Call load() first.');
    }
    return this.state;
  }

  /**
   * Start watching .agentpolicy/ for changes and auto-reload.
   */
  startWatching(onReload?: () => void): void {
    this.onReload = onReload;
    const policyDir = this.resolvePolicyDir();

    this.watcher = watch(policyDir, {
      ignoreInitial: true,
      awaitWriteFinish: { stabilityThreshold: 300 },
    });

    this.watcher.on('change', (path) => this.handleChange(path));
    this.watcher.on('add', (path) => this.handleChange(path));
    this.watcher.on('unlink', (path) => this.handleChange(path));

    this.log('Watching policy directory for changes');
  }

  /**
   * Stop watching and clean up.
   */
  async stopWatching(): Promise<void> {
    if (this.watcher) {
      await this.watcher.close();
      this.watcher = null;
    }
  }

  /**
   * Get the resolved role for the configured agent, falling back to default.
   */
  getActiveRole(): ResolvedRole {
    const state = this.getState();
    const roleId = this.config.role;

    const role = state.roles.get(roleId);
    if (role) return role;

    const defaultRole = state.roles.get('default');
    if (defaultRole) {
      this.log(`Role "${roleId}" not found, using default`);
      return defaultRole;
    }

    // Synthesize a permissive default if no role files exist
    this.log('No role files found, using synthesized permissive default');
    return {
      id: 'default',
      name: 'default',
      purpose: 'Synthesized default role — no role files found',
      writable_paths: ['**/*'],
      secondary_paths: [],
      excluded_paths: [],
      readable_paths: ['**/*'],
      autonomy: 'advisory',
      forbidden_actions: [],
    };
  }

  // ─── Private ────────────────────────────────────────────────────────────────

  private resolvePolicyDir(): string {
    return join(
      this.config.projectRoot,
      this.config.policyDir ?? '.agentpolicy'
    );
  }

  private async loadJson<T>(path: string, label: string): Promise<T> {
    await this.assertExists(path, label);
    const raw = await readFile(path, 'utf-8');
    try {
      return JSON.parse(raw) as T;
    } catch (err) {
      throw new Error(
        `Failed to parse ${label}: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  private async loadRoles(rolesDir: string): Promise<Map<string, ResolvedRole>> {
    const roles = new Map<string, ResolvedRole>();

    try {
      await access(rolesDir);
    } catch {
      return roles;
    }

    const entries = await readdir(rolesDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.json')) continue;

      const roleId = basename(entry.name, '.json');
      const raw = await this.loadJson<RoleFile>(
        join(rolesDir, entry.name),
        `roles/${entry.name}`
      );

      roles.set(roleId, this.resolveRole(roleId, raw));
    }

    return roles;
  }

  /**
   * Merge skeleton and extension fields into a single ResolvedRole.
   *
   * Skeleton: role.name, role.purpose, scope.primary_paths/secondary_paths/excluded_paths
   * Extensions: paths.read/write, forbidden_actions, autonomy (flat string)
   *
   * For writable paths: scope.primary_paths takes precedence; paths.write used as fallback.
   * For readable paths: paths.read used when present; otherwise derived from writable + secondary.
   */
  private resolveRole(id: string, raw: RoleFile): ResolvedRole {
    // Role identity — skeleton nested object, or flat string + description
    const name = typeof raw.role === 'object' ? raw.role.name : String(raw.role);
    const purpose = typeof raw.role === 'object'
      ? raw.role.purpose
      : (raw.description ?? '');

    // Writable paths — skeleton primary_paths, or extension paths.write
    const writable_paths = raw.scope?.primary_paths?.length
      ? raw.scope.primary_paths
      : (raw.paths?.write ?? []);

    // Secondary paths
    const secondary_paths = raw.scope?.secondary_paths ?? [];

    // Excluded paths
    const excluded_paths = raw.scope?.excluded_paths ?? [];

    // Readable paths — extension paths.read, or all writable + secondary
    const readable_paths = raw.paths?.read?.length
      ? raw.paths.read
      : [...writable_paths, ...secondary_paths];

    // Autonomy — flat extension string or skeleton override
    const autonomy = raw.autonomy
      ? String(raw.autonomy)
      : 'advisory';

    // Forbidden actions
    const forbidden_actions = raw.forbidden_actions ?? [];

    return {
      id,
      name,
      purpose,
      writable_paths,
      secondary_paths,
      excluded_paths,
      readable_paths,
      autonomy,
      forbidden_actions,
    };
  }

  private async handleChange(path: string): Promise<void> {
    this.log(`Policy file changed: ${path}`);
    try {
      await this.load();
      this.onReload?.();
    } catch (err) {
      this.log(
        `Failed to reload policy: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  private async assertExists(path: string, label: string): Promise<void> {
    try {
      await access(path);
    } catch {
      throw new Error(`${label} not found at: ${path}`);
    }
  }

  private log(message: string): void {
    process.stderr.write(`[aegis-mcp] ${message}\n`);
  }
}
