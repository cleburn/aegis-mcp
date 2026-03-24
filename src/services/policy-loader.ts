/**
 * PolicyLoader — Reads .agentpolicy/ files into process memory.
 *
 * Core of the zero-token-overhead design. All governance files are loaded
 * into Node.js process memory on startup. The agent never sees these files.
 *
 * Supports "auto" role mode: when config.role is "auto" (or not specified),
 * no role is locked at startup. The agent selects a role at runtime via
 * aegis_select_role, and all enforcement uses the selected role thereafter.
 *
 * Construction mode: The "construction" role is always available for initial
 * builds and major restructuring. It grants full repo access using native
 * tools, with governance files serving as the blueprint. The MCP logs the
 * session start and end to overrides.jsonl for audit trail purposes.
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

// ─── Construction Role (synthetic, always available) ────────────────────────

const CONSTRUCTION_ROLE: ResolvedRole = {
  id: 'construction',
  name: 'Construction',
  purpose: 'Initial build or major restructuring — full repo access using native tools, governance files serve as blueprint. MCP logs the session but does not enforce write restrictions. Select this for greenfield builds or significant overhauls.',
  writable_paths: ['**/*'],
  secondary_paths: [],
  excluded_paths: [],
  readable_paths: ['**/*'],
  autonomy: 'delegated',
  forbidden_actions: [],
};

export class PolicyLoader {
  private state: PolicyState | null = null;
  private watcher: ReturnType<typeof watch> | null = null;
  private onReload?: () => void;
  private selectedRole: ResolvedRole | null = null;
  private constructionMode = false;
  private constructionStartedAt: string | null = null;

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
   * Whether the MCP is in auto role mode (no role pre-assigned).
   */
  isAutoMode(): boolean {
    return this.config.role === 'auto';
  }

  /**
   * Whether a role has been selected in auto mode.
   */
  hasSelectedRole(): boolean {
    return this.selectedRole !== null;
  }

  /**
   * Whether construction mode is currently active.
   */
  isConstructionMode(): boolean {
    return this.constructionMode;
  }

  /**
   * Get the timestamp when construction mode was started.
   */
  getConstructionStartedAt(): string | null {
    return this.constructionStartedAt;
  }

  /**
   * Select a role in auto mode. Returns the resolved role, or null if not found.
   * Recognizes "construction" as a synthetic role that activates construction mode.
   */
  selectRole(roleId: string): ResolvedRole | null {
    // Handle construction role selection
    if (roleId === 'construction') {
      this.selectedRole = CONSTRUCTION_ROLE;
      this.constructionMode = true;
      this.constructionStartedAt = new Date().toISOString();
      this.log('Construction mode activated');
      return CONSTRUCTION_ROLE;
    }

    const state = this.getState();
    const role = state.roles.get(roleId);
    if (!role) return null;

    this.selectedRole = role;
    this.log(`Role selected: ${roleId}`);
    return role;
  }

  /**
   * End construction mode. Called when aegis_complete_task fires
   * during a construction session.
   */
  endConstructionMode(): void {
    this.constructionMode = false;
    this.log('Construction mode ended');
  }

  /**
   * Get all available roles as a summary list.
   * Always includes the synthetic "construction" role.
   */
  getAvailableRoles(): Array<{ id: string; name: string; purpose: string }> {
    const state = this.getState();
    const roles: Array<{ id: string; name: string; purpose: string }> = [];

    // Construction role is always first in the list
    roles.push({
      id: CONSTRUCTION_ROLE.id,
      name: CONSTRUCTION_ROLE.name,
      purpose: CONSTRUCTION_ROLE.purpose,
    });

    // Then all project-defined roles
    for (const [id, role] of state.roles) {
      roles.push({ id, name: role.name, purpose: role.purpose });
    }

    return roles;
  }

  /**
   * Get the resolved role for the configured agent.
   * In auto mode: returns the selected role, or a placeholder if none selected yet.
   * In fixed mode: returns the configured role, falling back to default.
   */
  getActiveRole(): ResolvedRole {
    const state = this.getState();

    // Auto mode — return selected role or placeholder
    if (this.isAutoMode()) {
      if (this.selectedRole) return this.selectedRole;

      // No role selected yet — return a restrictive placeholder
      return {
        id: 'unassigned',
        name: 'unassigned',
        purpose: 'No role selected. Call aegis_select_role to choose a role before performing any actions.',
        writable_paths: [],
        secondary_paths: [],
        excluded_paths: [],
        readable_paths: [],
        autonomy: 'conservative',
        forbidden_actions: ['All actions — no role has been selected yet.'],
      };
    }

    // Fixed mode — use configured role
    const roleId = this.config.role;

    const role = state.roles.get(roleId);
    if (role) return role;

    const defaultRole = state.roles.get('default');
    if (defaultRole) {
      this.log(`Role "${roleId}" not found, using default`);
      return defaultRole;
    }

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
   */
  private resolveRole(id: string, raw: RoleFile): ResolvedRole {
    const name = typeof raw.role === 'object' ? raw.role.name : String(raw.role);
    const purpose = typeof raw.role === 'object'
      ? raw.role.purpose
      : (raw.description ?? '');

    const writable_paths = raw.scope?.primary_paths?.length
      ? raw.scope.primary_paths
      : (raw.paths?.write ?? []);

    const secondary_paths = raw.scope?.secondary_paths ?? [];
    const excluded_paths = raw.scope?.excluded_paths ?? [];

    const readable_paths = raw.paths?.read?.length
      ? raw.paths.read
      : [...writable_paths, ...secondary_paths];

    const autonomy = raw.autonomy
      ? String(raw.autonomy)
      : 'advisory';

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
