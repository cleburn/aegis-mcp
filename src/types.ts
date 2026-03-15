/**
 * Aegis MCP Server — Core Type Definitions
 *
 * Aligned to the aegis-spec v0.2.0 schema contract and the aegis-cli v0.2.4
 * extraction prompt. Skeleton fields (required by the spec) are typed precisely.
 * Extension fields (domain-specific additions the LLM may generate) are typed
 * as optional with their known shapes.
 *
 * The enforcement engine reads skeleton fields with confidence and leverages
 * extension fields when present for deeper enforcement.
 */

// ─── Constitution (constitution.json) ───────────────────────────────────────

export interface Constitution {
  $schema?: string;
  version: string;
  project: {
    name: string;
    purpose: string;
    architecture: string;
    module_map?: ModuleMapEntry[];
    required_artifacts?: RequiredArtifact[];
    /** Extension: domain list with paths and descriptions */
    domains?: DomainEntry[];
    /** Extension: catch-all for other project fields */
    [key: string]: unknown;
  };
  tech_stack: {
    languages: string[];
    frameworks?: string[];
    infrastructure?: string[];
    package_managers?: string[];
    key_libraries?: Array<{ name: string; purpose: string; scope?: string }>;
    [key: string]: unknown;
  };
  principles: Principle[];
  build_commands?: BuildCommands;
  /** Extension: sensitivity tier definitions */
  sensitivity_tiers?: SensitivityTier[];
  [key: string]: unknown;
}

export interface ModuleMapEntry {
  path: string;
  purpose: string;
  owner?: string;
  internal_dependencies?: string[];
}

export interface RequiredArtifact {
  path: string;
  purpose: string;
  source?: string;
}

export interface DomainEntry {
  name: string;
  path: string;
  description: string;
}

export interface Principle {
  name: string;
  statement: string;
  priority?: number;
  /** Extension: enforcement level */
  id?: string;
  enforcement?: string;
  text?: string;
  [key: string]: unknown;
}

export interface BuildCommands {
  install?: string;
  build?: string;
  test?: string;
  lint?: string;
  typecheck?: string;
  dev?: string;
  custom?: Array<{ name: string; command: string; purpose: string }>;
  [key: string]: unknown;
}

export interface SensitivityTier {
  tier: string;
  description: string;
  examples: string[];
  handling: Record<string, string>;
}

// ─── Governance (governance.json) ────────────────────────────────────────────

export interface Governance {
  $schema?: string;
  version: string;
  autonomy: {
    default_level: AutonomyLevel;
    domains?: Record<string, AutonomyLevel>;
    /** Extension: detailed level descriptions */
    levels?: Record<string, { description: string }>;
    /** Extension: per-domain overrides (alternate key) */
    domain_overrides?: Record<string, AutonomyLevel | string>;
    [key: string]: unknown;
  };
  permissions: {
    boundaries: PermissionBoundaries;
    sensitive_patterns?: SensitivePattern[];
    [key: string]: unknown;
  };
  quality_gate: {
    pre_commit: PreCommitGates;
    /** Extension: richer gate array */
    gates?: QualityGateEntry[];
    /** Extension: override authority */
    override_authority?: string;
    [key: string]: unknown;
  };
  conventions?: Convention[];
  escalation?: EscalationConfig;
  override_protocol?: OverrideProtocol;
  /** Extension: cross-domain enforcement rules */
  cross_domain_rules?: CrossDomainRules;
  /** Extension: data directory policy */
  data_directory_policy?: Record<string, unknown>;
  /** Extension: build commands (may appear here or in constitution) */
  build_commands?: BuildCommands;
  [key: string]: unknown;
}

export type AutonomyLevel = 'conservative' | 'advisory' | 'delegated';

export interface PermissionBoundaries {
  writable?: string[];
  read_only?: string[];
  forbidden?: string[];
}

export interface SensitivePattern {
  pattern: string;
  reason: string;
}

export interface PreCommitGates {
  must_pass_tests?: boolean;
  must_pass_lint?: boolean;
  must_pass_typecheck?: boolean;
  must_add_tests?: boolean;
  must_update_docs?: boolean;
  max_files_changed?: number;
  custom_checks?: Array<{
    name: string;
    command: string;
    description?: string;
  }>;
}

export interface QualityGateEntry {
  name: string;
  scope: string | string[];
  required: boolean;
  description: string;
}

export interface Convention {
  id: string;
  scope: string;
  rule: string;
  value?: string;
  allowed?: string[];
  forbidden?: string[];
  enforcement: 'strict' | 'preferred' | 'suggestion';
  rationale?: string;
}

export interface EscalationConfig {
  on_ambiguity?: 'stop_and_ask' | 'best_judgment_and_flag' | 'best_judgment_silent';
  on_conflict?: 'stop_and_ask' | 'principles_win' | 'convention_wins';
  on_scope_boundary?: 'stop_and_ask' | 'flag_and_suggest' | 'stay_in_lane';
  /** Extension: trigger list */
  triggers?: string[];
  /** Extension: escalation target */
  target?: string;
  /** Extension: escalation behavior description */
  behavior?: string;
  [key: string]: unknown;
}

export interface OverrideProtocol {
  behavior?: 'block_and_log' | 'warn_confirm_and_log' | 'log_only';
  log_path?: string;
  log_entry_schema?: Record<string, unknown>;
  immutable_policies?: string[];
}

export interface CrossDomainRules {
  communication_method?: string;
  shared_interfaces_path?: string;
  violations?: Record<string, string>;
  description?: string;
  [key: string]: unknown;
}

// ─── Role (roles/*.json) ────────────────────────────────────────────────────

export interface RoleFile {
  $schema?: string;
  version: string;
  /** Skeleton: nested role object */
  role: {
    name: string;
    purpose: string;
    specialization?: string[];
  };
  /** Skeleton: scoped paths */
  scope: {
    primary_paths: string[];
    secondary_paths?: string[];
    excluded_paths?: string[];
  };
  autonomy_overrides?: Record<string, AutonomyLevel>;
  /** Extension: flat autonomy level for the role */
  autonomy?: AutonomyLevel | string;
  /** Extension: read/write path model */
  paths?: {
    read?: string[];
    write?: string[];
  };
  /** Extension: prose list of forbidden actions */
  forbidden_actions?: string[];
  /** Extension: convention overrides or key-value conventions */
  conventions?: unknown;
  /** Extension: escalation triggers */
  escalation_triggers?: string[];
  /** Extension: QA validation responsibilities */
  validation_responsibilities?: string[];
  /** Extension: write mode (e.g. append-only) */
  write_mode?: string;
  /** Extension: report format config */
  report_format?: Record<string, unknown>;
  /** Extension: collaboration protocols */
  collaboration?: Record<string, unknown>;
  /** Extension: description (flat, alongside role.purpose) */
  description?: string;
  [key: string]: unknown;
}

/**
 * Resolved role for enforcement — flattened from the RoleFile structure
 * with skeleton and extension fields merged for fast lookups.
 */
export interface ResolvedRole {
  /** Filename without .json */
  id: string;
  /** role.name from skeleton */
  name: string;
  /** role.purpose from skeleton */
  purpose: string;
  /** Merged: scope.primary_paths + paths.write */
  writable_paths: string[];
  /** Merged: scope.secondary_paths */
  secondary_paths: string[];
  /** Merged: scope.excluded_paths */
  excluded_paths: string[];
  /** Merged: paths.read (when present) */
  readable_paths: string[];
  /** Autonomy level for this role */
  autonomy: string;
  /** Forbidden actions (prose, for informational responses) */
  forbidden_actions: string[];
}

// ─── Enforcement Results ─────────────────────────────────────────────────────

export type EnforcementVerdict =
  | { allowed: true }
  | { allowed: false; reason: string; policy_ref: string; immutable: boolean };

export interface OverrideLogEntry {
  timestamp: string;
  policy_violated: string;
  policy_text: string;
  action_requested: string;
  human_confirmed: boolean;
  agent_role: string;
  rationale: string;
}

// ─── Loaded Policy State ─────────────────────────────────────────────────────

export interface PolicyState {
  constitution: Constitution;
  governance: Governance;
  roles: Map<string, ResolvedRole>;
  projectRoot: string;
  policyDir: string;
}

// ─── MCP Server Config ──────────────────────────────────────────────────────

export interface AegisMcpConfig {
  role: string;
  projectRoot: string;
  policyDir?: string;
}
