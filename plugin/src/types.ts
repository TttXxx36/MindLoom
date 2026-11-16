export interface MindLoomSettings {
  vaultPath: string;
  dataPath: string;
  nodePath: string;
  cliPath: string;
  operatorRoot: string;
  timeoutMs: number;
}

export const DEFAULT_SETTINGS: MindLoomSettings = {
  vaultPath: '',
  dataPath: '',
  nodePath: '',
  cliPath: '',
  operatorRoot: '',
  timeoutMs: 25000
};

export interface CliResult<T = unknown> {
  ok: boolean;
  data?: T;
  stdout: string;
  stderr: string;
  exitCode: number;
  error?: string;
}

export interface SearchItem {
  id: string;
  title: string;
  project: string;
  derived_source_tools?: string[];
  path: string;
  actionable: boolean;
  reason?: string;
  lifecycle?: string;
  review_state?: string;
  sources?: string[];
  snippet?: string;
  injectionDetected?: boolean;
}

export interface SearchResponse {
  mode: string;
  noAnswer: boolean;
  fallbackUsed?: boolean;
  fallbackReason?: string | null;
  items: SearchItem[];
}

export interface ProposalSummary {
  proposal_id: string;
  target_id: string | null;
  proposal_kind?: string | null;
  proposal_status: string;
  reconcile_state?: string;
  reason?: string | null;
  path?: string;
}

export interface StatusResponse {
  todayStr: string;
  notes: {
    total: number;
    missing: number;
    expired: number;
    unmapped: number;
    byType: {
      sessions: number;
      evidence: number;
      knowledge: number;
      proposals: number;
    };
  };
  snapshots: {
    codex: number;
    antigravity: number;
    dsh: number;
    needsReaudit: number;
  };
  tombstones: number;
  proposals: {
    verified: number;
    unverified: number;
    mismatch: number;
    versionChanged: number;
    pending: number;
    pendingDetails: ProposalSummary[];
    conflictCount: number;
    details: ProposalSummary[];
  };
  lastBackup?: {
    backup_id: string;
    status: string;
    created_at: string;
  } | null;
}

export interface ProposalShowResponse {
  id: string;
  title: string;
  privacy: string;
  target_id: string;
  base_revision_id: string;
  proposal_kind: string;
  proposal_status: string;
  reconcile_state: string;
  reconcile_reason: string | null;
  condition_checks?: {
    passed: boolean;
    pre_conditions?: Array<{ label?: string; text?: string; satisfied?: boolean }>;
    post_conditions?: Array<{ label?: string; text?: string; satisfied?: boolean }>;
  } | null;
  base_revision_diff?: {
    base_revision_id?: string;
    base_revision_found?: boolean;
    redacted?: boolean;
    reason?: string;
    changed?: boolean;
    removed_lines_count?: number;
    added_lines_count?: number;
    removed_lines?: string[];
    added_lines?: string[];
  } | null;
  body: string;
}

export interface RestoreListResponse {
  count: number;
  items: Array<{
    id: string;
    note_type: string;
    title: string;
    project: string;
    privacy: string;
    status: string;
    path: string;
    updated_at: string;
    revisions: string[];
  }>;
}

export interface RestoreDetailResponse {
  noteId: string;
  revision: string;
  restored: boolean;
  redacted: boolean;
  reason: string | null;
  targetPath: string;
  previewPath: string | null;
  revisionContent: string;
  currentDiskContent: string | null;
}

export interface ProjectMapEntry {
  project: string;
  paths: string[];
  git_roots: string[];
  workspace_slugs: string[];
}

export interface ProjectMapResponse {
  mapPath: string;
  schema_version: number;
  default_unmapped_project: string;
  projects: ProjectMapEntry[];
}

export interface CloudBudgetResponse {
  readOnly: boolean;
  operatorRoot: string;
  operatorDbIsolation: string;
  summaryUpdatedAt: string | null;
  approvals: Array<Record<string, unknown>>;
  egressPackagesCount: number;
  egressPackages: Array<{
    packageId: string;
    purpose: string | null;
    provider: string | null;
    createdAt: string | null;
  }>;
  pricingCatalog: Record<string, Record<string, Record<string, unknown>>>;
  adminCommands: {
    setupIsolation: string;
    issueCloudApproval: string;
    listApprovals: string;
    runDistill: string;
  };
}
