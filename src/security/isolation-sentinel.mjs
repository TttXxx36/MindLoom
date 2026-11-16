import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { issueCloudEgressApproval } from './cloud-approvals.mjs';
import { assertNoForbiddenCliFlags } from './trusted-approvals.mjs';
import { getConfiguredSourceRoots, getDefaultOperatorRoot } from '../config/paths.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const DEFAULT_INSPECT_SCRIPT_PATH = path.resolve(__dirname, '../../cli/inspect-raw-local.ps1');

export const PROTECTED_SURFACES = [
  'raw',
  'state_sqlite',
  'staging',
  'egress',
  'revisions',
  'vault_git_and_local_only'
];

export function getPlanB01SixSurfaces(options = {}) {
  const roots = getConfiguredSourceRoots(options);
  return [
    {
      id: 'source_sessions',
      planItem: 1,
      name: '三端原始会话源目录',
      paths: [roots.codexRoot, roots.agyRoot, roots.dshRoot],
      codeSurfaceKey: 'raw'
    },
    {
      id: 'raw_snapshots',
      planItem: 2,
      name: '库外原始快照副本',
      paths: ['Data/raw/{codex,antigravity,dsh}/'],
      codeSurfaceKey: 'raw'
    },
    {
      id: 'attachments',
      planItem: 3,
      name: '库外本地附件区',
      paths: ['Data/attachments/'],
      codeSurfaceKey: 'staging'
    },
    {
      id: 'local_only_notes',
      planItem: 4,
      name: 'Vault 内私有笔记工作区文件 (privacy: local_only)',
      paths: ['Vault/** (privacy: local_only)'],
      codeSurfaceKey: 'vault_git_and_local_only'
    },
    {
      id: 'vault_git_and_revisions',
      planItem: 5,
      name: 'Vault 本地恢复历史库 (.git 与 runtime/revisions/)',
      paths: ['Vault/.git/', 'Data/runtime/revisions/'],
      codeSurfaceKey: 'revisions'
    },
    {
      id: 'approvals_and_ledger',
      planItem: 6,
      name: '可信人工确认、外发批准与状态台账',
      paths: ['Data/egress/', 'Data/runtime/state.sqlite'],
      codeSurfaceKey: 'egress'
    }
  ];
}

// PLAN.md §3.3 定义的 6 类受保护目标与代码探测面的一一映射（动态读取配置源目录，不硬编码个人路径）
export const PLAN_B01_SIX_SURFACES = getPlanB01SixSurfaces();

export const SUPPORTED_HOST_CLIENTS = ['codex', 'antigravity', 'dsh'];

/**
 * 创建非秘密合成哨兵文件（严禁包含任何真实秘密）
 * @param {{ rawDir: string, fileName?: string }} options
 * @returns {{ sentinelPath: string, sentinelToken: string }}
 */
export function createNonSecretSentinel({
  rawDir,
  fileName = 'sentinel-b01-nonsecret.jsonl'
}) {
  if (!fs.existsSync(rawDir)) {
    fs.mkdirSync(rawDir, { recursive: true });
  }
  const sentinelToken = `SYNTHETIC-NONSECRET-SENTINEL-R3-${Date.now()}`;
  const sentinelPath = path.join(rawDir, fileName);
  const content = JSON.stringify({
    type: 'system',
    synthetic: true,
    note: 'Non-secret synthetic sentinel for R3 B01 isolation check',
    marker: sentinelToken
  }) + '\n';

  fs.writeFileSync(sentinelPath, content, 'utf8');
  return { sentinelPath, sentinelToken };
}

/**
 * 执行 R3 阶段 B 准入三路越权哨兵测试 (B01)
 * 1. 直接文件读取 (direct_file_read)
 * 2. 通用 Shell 命令读取 (general_shell_read)
 * 3. 独立原文查看脚本读取 (standalone_script_read)
 *
 * 仅当三路均无法读出哨兵内容时，才可认定强隔离已建立；
 * 否则严格停留在降级路径 (degraded_low_sensitivity_only)，禁止处理强保密原文。
 *
 * @param {{
 *   rawDir: string,
 *   dataDir?: string,
 *   sentinelPath?: string,
 *   sentinelToken?: string,
 *   inspectScriptPath?: string,
 *   directReader?: (filePath: string) => string,
 *   shellReader?: (filePath: string) => string,
 *   scriptReader?: (params: { scriptPath: string, sentinelPath: string, dataDir: string }) => string
 * }} params
 */
export function runIsolationSentinelCheck({
  rawDir,
  dataDir,
  sentinelPath,
  sentinelToken,
  inspectScriptPath = DEFAULT_INSPECT_SCRIPT_PATH,
  directReader,
  shellReader,
  scriptReader
}) {
  const effectiveDataDir = dataDir || path.dirname(rawDir);
  let targetPath = sentinelPath;
  let expectedToken = sentinelToken;

  if (!targetPath) {
    const defaultSentinel = path.join(rawDir, 'sentinel-b01-nonsecret.jsonl');
    if (fs.existsSync(defaultSentinel)) {
      targetPath = defaultSentinel;
      if (!expectedToken) {
        try {
          const parsed = JSON.parse(fs.readFileSync(defaultSentinel, 'utf8'));
          expectedToken = parsed.marker || null;
        } catch {
          expectedToken = null;
        }
      }
    } else {
      try {
        const created = createNonSecretSentinel({ rawDir });
        targetPath = created.sentinelPath;
        expectedToken = created.sentinelToken;
      } catch (err) {
        // 若 rawDir 对当前进程连写权限也被 OS ACL 剥夺且未预先置入哨兵，仍以占位路径继续执行三路读探测
        targetPath = defaultSentinel;
        expectedToken = null;
      }
    }
  }

  const vectors = {
    direct_file_read: { blocked: false, leaked: false, detail: '' },
    general_shell_read: { blocked: false, leaked: false, detail: '' },
    standalone_script_read: { blocked: false, leaked: false, detail: '' }
  };

  const sentinelPresent = Boolean(expectedToken) || fs.existsSync(targetPath);

  // Vector 1: 直接文件读取
  try {
    const reader = directReader || ((p) => fs.readFileSync(p, 'utf8'));
    const out = reader(targetPath);
    const leaked = expectedToken ? String(out).includes(expectedToken) : String(out).length > 0;
    vectors.direct_file_read = {
      blocked: !leaked,
      leaked,
      detail: leaked ? '直接文件读取可读取 raw/ 哨兵内容' : '直接文件读取未命中哨兵内容'
    };
  } catch (err) {
    const isPermDenied = err?.code === 'EACCES' || err?.code === 'EPERM';
    const isBlocked = sentinelPresent || isPermDenied;
    vectors.direct_file_read = {
      blocked: isBlocked,
      leaked: false,
      detail: isBlocked ? `已阻断 (${err.code || err.message})` : `哨兵不存在且未证明受阻 (${err.code || err.message})`
    };
  }

  // Vector 2: 通用 Shell 读取
  try {
    const defaultShellReader = (p) => {
      return execFileSync(
        'pwsh',
        ['-NoProfile', '-NonInteractive', '-Command', `Get-Content -LiteralPath '${p.replace(/'/g, "''")}' -Raw`],
        { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      );
    };
    const runner = shellReader || defaultShellReader;
    const out = runner(targetPath);
    const leaked = expectedToken ? String(out).includes(expectedToken) : String(out).length > 0;
    vectors.general_shell_read = {
      blocked: !leaked,
      leaked,
      detail: leaked ? '通用 Shell 命令可读取 raw/ 哨兵内容' : '通用 Shell 未命中哨兵内容'
    };
  } catch (err) {
    const errText = `${err.stderr || ''} ${err.message || ''}`;
    const isPermDenied = /Access.*denied|UnauthorizedAccess|EACCES|EPERM/i.test(errText);
    const isBlocked = sentinelPresent || isPermDenied;
    vectors.general_shell_read = {
      blocked: isBlocked,
      leaked: false,
      detail: isBlocked ? `已阻断 (${err.status || err.code || err.message})` : `哨兵不存在且未证明受阻 (${err.status || err.code || err.message})`
    };
  }

  // Vector 3: 独立原文脚本读取 (以非交互自动化方式调用 inspect-raw-local.ps1)
  try {
    const defaultScriptReader = ({ scriptPath, sentinelPath: sp, dataDir: dd }) => {
      return execFileSync(
        'pwsh',
        ['-NoProfile', '-NonInteractive', '-File', scriptPath, '-SnapshotFile', sp, '-DataDir', dd],
        { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      );
    };
    const runner = scriptReader || defaultScriptReader;
    const out = runner({ scriptPath: inspectScriptPath, sentinelPath: targetPath, dataDir: effectiveDataDir });
    const leaked = expectedToken ? String(out).includes(expectedToken) : String(out).length > 0;
    vectors.standalone_script_read = {
      blocked: !leaked,
      leaked,
      detail: leaked ? '独立原文脚本以非交互方式读出哨兵' : '独立脚本未命中哨兵内容'
    };
  } catch (err) {
    vectors.standalone_script_read = {
      blocked: true,
      leaked: false,
      detail: `已阻断 (${err.status || err.code || err.message})`
    };
  }

  const strongIsolationEstablished =
    vectors.direct_file_read.blocked &&
    vectors.general_shell_read.blocked &&
    vectors.standalone_script_read.blocked;

  return {
    sentinelPath: targetPath,
    strongIsolationEstablished,
    mode: strongIsolationEstablished ? 'strong_isolated' : 'degraded_low_sensitivity_only',
    allowedSensitivities: strongIsolationEstablished
      ? ['synthetic', 'approved_low_sensitivity', 'confidential']
      : ['synthetic', 'approved_low_sensitivity'],
    vectors
  };
}

/**
 * 校验输入会话灵敏度是否被当前隔离级别允许 (§3.3)
 * @param {{ sensitivity: string, isolationReport: ReturnType<typeof runIsolationSentinelCheck> }} params
 */
export function assertSensitivityAllowed({ sensitivity = 'synthetic', isolationReport }) {
  const allowed = new Set(['synthetic', 'approved_low_sensitivity', 'confidential']);
  if (!allowed.has(sensitivity)) {
    throw new Error(`非法会话灵敏度级别: ${sensitivity}`);
  }
  if (sensitivity === 'confidential' && (!isolationReport || !isolationReport.strongIsolationEstablished)) {
    throw new Error(
      'R3_ISOLATION_GATE_BLOCKED: 当前宿主环境未通过 B01 强隔离三路哨兵测试，处于降级模式 (degraded_low_sensitivity_only)，严禁处理 confidential 强保密原文！'
    );
  }
}

/**
 * B01 三端宿主 × 6 类受保护面全量哨兵矩阵评估 (§6.1, 第 5/6 轮审核闭环)
 * 受保护面：
 *   1. raw (AgentMemory-Data/raw/)
 *   2. state_sqlite (AgentMemory-Data/runtime/state.sqlite)
 *   3. staging (AgentMemory-Data/staging/)
 *   4. egress (AgentMemory-Data/egress/)
 *   5. revisions (AgentMemory-Data/runtime/revisions/)
 *   6. vault_git_and_local_only (AgentMemory/.git/ 与 privacy: local_only 笔记)
 *
 * 规则：任一宿主端对任一受保护面的任一探测向量未阻断，该端即判定为 degraded_low_sensitivity_only
 *
 * @param {{
 *   hosts?: Array<'codex' | 'antigravity' | 'dsh'>,
 *   surfaceProbeFn?: (host: string, surface: string) => { direct_file_read: boolean, general_shell_read: boolean, standalone_script_read: boolean }
 * }} [params]
 */
export function runMultiHostIsolationMatrix({
  hosts = SUPPORTED_HOST_CLIENTS,
  surfaceProbeFn = null
} = {}) {
  const hostReports = {};
  let allHostsStrongIsolated = true;

  for (const host of hosts) {
    const surfaceResults = {};
    let hostStrong = true;

    for (const surface of PROTECTED_SURFACES) {
      const probe = surfaceProbeFn
        ? surfaceProbeFn(host, surface)
        : {
            direct_file_read: false,
            general_shell_read: false,
            standalone_script_read: true
          };

      const surfaceBlocked =
        Boolean(probe.direct_file_read) &&
        Boolean(probe.general_shell_read) &&
        Boolean(probe.standalone_script_read);

      surfaceResults[surface] = {
        blocked: surfaceBlocked,
        vectors: {
          direct_file_read: Boolean(probe.direct_file_read),
          general_shell_read: Boolean(probe.general_shell_read),
          standalone_script_read: Boolean(probe.standalone_script_read)
        }
      };

      if (!surfaceBlocked) {
        hostStrong = false;
      }
    }

    if (!hostStrong) {
      allHostsStrongIsolated = false;
    }

    hostReports[host] = {
      host,
      strongIsolationEstablished: hostStrong,
      mode: hostStrong ? 'strong_isolated' : 'degraded_low_sensitivity_only',
      protectedSurfacesChecked: PROTECTED_SURFACES.length,
      planSurfacesChecked: PLAN_B01_SIX_SURFACES.length,
      scriptRefusalDoesNotProveOsIsolation: true,
      surfaces: surfaceResults
    };
  }

  const planSurfaceResults = Object.fromEntries(
    hosts.map(host => [
      host,
      Object.fromEntries(
        PLAN_B01_SIX_SURFACES.map(ps => [
          ps.id,
          {
            planItem: ps.planItem,
            name: ps.name,
            paths: ps.paths,
            codeSurfaceKey: ps.codeSurfaceKey,
            blocked: Boolean(hostReports[host]?.surfaces?.[ps.codeSurfaceKey]?.blocked)
          }
        ])
      )
    ])
  );

  return {
    hostsChecked: hosts,
    protectedSurfaces: PROTECTED_SURFACES,
    planSurfaces: PLAN_B01_SIX_SURFACES,
    planSurfaceResults,
    scriptRefusalDoesNotProveOsIsolation: true,
    allHostsStrongIsolated,
    hostReports
  };
}

export const CLOUD_FOUR_SENTINELS = Object.freeze([
  'key_file_unreadable',
  'operator_db_unwritable',
  'cannot_self_issue_approval',
  'operator_package_unwritable'
]);

function probeOpenBlocked(targetPath, mode, openSucceededReason) {
  if (!targetPath || typeof targetPath !== 'string') {
    return { blocked: false, reason: 'target_missing', code: 'ENOENT' };
  }
  try {
    // Probe directly with fs.openSync instead of pre-checking fs.existsSync: on Windows NTFS,
    // restricted parent directories cause existsSync to swallow EPERM/EACCES and return false.
    const fd = fs.openSync(targetPath, mode);
    fs.closeSync(fd);
    return { blocked: false, reason: openSucceededReason, code: null };
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      return { blocked: false, reason: 'target_missing', code: 'ENOENT' };
    }
    if (err && (err.code === 'EACCES' || err.code === 'EPERM' || (mode === 'r+' && err.code === 'EROFS'))) {
      return { blocked: true, reason: `os_denied_${err.code}`, code: err.code };
    }
    return { blocked: false, reason: `unexpected_error_${err?.code || 'UNKNOWN'}`, code: err?.code || null };
  }
}

function defaultProbeReadBlocked(targetPath) {
  return probeOpenBlocked(targetPath, 'r', 'read_succeeded');
}

function defaultProbeWriteBlocked(targetPath) {
  // Use O_RDWR ('r+') instead of fs.accessSync(W_OK) because accessSync ignores Windows NTFS ACLs.
  return probeOpenBlocked(targetPath, 'r+', 'write_open_succeeded');
}

function probeOptionalSidecarWrite(sidecarPath, missingReason, probeWriteFn) {
  if (!sidecarPath) {
    return { checked: false, probe: { blocked: true, reason: missingReason, code: null } };
  }
  const rawProbe = probeWriteFn(sidecarPath);
  if (rawProbe?.code === 'ENOENT' && !fs.existsSync(sidecarPath)) {
    return { checked: false, probe: { blocked: true, reason: missingReason, code: null } };
  }
  return { checked: true, probe: rawProbe };
}

export function getProtectedOperatorPackageSpec({
  entrypointPath = null,
  modulePaths = [],
  configPaths = []
} = {}) {
  const entries = [];
  if (entrypointPath) {
    entries.push({ category: 'entrypoint', filePath: path.resolve(entrypointPath) });
  }
  for (const modPath of modulePaths) {
    if (modPath) {
      entries.push({ category: 'module', filePath: path.resolve(modPath) });
    }
  }
  for (const cfgPath of configPaths) {
    if (cfgPath) {
      entries.push({ category: 'config', filePath: path.resolve(cfgPath) });
    }
  }
  return entries;
}

export function runFourPointCloudIsolationSentinel({
  keyFilePath = null,
  operatorDbPath = null,
  operatorPackage = {},
  probeReadFn = defaultProbeReadBlocked,
  probeWriteFn = defaultProbeWriteBlocked,
  selfIssueAttemptFn = null
} = {}) {
  // 1. Host cannot read operator's cloud API key file
  const keyProbe = probeReadFn(keyFilePath);
  const keyFileUnreadable = {
    id: 'key_file_unreadable',
    passed: Boolean(keyProbe?.blocked),
    targetPath: keyFilePath,
    reason: keyProbe?.reason || 'unknown',
    code: keyProbe?.code || null
  };

  // 2. Host cannot open operator DB (and existing WAL/SHM sidecars) for writing
  const dbMainProbe = probeWriteFn(operatorDbPath);
  const walSidecar = probeOptionalSidecarWrite(operatorDbPath ? `${operatorDbPath}-wal` : null, 'no_wal', probeWriteFn);
  const shmSidecar = probeOptionalSidecarWrite(operatorDbPath ? `${operatorDbPath}-shm` : null, 'no_shm', probeWriteFn);
  const walCheckNeeded = walSidecar.checked;
  const dbWalProbe = walSidecar.probe;
  const shmCheckNeeded = shmSidecar.checked;
  const dbShmProbe = shmSidecar.probe;
  const dbAllBlocked = Boolean(dbMainProbe?.blocked) && Boolean(dbWalProbe?.blocked) && Boolean(dbShmProbe?.blocked);
  const dbFailureSidecar = !dbMainProbe?.blocked
    ? dbMainProbe
    : !dbWalProbe?.blocked
      ? { reason: `wal_${dbWalProbe?.reason}`, code: dbWalProbe?.code }
      : { reason: `shm_${dbShmProbe?.reason}`, code: dbShmProbe?.code };
  const operatorDbUnwritable = {
    id: 'operator_db_unwritable',
    passed: dbAllBlocked,
    targetPath: operatorDbPath,
    walChecked: walCheckNeeded,
    shmChecked: shmCheckNeeded,
    reason: dbAllBlocked ? dbMainProbe?.reason : dbFailureSidecar?.reason,
    code: dbAllBlocked ? dbMainProbe?.code : dbFailureSidecar?.code
  };

  // 3. Host cannot self-issue cloud approval
  let selfIssueBlocked = false;
  let selfIssueReason = 'untested';
  try {
    if (typeof selfIssueAttemptFn === 'function') {
      const attempt = selfIssueAttemptFn();
      selfIssueBlocked = Boolean(attempt?.blocked);
      selfIssueReason = attempt?.reason || (selfIssueBlocked ? 'custom_probe_blocked' : 'custom_probe_allowed');
    } else {
      let rejectedUntrusted = false;
      try {
        issueCloudEgressApproval(
          { prepare: () => ({ get: () => null, run: () => ({ changes: 0 }) }), exec: () => {} },
          {
            purpose: 'embed_query',
            scopeRef: 'query-session:sentinel',
            corpusDigest: '0'.repeat(64),
            boundVaultId: 'v1',
            boundDataId: 'd1',
            queryEgressAllowed: 1,
            provider: 'siliconflow',
            endpointUrl: 'https://api.siliconflow.cn/v1/embeddings',
            modelId: 'BAAI/bge-m3',
            maxCalls: 1,
            maxInputTokens: 100,
            maxOutputTokens: 0,
            maxCostMicroCny: 100,
            expiresAt: new Date(Date.now() + 60_000).toISOString(),
            trustedHumanContext: false
          }
        );
      } catch (err) {
        if (err && err.code === 'ERR_CLOUD_APPROVAL_UNTRUSTED_CONTEXT') {
          rejectedUntrusted = true;
        }
      }

      let rejectedCliFlag = false;
      try {
        assertNoForbiddenCliFlags(['search', '--approve-cloud-egress']);
      } catch {
        rejectedCliFlag = true;
      }

      selfIssueBlocked = rejectedUntrusted && rejectedCliFlag && operatorDbUnwritable.passed;
      selfIssueReason = selfIssueBlocked
        ? 'untrusted_context_and_cli_flags_rejected_and_db_unwritable'
        : 'self_issue_guard_or_db_isolation_incomplete';
    }
  } catch (err) {
    selfIssueBlocked = false;
    selfIssueReason = `probe_threw:${err?.message || String(err)}`;
  }

  const cannotSelfIssueApproval = {
    id: 'cannot_self_issue_approval',
    passed: selfIssueBlocked,
    reason: selfIssueReason
  };

  // 4. Host cannot write or tamper with operator entrypoint, loaded modules, or config files
  const packageTargets = getProtectedOperatorPackageSpec(operatorPackage);
  const hasEntrypoint = packageTargets.some((t) => t.category === 'entrypoint');
  const hasModule = packageTargets.some((t) => t.category === 'module');
  const hasConfig = packageTargets.some((t) => t.category === 'config');
  const targetResults = packageTargets.map((target) => {
    const res = probeWriteFn(target.filePath);
    return {
      category: target.category,
      filePath: target.filePath,
      blocked: Boolean(res?.blocked),
      reason: res?.reason || 'unknown',
      code: res?.code || null
    };
  });
  const writableTargets = targetResults.filter((r) => !r.blocked);
  const allTargetsBlocked =
    hasEntrypoint &&
    hasModule &&
    hasConfig &&
    targetResults.length > 0 &&
    writableTargets.length === 0;

  const operatorPackageUnwritable = {
    id: 'operator_package_unwritable',
    passed: allTargetsBlocked,
    hasEntrypoint,
    hasModule,
    hasConfig,
    checkedCount: targetResults.length,
    writableTargets,
    targets: targetResults,
    reason: !hasEntrypoint || !hasModule || !hasConfig
      ? 'incomplete_operator_package_coverage'
      : writableTargets.length > 0
        ? `writable_operator_files:${writableTargets.map((w) => `${w.category}:${w.filePath}`).join(',')}`
        : 'all_operator_package_files_unwritable'
  };

  const sentinels = {
    key_file_unreadable: keyFileUnreadable,
    operator_db_unwritable: operatorDbUnwritable,
    cannot_self_issue_approval: cannotSelfIssueApproval,
    operator_package_unwritable: operatorPackageUnwritable
  };

  const allFourPassed = Object.values(sentinels).every((s) => s.passed === true);

  return {
    allFourPassed,
    canEnableRealCloudApi: allFourPassed,
    sentinels,
    failedSentinels: Object.values(sentinels)
      .filter((s) => !s.passed)
      .map((s) => s.id)
  };
}

export function assertRealCloudApiGate(sentinelReport) {
  if (!sentinelReport || sentinelReport.allFourPassed !== true) {
    const failed = sentinelReport?.failedSentinels?.join(', ') || 'sentinel_not_run';
    const err = new Error(
      `[ERR_CLOUD_OS_ISOLATION_FAILED] Real cloud API blocked: 4-point OS isolation sentinel failed (${failed})`
    );
    err.code = 'ERR_CLOUD_OS_ISOLATION_FAILED';
    err.sentinelReport = sentinelReport || null;
    throw err;
  }
  return true;
}

export const DEFAULT_OPERATOR_ROOT = getDefaultOperatorRoot();

const ADMIN_AND_SYSTEM_SIDS = new Set(['S-1-5-32-544', 'S-1-5-18']);
const WINDOWS_WRITE_OR_ADMIN_RIGHTS_MASK =
  0x2 | // WriteData / CreateFiles
  0x4 | // AppendData / CreateDirectories
  0x10 | // WriteExtendedAttributes
  0x40 | // DeleteSubdirectoriesAndFiles
  0x100 | // WriteAttributes
  0x10000 | // Delete
  0x40000 | // WriteDac (ChangePermissions)
  0x80000 | // WriteOwner (TakeOwnership)
  0x10000000 | // GenericAll
  0x40000000; // GenericWrite

export function buildOperatorIsolationTargets({ operatorRoot = DEFAULT_OPERATOR_ROOT } = {}) {
  const root = path.resolve(operatorRoot);
  const cliRoot = path.join(root, 'operator-cli');
  return {
    operatorRoot: root,
    cliRoot,
    keyFilePath: path.join(root, 'keys', 'provider-secrets.json'),
    operatorDbPath: path.join(root, 'operator-state', 'operator-state.sqlite'),
    trialWorkspaceDir: path.join(root, 'trial-workspace'),
    approveScriptPath: path.join(cliRoot, 'scripts', 'approve-human.ps1'),
    operatorPackage: {
      entrypointPath: path.join(cliRoot, 'cli', 'mem-operator.mjs'),
      modulePaths: [
        path.join(cliRoot, 'src', 'providers', 'api-gateway.mjs'),
        path.join(cliRoot, 'src', 'providers', 'adapters', 'emrank.mjs'),
        path.join(cliRoot, 'src', 'providers', 'adapters', 'index.mjs'),
        path.join(cliRoot, 'src', 'providers', 'adapters', 'openai-embedding-common.mjs'),
        path.join(cliRoot, 'src', 'security', 'cloud-approvals.mjs'),
        path.join(cliRoot, 'src', 'security', 'isolation-sentinel.mjs'),
        path.join(cliRoot, 'src', 'search', 'vector-index.mjs'),
        path.join(cliRoot, 'scripts', 'approve-human.ps1')
      ],
      configPaths: [
        path.join(cliRoot, 'config', 'operator-config.json'),
        path.join(cliRoot, 'package.json')
      ]
    }
  };
}

export function isCurrentWindowsProcessElevated() {
  if (process.platform !== 'win32') return false;
  try {
    const out = execFileSync(
      'pwsh',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
      ],
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    ).trim();
    return /^true$/i.test(out);
  } catch {
    return false;
  }
}

export function defaultInspectWindowsAcl(targetPath) {
  if (!targetPath || typeof targetPath !== 'string' || !fs.existsSync(targetPath)) {
    return { exists: false, reason: 'target_missing' };
  }
  const escaped = path.resolve(targetPath).replace(/'/g, "''");
  const psScript = `
$acl = Get-Acl -LiteralPath '${escaped}'
$ownerSid = $null
try { $ownerSid = ([System.Security.Principal.NTAccount]$acl.Owner).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $ownerSid = $acl.Owner }
$rules = @($acl.Access | ForEach-Object {
  $sid = $null
  try { $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = [string]$_.IdentityReference }
  [PSCustomObject]@{
    identity = [string]$_.IdentityReference
    sid = $sid
    accessControlType = [string]$_.AccessControlType
    rightsMask = [int64]$_.FileSystemRights
    rightsText = [string]$_.FileSystemRights
    isInherited = [bool]$_.IsInherited
  }
})
[PSCustomObject]@{
  exists = $true
  owner = $acl.Owner
  ownerSid = $ownerSid
  areAccessRulesProtected = [bool]$acl.AreAccessRulesProtected
  access = $rules
} | ConvertTo-Json -Depth 5 -Compress
`.trim();
  const stdout = execFileSync(
    'pwsh',
    ['-NoProfile', '-NonInteractive', '-Command', psScript],
    { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
  );
  return JSON.parse(stdout);
}

function checkPrivateAcl(aclInfo, { requireProtectedInheritance = true } = {}) {
  if (!aclInfo || !aclInfo.exists) {
    return { blocked: false, reason: aclInfo?.reason || 'target_missing' };
  }
  if (!ADMIN_AND_SYSTEM_SIDS.has(String(aclInfo.ownerSid || '').toUpperCase())) {
    return { blocked: false, reason: `untrusted_owner:${aclInfo.ownerSid || aclInfo.owner}` };
  }
  const rules = Array.isArray(aclInfo.access) ? aclInfo.access : [];
  if (rules.length === 0) {
    return { blocked: false, reason: 'empty_acl' };
  }
  for (const rule of rules) {
    if (String(rule.accessControlType).toLowerCase() !== 'allow') continue;
    if (!ADMIN_AND_SYSTEM_SIDS.has(String(rule.sid || '').toUpperCase())) {
      return { blocked: false, reason: `non_admin_allow_ace:${rule.sid || rule.identity}` };
    }
  }
  if (requireProtectedInheritance && aclInfo.areAccessRulesProtected !== true) {
    return { blocked: false, reason: 'acl_inheritance_not_disabled' };
  }
  return { blocked: true, reason: 'ntfs_acl_admin_system_only' };
}

function checkPrivateSidecarAcl(sidecarPath, missingReason, aclInspectorFn) {
  if (!sidecarPath || !fs.existsSync(sidecarPath)) {
    return { blocked: true, reason: missingReason };
  }
  const sidecarAcl = aclInspectorFn(sidecarPath);
  const directCheck = checkPrivateAcl(sidecarAcl, { requireProtectedInheritance: true });
  if (directCheck.blocked || directCheck.reason !== 'acl_inheritance_not_disabled') {
    return directCheck;
  }
  // Dynamically created SQLite -wal/-shm files inherit ACLs from operator-state/;
  // accept inheritance when sidecar rules are Admin+SYSTEM-only AND parent dir disables inheritance.
  const sidecarRulesOnly = checkPrivateAcl(sidecarAcl, { requireProtectedInheritance: false });
  if (!sidecarRulesOnly.blocked) {
    return sidecarRulesOnly;
  }
  const parentCheck = checkPrivateAcl(aclInspectorFn(path.dirname(sidecarPath)), {
    requireProtectedInheritance: true
  });
  if (!parentCheck.blocked) {
    return { blocked: false, reason: `parent_${parentCheck.reason}` };
  }
  return { blocked: true, reason: 'ntfs_acl_inherited_from_protected_parent' };
}

function checkReadOnlyPackageAcl(aclInfo) {
  if (!aclInfo || !aclInfo.exists) {
    return { blocked: false, reason: aclInfo?.reason || 'target_missing' };
  }
  if (!ADMIN_AND_SYSTEM_SIDS.has(String(aclInfo.ownerSid || '').toUpperCase())) {
    return { blocked: false, reason: `untrusted_owner:${aclInfo.ownerSid || aclInfo.owner}` };
  }
  if (aclInfo.areAccessRulesProtected !== true) {
    return { blocked: false, reason: 'acl_inheritance_not_disabled' };
  }
  const rules = Array.isArray(aclInfo.access) ? aclInfo.access : [];
  if (rules.length === 0) {
    return { blocked: false, reason: 'empty_acl' };
  }
  for (const rule of rules) {
    if (String(rule.accessControlType).toLowerCase() !== 'allow') continue;
    if (ADMIN_AND_SYSTEM_SIDS.has(String(rule.sid || '').toUpperCase())) continue;
    const mask = Number(rule.rightsMask || 0);
    if (
      (mask & WINDOWS_WRITE_OR_ADMIN_RIGHTS_MASK) !== 0 ||
      /(Write|Modify|FullControl|Delete|TakeOwnership|ChangePermissions)/i.test(String(rule.rightsText || ''))
    ) {
      return { blocked: false, reason: `writable_non_admin_ace:${rule.sid || rule.identity}:${rule.rightsText}` };
    }
  }
  return { blocked: true, reason: 'ntfs_acl_non_admin_unwritable' };
}

export function verifyElevatedWindowsOperatorAclIsolation({
  keyFilePath,
  operatorDbPath,
  operatorPackage = {},
  approveScriptPath = null,
  aclInspectorFn = defaultInspectWindowsAcl
} = {}) {
  const keyProbe = checkPrivateAcl(aclInspectorFn(keyFilePath));
  const dbMainProbe = checkPrivateAcl(aclInspectorFn(operatorDbPath));
  const dbWalProbe = checkPrivateSidecarAcl(
    operatorDbPath ? `${operatorDbPath}-wal` : null,
    'no_wal',
    aclInspectorFn
  );
  const dbShmProbe = checkPrivateSidecarAcl(
    operatorDbPath ? `${operatorDbPath}-shm` : null,
    'no_shm',
    aclInspectorFn
  );

  const packageTargets = getProtectedOperatorPackageSpec(operatorPackage);
  const hasEntrypoint = packageTargets.some((t) => t.category === 'entrypoint');
  const hasModule = packageTargets.some((t) => t.category === 'module');
  const hasConfig = packageTargets.some((t) => t.category === 'config');
  const targetResults = packageTargets.map((target) => {
    const res = checkReadOnlyPackageAcl(aclInspectorFn(target.filePath));
    return {
      category: target.category,
      filePath: target.filePath,
      blocked: Boolean(res.blocked),
      reason: res.reason
    };
  });
  const writableTargets = targetResults.filter((r) => !r.blocked);

  let selfIssueBlocked = false;
  let selfIssueReason = 'untested';
  const dbAllBlocked = dbMainProbe.blocked && dbWalProbe.blocked && dbShmProbe.blocked;
  try {
    let rejectedUntrusted = false;
    try {
      issueCloudEgressApproval(
        { prepare: () => ({ get: () => null, run: () => ({ changes: 0 }) }), exec: () => {} },
        {
          purpose: 'embed_query',
          scopeRef: 'query-session:acl-sentinel',
          corpusDigest: '0'.repeat(64),
          boundVaultId: 'v1',
          boundDataId: 'd1',
          queryEgressAllowed: 1,
          provider: 'emrank',
          endpointUrl: 'https://emrank.tech/v1/embeddings',
          modelId: 'Qwen/Qwen3-Embedding-8B',
          maxCalls: 1,
          maxInputTokens: 100,
          maxOutputTokens: 0,
          maxCostMicroCny: 100,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          trustedHumanContext: false
        }
      );
    } catch (err) {
      if (err && err.code === 'ERR_CLOUD_APPROVAL_UNTRUSTED_CONTEXT') rejectedUntrusted = true;
    }

    let rejectedCliFlag = false;
    try {
      assertNoForbiddenCliFlags(['search', '--approve-cloud-egress']);
    } catch {
      rejectedCliFlag = true;
    }

    let approveScriptRefusedNonInteractive = true;
    if (approveScriptPath && fs.existsSync(approveScriptPath)) {
      approveScriptRefusedNonInteractive = false;
      try {
        execFileSync(
          'pwsh',
          ['-NoProfile', '-NonInteractive', '-File', approveScriptPath],
          { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
        );
      } catch {
        approveScriptRefusedNonInteractive = true;
      }
    }

    selfIssueBlocked =
      rejectedUntrusted && rejectedCliFlag && dbAllBlocked && approveScriptRefusedNonInteractive;
    selfIssueReason = selfIssueBlocked
      ? 'acl_and_interactive_self_issue_guards_verified'
      : 'acl_or_self_issue_guard_incomplete';
  } catch (err) {
    selfIssueBlocked = false;
    selfIssueReason = `probe_threw:${err?.message || String(err)}`;
  }

  const sentinels = {
    key_file_unreadable: {
      id: 'key_file_unreadable',
      passed: keyProbe.blocked,
      targetPath: keyFilePath,
      reason: keyProbe.reason
    },
    operator_db_unwritable: {
      id: 'operator_db_unwritable',
      passed: dbAllBlocked,
      targetPath: operatorDbPath,
      reason: !dbMainProbe.blocked ? dbMainProbe.reason : !dbWalProbe.blocked ? dbWalProbe.reason : dbShmProbe.reason
    },
    cannot_self_issue_approval: {
      id: 'cannot_self_issue_approval',
      passed: selfIssueBlocked,
      reason: selfIssueReason
    },
    operator_package_unwritable: {
      id: 'operator_package_unwritable',
      passed: hasEntrypoint && hasModule && hasConfig && targetResults.length > 0 && writableTargets.length === 0,
      hasEntrypoint,
      hasModule,
      hasConfig,
      checkedCount: targetResults.length,
      writableTargets,
      targets: targetResults,
      reason: !hasEntrypoint || !hasModule || !hasConfig
        ? 'incomplete_operator_package_coverage'
        : writableTargets.length > 0
          ? `writable_operator_files:${writableTargets.map((w) => `${w.category}:${w.filePath}`).join(',')}`
          : 'all_operator_package_files_acl_protected'
    }
  };

  const allFourPassed = Object.values(sentinels).every((s) => s.passed === true);
  return {
    verificationMode: 'windows_ntfs_acl_inspection',
    allFourPassed,
    canEnableRealCloudApi: allFourPassed,
    sentinels,
    failedSentinels: Object.values(sentinels).filter((s) => !s.passed).map((s) => s.id)
  };
}
