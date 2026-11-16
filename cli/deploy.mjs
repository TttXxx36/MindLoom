#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { resolveConfiguredPaths } from '../src/config/paths.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const REPO_ROOT = path.resolve(__dirname, '..');
export const DEFAULT_DEPLOY_DIR = resolveConfiguredPaths().deployDir;

const ROOT_WRAPPER_CONTENT = Buffer.from("#!/usr/bin/env node\nimport './cli/mem.mjs';\n", 'utf8');

function sha256Buffer(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function walkFiles(dirPath, baseDir) {
  const results = [];
  if (!fs.existsSync(dirPath)) return results;
  const entries = fs.readdirSync(dirPath, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    if (entry.name === '.tmp' || entry.name === 'node_modules' || entry.name === '.git') continue;
    const full = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkFiles(full, baseDir));
    } else if (entry.isFile()) {
      results.push(path.relative(baseDir, full).replace(/\\/g, '/'));
    }
  }
  return results;
}

export function buildDeployPlan({ repoRoot = REPO_ROOT, targetDir = DEFAULT_DEPLOY_DIR } = {}) {
  const resolvedRepo = path.resolve(repoRoot);
  const resolvedTarget = path.resolve(targetDir);
  if (resolvedRepo.toLowerCase() === resolvedTarget.toLowerCase()) {
    throw new Error(`DEPLOY_INVALID_TARGET: 部署目标目录不能与工程仓相同: ${resolvedTarget}`);
  }

  const entries = [];
  const addRepoFile = (srcRel, destRel = srcRel) => {
    const srcFull = path.join(resolvedRepo, srcRel);
    if (!fs.existsSync(srcFull)) {
      throw new Error(`DEPLOY_SOURCE_MISSING: 工程文件缺失: ${srcRel}`);
    }
    const content = fs.readFileSync(srcFull);
    entries.push({
      destRel: destRel.replace(/\\/g, '/'),
      source: srcRel.replace(/\\/g, '/'),
      sha256: sha256Buffer(content),
      size: content.length,
      readBytes: () => content
    });
  };

  addRepoFile('package.json', 'package.json');
  for (const rel of walkFiles(path.join(resolvedRepo, 'cli'), resolvedRepo)) {
    addRepoFile(rel, rel);
  }
  addRepoFile('cli/inspect-raw-local.ps1', 'inspect-raw-local.ps1');
  entries.push({
    destRel: 'mem.mjs',
    source: '<generated-root-wrapper>',
    sha256: sha256Buffer(ROOT_WRAPPER_CONTENT),
    size: ROOT_WRAPPER_CONTENT.length,
    readBytes: () => ROOT_WRAPPER_CONTENT
  });

  for (const dirName of ['src', 'tests']) {
    for (const rel of walkFiles(path.join(resolvedRepo, dirName), resolvedRepo)) {
      addRepoFile(rel, rel);
    }
  }

  const actions = entries.map(item => {
    const destFull = path.join(resolvedTarget, item.destRel);
    if (!fs.existsSync(destFull)) {
      return { ...item, destFull, status: 'create' };
    }
    const curBytes = fs.readFileSync(destFull);
    const curSha = sha256Buffer(curBytes);
    const matchesWrapperEol =
      item.destRel === 'mem.mjs' &&
      curBytes.toString('utf8').replace(/\r\n/g, '\n') === ROOT_WRAPPER_CONTENT.toString('utf8');
    const unchanged = curSha === item.sha256 || matchesWrapperEol;
    return { ...item, destFull, status: unchanged ? 'unchanged' : 'update', existingSha256: curSha };
  });

  const plannedSet = new Set(actions.map(a => a.destRel));
  const preservedExtraFiles = fs.existsSync(resolvedTarget)
    ? walkFiles(resolvedTarget, resolvedTarget).filter(rel => !plannedSet.has(rel))
    : [];

  return {
    repoRoot: resolvedRepo,
    targetDir: resolvedTarget,
    actions,
    preservedExtraFiles
  };
}

export function runDeploy({
  repoRoot = REPO_ROOT,
  targetDir = DEFAULT_DEPLOY_DIR,
  apply = false
} = {}) {
  const plan = buildDeployPlan({ repoRoot, targetDir });

  if (apply) {
    fs.mkdirSync(plan.targetDir, { recursive: true });
    for (const act of plan.actions) {
      if (act.status === 'unchanged') continue;
      fs.mkdirSync(path.dirname(act.destFull), { recursive: true });
      fs.writeFileSync(act.destFull, act.readBytes());
    }
  }

  const verifyPlan = buildDeployPlan({ repoRoot: plan.repoRoot, targetDir: plan.targetDir });
  const postDiffFiles = verifyPlan.actions.filter(a => a.status !== 'unchanged').map(a => a.destRel);
  const counts = {
    total: plan.actions.length,
    create: plan.actions.filter(a => a.status === 'create').length,
    update: plan.actions.filter(a => a.status === 'update').length,
    unchanged: plan.actions.filter(a => a.status === 'unchanged').length
  };

  return {
    mode: apply ? 'apply' : 'dry-run',
    repoRoot: plan.repoRoot,
    targetDir: plan.targetDir,
    counts,
    preDiffCount: counts.create + counts.update,
    postDiffCount: postDiffFiles.length,
    verifiedZeroDiff: apply ? postDiffFiles.length === 0 : null,
    changedFiles: plan.actions.filter(a => a.status !== 'unchanged').map(a => ({ path: a.destRel, action: a.status, source: a.source })),
    postDiffFiles,
    preservedExtraFiles: verifyPlan.preservedExtraFiles
  };
}

function parseArgs(argv) {
  let apply = false;
  let targetDir = process.env.MINDLOOM_DEPLOY_DIR || process.env.AGENT_MEMORY_DEPLOY_DIR || resolveConfiguredPaths().deployDir;
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--apply') apply = true;
    else if (a === '--dry-run') apply = false;
    else if (a === '--json') json = true;
    else if (a === '--target' && argv[i + 1]) targetDir = argv[++i];
  }
  return { apply, targetDir, json };
}

const isEntrypoint = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename);
if (isEntrypoint) {
  const args = parseArgs(process.argv.slice(2));
  const result = runDeploy(args);
  if (args.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(`[mem deploy:${result.mode}] target=${result.targetDir}\n`);
    process.stdout.write(
      `files=${result.counts.total} (create=${result.counts.create}, update=${result.counts.update}, unchanged=${result.counts.unchanged}) postDiff=${result.postDiffCount}\n`
    );
    if (result.changedFiles.length > 0) {
      for (const f of result.changedFiles) {
        process.stdout.write(`  - [${f.action}] ${f.path} <- ${f.source}\n`);
      }
    }
    if (result.preservedExtraFiles.length > 0) {
      process.stdout.write(`preserved extra files (${result.preservedExtraFiles.length}): ${result.preservedExtraFiles.join(', ')}\n`);
    }
  }
}
