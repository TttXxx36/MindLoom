import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..');

export function verifyReleaseAssets({ repoRoot = DEFAULT_REPO_ROOT, tag = null } = {}) {
  const rootPkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
  const pluginPkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'plugin', 'package.json'), 'utf8'));
  const manifest = JSON.parse(fs.readFileSync(path.join(repoRoot, 'plugin', 'manifest.json'), 'utf8'));

  if (rootPkg.version !== pluginPkg.version || rootPkg.version !== manifest.version) {
    throw new Error(
      `RELEASE_VERSION_MISMATCH: package.json=${rootPkg.version}, plugin/package.json=${pluginPkg.version}, plugin/manifest.json=${manifest.version}`
    );
  }

  if (tag) {
    const cleanTag = String(tag).replace(/^refs\/tags\//, '').replace(/^v/, '');
    if (cleanTag !== manifest.version) {
      throw new Error(`RELEASE_TAG_MISMATCH: tag=${tag} does not match manifest.version=${manifest.version}`);
    }
  }

  const distDir = path.join(repoRoot, 'plugin', 'dist');
  const requiredFiles = ['main.js', 'manifest.json', 'styles.css'];
  for (const name of requiredFiles) {
    const full = path.join(distDir, name);
    if (!fs.existsSync(full) || fs.statSync(full).size === 0) {
      throw new Error(`RELEASE_ARTIFACT_MISSING_OR_EMPTY: ${full}`);
    }
  }

  const distManifest = JSON.parse(fs.readFileSync(path.join(distDir, 'manifest.json'), 'utf8'));
  if (distManifest.version !== manifest.version || distManifest.id !== manifest.id) {
    throw new Error(
      `RELEASE_DIST_MANIFEST_MISMATCH: dist=${distManifest.id}@${distManifest.version}, src=${manifest.id}@${manifest.version}`
    );
  }

  const mainBytes = fs.statSync(path.join(distDir, 'main.js')).size;
  if (mainBytes >= 153600) {
    throw new Error(`RELEASE_BUNDLE_TOO_LARGE: main.js=${mainBytes} bytes (limit < 153600)`);
  }

  return {
    ok: true,
    version: manifest.version,
    mainBytes,
    assets: requiredFiles.map((name) => path.join(distDir, name))
  };
}

const isEntrypoint = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename);
if (isEntrypoint) {
  const tagIdx = process.argv.indexOf('--tag');
  const cliTag = tagIdx !== -1 ? process.argv[tagIdx + 1] : null;
  const envTag = process.env.RELEASE_TAG || process.env.GITHUB_REF_NAME || null;
  const tag = cliTag || envTag || null;
  const res = verifyReleaseAssets({ tag });
  process.stdout.write(`RELEASE ASSETS OK: v${res.version} (main.js=${res.mainBytes} bytes)\n`);
}
