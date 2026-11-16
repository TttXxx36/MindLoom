import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import esbuild from 'esbuild';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const isProd = process.argv[2] === 'production';

const distDir = path.join(__dirname, 'dist');
fs.mkdirSync(distDir, { recursive: true });

const context = await esbuild.context({
  entryPoints: [path.join(__dirname, 'src', 'main.ts')],
  bundle: true,
  external: [
    'obsidian',
    'electron',
    '@codemirror/autocomplete',
    '@codemirror/collab',
    '@codemirror/commands',
    '@codemirror/language',
    '@codemirror/lint',
    '@codemirror/search',
    '@codemirror/state',
    '@codemirror/view',
    '@lezer/common',
    '@lezer/highlight',
    '@lezer/lr',
    'node:child_process',
    'node:fs',
    'node:os',
    'node:path',
    'child_process',
    'fs',
    'os',
    'path'
  ],
  format: 'cjs',
  target: 'es2022',
  logLevel: 'info',
  sourcemap: isProd ? false : 'inline',
  treeShaking: true,
  minify: isProd,
  outfile: path.join(distDir, 'main.js')
});

if (isProd) {
  await context.rebuild();
  await context.dispose();
  for (const staticFile of ['manifest.json', 'styles.css']) {
    const src = path.join(__dirname, staticFile);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, path.join(distDir, staticFile));
    }
  }
} else {
  await context.watch();
}
