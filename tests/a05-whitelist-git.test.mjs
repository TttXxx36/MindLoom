import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  isWhitelistedVaultPath,
  commitPublishedFile,
  retryGitCommit
} from '../src/git/repo-manager.mjs';

test('A05: 白名单 Git 边界管理与脏暂存隔离', async (t) => {
  const baseDir = path.resolve('.tmp/test-a05-' + Date.now());
  const vaultDir = path.join(baseDir, 'AgentMemory');
  const dataDir = path.join(baseDir, 'AgentMemory-Data');

  fs.mkdirSync(vaultDir, { recursive: true });
  fs.mkdirSync(path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks'), { recursive: true });
  fs.mkdirSync(path.join(dataDir, 'raw'), { recursive: true });
  fs.mkdirSync(path.join(dataDir, 'staging'), { recursive: true });

  // 初始化 Git 仓库
  execFileSync('git', ['init'], { cwd: vaultDir });
  execFileSync('git', ['config', 'core.quotepath', 'false'], { cwd: vaultDir });
  execFileSync('git', ['config', 'user.name', 'Tester'], { cwd: vaultDir });
  execFileSync('git', ['config', 'user.email', 'tester@example.com'], { cwd: vaultDir });

  // 初始提交一个 README
  fs.writeFileSync(path.join(vaultDir, '首页.md'), '# 首页', 'utf8');
  execFileSync('git', ['add', '首页.md'], { cwd: vaultDir });
  execFileSync('git', ['commit', '-m', 'chore: initial commit'], { cwd: vaultDir });

  t.after(() => {
    try {
      fs.rmSync(baseDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  await t.test('1. 白名单路径校验：仅允许 Vault 正式文件，严禁 Data 目录文件', () => {
    const validNote = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-001.md');
    const validView = path.join(vaultDir, '50_Bases_Views', '知识总览.base');
    const invalidRaw = path.join(dataDir, 'raw', 'session.jsonl');
    const invalidStaging = path.join(dataDir, 'staging', 'stg-001.md');
    const invalidDb = path.join(dataDir, 'runtime', 'state.sqlite');

    assert.equal(isWhitelistedVaultPath(vaultDir, validNote), true);
    assert.equal(isWhitelistedVaultPath(vaultDir, validView), true);
    assert.equal(isWhitelistedVaultPath(vaultDir, invalidRaw), false);
    assert.equal(isWhitelistedVaultPath(vaultDir, invalidStaging), false);
    assert.equal(isWhitelistedVaultPath(vaultDir, invalidDb), false);

    // 尝试提交非法路径应抛出错误
    assert.throws(() => {
      commitPublishedFile({
        vaultDir,
        filePath: invalidRaw,
        commitMessage: 'feat: add raw session'
      });
    }, /白名单/);
  });

  await t.test('2. 脏工作区与脏暂存隔离：仅精确暂存目标笔记，绝不吸收无关修改', () => {
    // 模拟用户在工作区手工创建了一个未暂存文件
    const dirtyFile = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', '用户草稿.md');
    fs.writeFileSync(dirtyFile, '未经审核的用户草稿内容', 'utf8');

    // 模拟用户在首页做了一个修改并已手工 git add 到暂存区
    fs.appendFileSync(path.join(vaultDir, '首页.md'), '\n用户手工增加的首页导航', 'utf8');
    execFileSync('git', ['add', '首页.md'], { cwd: vaultDir });

    // 现在发布新笔记
    const targetFile = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-001.md');
    fs.writeFileSync(targetFile, '---\nid: "KN-001"\ntitle: 正式笔记\n---\n正文内容', 'utf8');

    const result = commitPublishedFile({
      vaultDir,
      filePath: targetFile,
      commitMessage: 'feat(memory): publish KN-001'
    });

    assert.equal(result.success, true);
    assert.equal(result.gitState, 'committed');

    // 验证：最新提交中【只包含】KN-001.md，绝对不包含首页.md或草稿
    const showDiff = execFileSync('git', ['show', '--name-only', '--format=', 'HEAD'], { cwd: vaultDir, encoding: 'utf8' });
    const committedFiles = showDiff.trim().split(/\r?\n/).map(s => s.replace(/\\/g, '/'));

    assert.equal(committedFiles.length, 1);
    assert.ok(committedFiles[0].includes('KN-001.md'));

    // 验证：用户的草稿依然是未暂存状态
    const statusOut = execFileSync('git', ['status', '--porcelain'], { cwd: vaultDir, encoding: 'utf8' });
    assert.ok(statusOut.includes('用户草稿.md'));
    assert.ok(statusOut.includes('首页.md')); // 用户手工暂存的修改依然保留在暂存区未被合入
  });

  await t.test('3. 提交失败隔离：失败时不回滚已发布笔记，仅将 gitState 标为 failed', () => {
    const failedTarget = path.join(vaultDir, '30_Knowledge_Notes', 'Playbooks', 'KN-002.md');
    fs.writeFileSync(failedTarget, '---\nid: "KN-002"\ntitle: 提交失败测试\n---\n正文内容', 'utf8');

    // 注入一个会抛错的 gitRunner 模拟 Git 失败（如 index.lock 冲突）
    const failingGitRunner = () => {
      throw new Error('fatal: Unable to create index.lock: File exists.');
    };

    const failResult = commitPublishedFile({
      vaultDir,
      filePath: failedTarget,
      commitMessage: 'feat(memory): publish KN-002',
      gitRunner: failingGitRunner
    });

    assert.equal(failResult.success, false);
    assert.equal(failResult.gitState, 'failed');
    assert.ok(failResult.error.includes('index.lock'));

    // 核心断言：物理文件完好无损保留在磁盘上（files_published 保持不变，零回滚）
    assert.ok(fs.existsSync(failedTarget));
    assert.ok(fs.readFileSync(failedTarget, 'utf8').includes('提交失败测试'));

    // 补救重试：使用正常 runner 补提交
    const retryResult = retryGitCommit({
      vaultDir,
      filePath: failedTarget,
      commitMessage: 'feat(memory): retry publish KN-002'
    });

    assert.equal(retryResult.success, true);
    assert.equal(retryResult.gitState, 'committed');
  });
});
