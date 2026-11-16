import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  sanitizeTitle,
  formatFileName,
  resolveTargetFilePath,
  extractUuidSuffix
} from '../src/storage/path-sanitizer.mjs';

test('A03: Windows 路径清洗与 R7 短文件名碰撞消歧协议', async (t) => {
  const testDir = path.resolve('.tmp/test-a03-' + Date.now());
  fs.mkdirSync(testDir, { recursive: true });

  t.after(() => {
    try {
      fs.rmSync(testDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  await t.test('1. Windows 非法字符过滤与控制字符清洗', () => {
    const raw = '非法<字符>:测试"路径"/\\|管道?通配*与\x00\x1f控制符';
    const clean = sanitizeTitle(raw);
    assert.equal(clean.includes('<'), false);
    assert.equal(clean.includes('>'), false);
    assert.equal(clean.includes(':'), false);
    assert.equal(clean.includes('"'), false);
    assert.equal(clean.includes('/'), false);
    assert.equal(clean.includes('\\'), false);
    assert.equal(clean.includes('|'), false);
    assert.equal(clean.includes('?'), false);
    assert.equal(clean.includes('*'), false);
    assert.equal(clean.includes('\x00'), false);
    assert.equal(clean.includes('\x1f'), false);
  });

  await t.test('2. 首尾空格与句点剔除', () => {
    assert.equal(sanitizeTitle('  ..测试标题..  '), '测试标题');
    assert.equal(sanitizeTitle('.点开头结尾.'), '点开头结尾');
  });

  await t.test('3. Windows 保留设备名拦截与重命名', () => {
    assert.equal(sanitizeTitle('CON'), '_CON');
    assert.equal(sanitizeTitle('aux'), '_aux');
    assert.equal(sanitizeTitle('NUL'), '_NUL');
    assert.equal(sanitizeTitle('COM1'), '_COM1');
    assert.equal(sanitizeTitle('LPT9'), '_LPT9');
    assert.equal(sanitizeTitle('prn.txt'), '_prn.txt');
  });

  await t.test('4. 标题长度截断 (<= 40 字符且 UTF-8 <= 120 字节)', () => {
    const longChinese = '这是一个非常非常非常非常非常非常非常非常非常非常长的一个中文标题用来测试截断功能是否完全正常';
    const clean = sanitizeTitle(longChinese);
    assert.ok(clean.length <= 40, `长度 ${clean.length} 超过 40`);
    assert.ok(Buffer.byteLength(clean, 'utf8') <= 120, 'UTF-8 字节数超过 120');
  });

  await t.test('5. 默认短文件名格式生成 (<前缀>-<YYYYMMDD>-<UUID末6位>_<简短中文标题>.md)', () => {
    const fileName = formatFileName({
      prefix: 'KN',
      dateStr: '20261110',
      uuid: 'KN-019316a8-7c40-7000-8000-1a2b3c4d5e6f',
      title: '容器端口绑定失败排查'
    });
    assert.equal(fileName, 'KN-20261110-4d5e6f_容器端口绑定失败排查.md');
  });

  await t.test('6. 同作业重试场景：复用原路径', () => {
    const uuid1 = 'KN-019316a8-7c40-7000-8000-1a2b3c4d5e6f';
    const filePath = path.join(testDir, 'KN-20261110-4d5e6f_容器端口绑定失败排查.md');
    fs.writeFileSync(filePath, `---\nid: "${uuid1}"\ntitle: 容器端口绑定失败排查\n---\n原始内容`, 'utf8');

    const result = resolveTargetFilePath({
      targetDir: testDir,
      prefix: 'KN',
      dateStr: '20261110',
      uuid: uuid1,
      title: '容器端口绑定失败排查'
    });

    assert.equal(result.targetPath, filePath);
    assert.equal(result.isRetry, true);
    assert.equal(result.collided, false);
  });

  await t.test('7. 短文件名碰撞场景：扩展为 12 位 UUID，严禁覆写原文件', () => {
    const uuid1 = 'KN-019316a8-7c40-7000-8000-1111114d5e6f';
    const uuid2 = 'KN-019316a8-7c40-7000-8000-2222224d5e6f';

    const file1Path = path.join(testDir, 'KN-20261110-4d5e6f_短哈希碰撞测试.md');
    fs.writeFileSync(file1Path, `---\nid: "${uuid1}"\ntitle: 短哈希碰撞测试\n---\n第一篇笔记原始正文`, 'utf8');

    // 第二篇笔记具有不同 UUID，但末 6 位相同
    const result2 = resolveTargetFilePath({
      targetDir: testDir,
      prefix: 'KN',
      dateStr: '20261110',
      uuid: uuid2,
      title: '短哈希碰撞测试'
    });

    assert.equal(result2.collided, true);
    assert.equal(result2.expanded, true);
    assert.notEqual(result2.targetPath, file1Path);
    assert.ok(result2.targetPath.includes('2222224d5e6f'), `目标路径应包含 12 位 UUID 后缀: ${result2.targetPath}`);

    // 写入第二篇笔记
    fs.writeFileSync(result2.targetPath, `---\nid: "${uuid2}"\ntitle: 短哈希碰撞测试\n---\n第二篇笔记正文`, 'utf8');

    // 验证原第一篇文件完好无损
    const file1Content = fs.readFileSync(file1Path, 'utf8');
    assert.ok(file1Content.includes('第一篇笔记原始正文'));
    assert.ok(file1Content.includes(uuid1));
  });
});
