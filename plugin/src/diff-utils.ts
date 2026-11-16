export interface DiffLine {
  kind: 'same' | 'add' | 'del';
  text: string;
}

export function computeSimpleLineDiff(beforeText: string, afterText: string): DiffLine[] {
  const a = String(beforeText || '').replace(/\r\n/g, '\n').split('\n');
  const b = String(afterText || '').replace(/\r\n/g, '\n').split('\n');

  // Use exact LCS line diff for normal note sizes; fall back to frequency-aware diff for huge inputs
  if (a.length <= 600 && b.length <= 600) {
    const m = a.length;
    const n = b.length;
    const dp: Int32Array[] = Array.from({ length: m + 1 }, () => new Int32Array(n + 1));
    for (let i = m - 1; i >= 0; i--) {
      for (let j = n - 1; j >= 0; j--) {
        if (a[i] === b[j]) {
          dp[i][j] = 1 + dp[i + 1][j + 1];
        } else {
          dp[i][j] = dp[i + 1][j] >= dp[i][j + 1] ? dp[i + 1][j] : dp[i][j + 1];
        }
      }
    }
    const out: DiffLine[] = [];
    let i = 0;
    let j = 0;
    while (i < m && j < n) {
      if (a[i] === b[j]) {
        out.push({ kind: 'same', text: `  ${a[i]}` });
        i++;
        j++;
      } else if (dp[i + 1][j] >= dp[i][j + 1]) {
        out.push({ kind: 'del', text: `- ${a[i]}` });
        i++;
      } else {
        out.push({ kind: 'add', text: `+ ${b[j]}` });
        j++;
      }
    }
    while (i < m) {
      out.push({ kind: 'del', text: `- ${a[i++]}` });
    }
    while (j < n) {
      out.push({ kind: 'add', text: `+ ${b[j++]}` });
    }
    return out;
  }

  const bCounts = new Map<string, number>();
  for (const line of b) bCounts.set(line, (bCounts.get(line) || 0) + 1);
  const aCounts = new Map<string, number>();
  for (const line of a) aCounts.set(line, (aCounts.get(line) || 0) + 1);

  const lines: DiffLine[] = [];
  for (const line of a) {
    const rem = bCounts.get(line) || 0;
    if (rem > 0) bCounts.set(line, rem - 1);
    else lines.push({ kind: 'del', text: `- ${line}` });
  }
  for (const line of b) {
    const rem = aCounts.get(line) || 0;
    if (rem > 0) {
      aCounts.set(line, rem - 1);
      lines.push({ kind: 'same', text: `  ${line}` });
    } else {
      lines.push({ kind: 'add', text: `+ ${line}` });
    }
  }
  return lines;
}

export function extractEventWikilinks(sources: string[] = []): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of sources) {
    const clean = formatWikilinkTarget(raw);
    if (/#\^event-\d+/i.test(clean) && !seen.has(clean)) {
      seen.add(clean);
      out.push(clean);
    }
  }
  return out;
}

export function formatWikilinkTarget(rawLink: string): string {
  return String(rawLink || '')
    .replace(/^\[\[/, '')
    .replace(/\]\]$/, '')
    .split('|')[0]
    .trim();
}
