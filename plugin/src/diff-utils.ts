export interface DiffLine {
  kind: 'same' | 'add' | 'del';
  text: string;
}

export function computeSimpleLineDiff(beforeText: string, afterText: string): DiffLine[] {
  const a = String(beforeText || '').replace(/\r\n/g, '\n').split('\n');
  const b = String(afterText || '').replace(/\r\n/g, '\n').split('\n');
  const aSet = new Set(a);
  const bSet = new Set(b);

  const lines: DiffLine[] = [];
  for (const line of a) {
    if (!bSet.has(line)) {
      lines.push({ kind: 'del', text: `- ${line}` });
    }
  }
  for (const line of b) {
    if (!aSet.has(line)) {
      lines.push({ kind: 'add', text: `+ ${line}` });
    } else {
      lines.push({ kind: 'same', text: `  ${line}` });
    }
  }
  return lines;
}

export function extractEventWikilinks(sources: string[] = []): string[] {
  const out: string[] = [];
  for (const raw of sources) {
    const clean = String(raw || '').replace(/^\[\[/, '').replace(/\]\]$/, '').trim();
    if (/#\^event-\d+/i.test(clean)) {
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
