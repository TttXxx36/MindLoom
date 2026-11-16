/**
 * 确定性 YAML Frontmatter 解析与安全序列化辅助模块
 * - 兼容 Windows UTF-8 BOM 与 CRLF/LF
 * - 仅匹配水平空白 [ \t]*，防止空字段跨行吞并下一行键值对
 * - 支持双引号/单引号内嵌异种引号与转义符、行内数组 [a, b]、多行列表 - item 及一级嵌套对象 (env, coverage)
 */

export function unquoteYamlScalar(rawVal) {
  if (rawVal === undefined || rawVal === null) return null;
  const trimmed = String(rawVal).trim();
  if (trimmed === '') return null;

  if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) {
    const inner = trimmed.slice(1, -1);
    return inner
      .replace(/\\"/g, '"')
      .replace(/\\\\/g, '\\')
      .replace(/\\n/g, '\n')
      .replace(/\\r/g, '\r')
      .replace(/\\t/g, '\t');
  }

  if (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2) {
    return trimmed.slice(1, -1).replace(/''/g, "'");
  }

  return trimmed;
}

export function parseInlineYamlArray(rawVal) {
  const trimmed = String(rawVal || '').trim();
  if (!trimmed.startsWith('[') || !trimmed.endsWith(']')) return null;
  const inner = trimmed.slice(1, -1).trim();
  if (!inner) return [];
  const items = [];
  let current = '';
  let quoteChar = null;
  let escaped = false;

  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === '\\' && quoteChar === '"') {
      current += ch;
      escaped = true;
      continue;
    }
    if ((ch === '"' || ch === "'") && !quoteChar) {
      quoteChar = ch;
      current += ch;
      continue;
    }
    if (ch === quoteChar) {
      quoteChar = null;
      current += ch;
      continue;
    }
    if (ch === ',' && !quoteChar) {
      const val = unquoteYamlScalar(current);
      if (val !== null && val !== '') items.push(val);
      current = '';
      continue;
    }
    current += ch;
  }
  const tail = unquoteYamlScalar(current);
  if (tail !== null && tail !== '') items.push(tail);
  return items;
}

/**
 * 解析 Markdown 文档的 YAML Frontmatter 与正文
 * @param {string} content
 * @returns {{ frontmatter: Record<string, any>, body: string, hasFrontmatter: boolean }}
 */
export function parseMarkdownFrontmatter(content) {
  const cleanContent = content ? String(content).replace(/^\uFEFF/, '') : '';
  const match = cleanContent.match(/^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/);
  if (!match) {
    return { frontmatter: {}, body: cleanContent, hasFrontmatter: false };
  }

  const yamlText = match[1];
  const body = cleanContent.slice(match[0].length);
  const lines = yamlText.split(/\r?\n/);
  const fm = {};

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim() || line.trim().startsWith('#')) {
      i++;
      continue;
    }

    const keyMatch = line.match(/^([A-Za-z0-9_-]+):[ \t]*(.*)$/);
    if (!keyMatch) {
      i++;
      continue;
    }

    const key = keyMatch[1];
    const rest = keyMatch[2];

    // 检查是否同行已有值
    if (rest.trim() !== '') {
      const inlineArr = parseInlineYamlArray(rest);
      if (inlineArr !== null) {
        fm[key] = inlineArr;
      } else {
        const unquoted = unquoteYamlScalar(rest);
        if (unquoted === null || unquoted === '') {
          fm[key] = null;
        } else if (rest.trim() === 'true') {
          fm[key] = true;
        } else if (rest.trim() === 'false') {
          fm[key] = false;
        } else {
          fm[key] = unquoted;
        }
      }
      i++;
      continue;
    }

    // 值为空，检查后续缩进行（数组 - item 或嵌套 map key: val）
    const listItems = [];
    const mapObj = {};
    let isList = false;
    let isMap = false;
    let j = i + 1;

    while (j < lines.length) {
      const sub = lines[j];
      if (!sub.trim()) {
        j++;
        continue;
      }
      if (!/^[ \t]+/.test(sub)) {
        break;
      }
      const listMatch = sub.match(/^[ \t]+-[ \t]*(.*)$/);
      if (listMatch) {
        isList = true;
        const val = unquoteYamlScalar(listMatch[1]);
        if (val !== null && val !== '') {
          listItems.push(val);
        }
        j++;
        continue;
      }
      const subKeyMatch = sub.match(/^[ \t]+([A-Za-z0-9_-]+):[ \t]*(.*)$/);
      if (subKeyMatch) {
        isMap = true;
        const subKey = subKeyMatch[1];
        const subValRaw = subKeyMatch[2];
        const subVal = unquoteYamlScalar(subValRaw);
        if (subVal !== null && /^\d+$/.test(subVal) && !subValRaw.trim().startsWith('"') && !subValRaw.trim().startsWith("'")) {
          mapObj[subKey] = Number(subVal);
        } else {
          mapObj[subKey] = subVal;
        }
        j++;
        continue;
      }
      break;
    }

    if (isList) {
      fm[key] = listItems;
      i = j;
    } else if (isMap) {
      fm[key] = mapObj;
      i = j;
    } else {
      fm[key] = null;
      i++;
    }
  }

  return {
    frontmatter: fm,
    body,
    hasFrontmatter: true
  };
}

/**
 * 安全序列化单行 YAML 标量（剥离换行防止 Frontmatter 注入）
 * @param {unknown} value
 * @returns {string}
 */
export function formatYamlScalar(value) {
  const singleLine = String(value ?? '').replace(/[\r\n]+/g, ' ').trim();
  return JSON.stringify(singleLine);
}
