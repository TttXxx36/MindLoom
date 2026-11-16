/**
 * 全出口实时脱敏与全通道清洗器 (R3 / B02)
 * - 支持同会话一致的结构化占位符 ([TOKEN_1], [HOST_1], [CONN_1], [PRIVATE_KEY_1], [COOKIE_1], [SECRET_1])
 * - 覆盖 Exit A (外部模型 API 外发包) 与 Exit B (stdout, stderr, 异常堆栈, 结构化返回值, 预览文件)
 */

export const SANITIZER_VERSION = 'v2.4.2';

const ALREADY_REDACTED_RE = /^\[(?:TOKEN|HOST|CONN|PRIVATE_KEY|COOKIE|SECRET|CRED|REDACTED_RAW_PATH)(?:_\d+)?\]$/;

// 匹配标准 UUID / 带前缀 UUID，防止高熵检测误伤主键
const UUID_LIKE_RE = /^(?:[A-Za-z]+-)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

// 匹配标准 SHA-256 纯十六进制
const PURE_HEX_RE = /^[0-9a-fA-F]{32,128}$/;

// 匹配连接串中内嵌账号密码或 URL 凭据
const EMBEDDED_CRED_URL_RE = /\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|amqps|mssql|https?):\/\/([^\s:/@"'<>]+):([^\s/@"'<>]+)@([^\s/:,"'<>]+(?::\d+)?)/gi;

// 匹配私钥块
const PRIVATE_KEY_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;

// 匹配 JSON 键形式或 HTTP 头形式的 Cookie / Set-Cookie
const JSON_COOKIE_RE = /(["'])(Set-Cookie|Cookie)\1([ \t]*:[ \t]*)(["'])([^"'\r\n]+)\4/gi;
const COOKIE_HEADER_RE = /\b(Set-Cookie|Cookie)[ \t]*:[ \t]*([^\r\n"]+)/gi;

// 匹配 Authorization 头 (Bearer / Basic / Token) 及独立 Bearer / Basic Base64 / JWT
const AUTH_HEADER_CRED_RE = /(["']?\b(?:proxy-)?authorization["']?[ \t]*[:=][ \t]*["']?(?:Bearer|Basic|Token)[ \t]+)([^\s"',}\r\n]+)/gi;
const BEARER_RE = /\b(Bearer)\s+([A-Za-z0-9\-._~+/]+=*)/gi;
const BASIC_CRED_RE = /\b(Basic)[ \t]+([A-Za-z0-9+/]+={0,2})(?=$|[^A-Za-z0-9+/=])/g;
const JWT_RE = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;

// 常见已知前缀 API Key (动态拼接模式字符，避免静态扫描误报；使用线性 + 配合回调长度核验防止 V8 大字符串栈溢出)
const PREFIXED_KEY_RE = new RegExp(
  '\\b(?:' +
    ['sk', '[A-Za-z0-9_-]+'].join('-') + '|' +
    ['sk', '(?:live|test|proj)', '[A-Za-z0-9_]+'].join('_') + '|' +
    ['rk', '(?:live|test)', '[A-Za-z0-9_]+'].join('_') + '|' +
    ['gh[pousr]', '[A-Za-z0-9_]+'].join('_') + '|' +
    ['github', 'pat', '[A-Za-z0-9_]+'].join('_') + '|' +
    ['glpat', '[A-Za-z0-9_-]+'].join('-') + '|' +
    ['npm', '[A-Za-z0-9]+'].join('_') + '|' +
    'AKIA[0-9A-Z]{16}' + '|' +
    'AIza[0-9A-Za-z_-]+' + '|' +
    ['xox[baprs]', '[0-9A-Za-z-]+'].join('-') +
  ')\\b',
  'g'
);

function isValidPrefixedApiKey(tok) {
  if (!tok) return false;
  if (tok.startsWith('sk_')) {
    const idx = tok.indexOf('_', 3);
    return idx !== -1 && tok.length - (idx + 1) >= 16;
  }
  if (tok.startsWith('rk_')) {
    const idx = tok.indexOf('_', 3);
    return idx !== -1 && tok.length - (idx + 1) >= 16;
  }
  if (tok.startsWith('sk-')) return tok.length >= 19;
  if (/^gh[pousr]_/.test(tok)) return tok.length >= 20;
  if (tok.startsWith('github_pat_')) return tok.length >= 31;
  if (tok.startsWith('glpat-')) return tok.length >= 22;
  if (tok.startsWith('npm_')) return tok.length >= 24;
  if (tok.startsWith('AKIA')) return tok.length === 20;
  if (tok.startsWith('AIza')) return tok.length >= 24;
  if (/^xox[baprs]-/.test(tok)) return tok.length >= 21;
  return false;
}

function isValidJwtToken(tok) {
  const parts = String(tok || '').split('.');
  return parts.length === 3 && parts[0].length >= 11 && parts[1].length >= 8 && parts[2].length >= 8;
}

const SECRET_KEY_NAMES =
  'api[_-]?key|apikey|x-api-key|access[_-]?token|auth[_-]?token|refresh[_-]?token|id[_-]?token|' +
  'secret[_-]?key|client[_-]?secret|session[_-]?secret|private[_-]?key|account[_-]?key|' +
  'shared[_-]?access[_-]?key|password|passwd|pwd|secret|token|credential|authorization';

// 支持未加引号 (api_key=val / api_key: val) 与 JSON/YAML 加引号 ("api_key": "val") 的赋值形式
const KEY_VALUE_SECRET_RE = new RegExp(
  `(["']?)\\b(${SECRET_KEY_NAMES})\\b\\1([ \\t]*[:=][ \\t]*)(["']?)([^\\s"'\\r\\n,;}{]+)\\4`,
  'gi'
);
const CLI_FLAG_SECRET_RE = /(--?(?:api-key|token|secret|password|passwd))\s+(["']?)([^\s"'\r\n]+)\2/gi;
const CONN_PARAM_SECRET_RE = /\b(Password|Pwd|SharedAccessKey|AccountKey)\s*=\s*([^;\r\n"']+)/gi;

// raw 目录泄露路径（覆盖 AgentMemory-Data/raw 及任意绝对/相对 raw/ 文件路径）
const RAW_PATH_RE = /(?:[A-Za-z]:[\\/]{1,2}[^\s"'<>|*?]*?(?:AgentMemory-Data[\\/]+raw|[\\/]raw)(?:[\\/]+[^\s"'<>|*?\r\n]*)?|(?<![a-zA-Z0-9:])\/[^\s"'<>|*?]*?(?:AgentMemory-Data\/+raw|\/raw)(?:\/+[^\s"'<>|*?\r\n]*)?|[^\s"'<>|*?]*?AgentMemory-Data[\\/]+raw(?:[\\/]+[^\s"'<>|*?\r\n]*)?)/gi;
const RELATIVE_RAW_PATH_RE = /(?:^|[\s("':=])((?:\.\.?[\\/]+)*raw[\\/]+[^\s"'<>|*?\r\n]+)/gi;

function shannonEntropy(str) {
  const counts = new Map();
  for (const ch of str) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const SYSTEM_ID_PREFIX_RE = /^(?:KN|PROP|EV|SES|EGR|BKP|HC|DR|item|stg)-[A-Za-z0-9-]+$/i;
const SNAPSHOT_ID_RE = /^[a-z0-9_-]+-[0-9a-f]{32,64}$/i;
const BENIGN_LITERAL_VALUES = new Set(['null', 'none', 'undefined', 'true', 'false', 'empty', 'bearer', 'basic', 'token']);

function isBenignSecretCandidate(val) {
  if (!val) return true;
  const trimmed = String(val).trim();
  if (trimmed.length < 4) return true;
  if (ALREADY_REDACTED_RE.test(trimmed)) return true;
  if (BENIGN_LITERAL_VALUES.has(trimmed.toLowerCase())) return true;
  if (UUID_LIKE_RE.test(trimmed)) return true;
  if (SYSTEM_ID_PREFIX_RE.test(trimmed)) return true;
  if (SNAPSHOT_ID_RE.test(trimmed)) return true;
  if (/^\d{1,5}$/.test(trimmed)) return true;
  return false;
}

function isLikelyHighEntropySecret(token) {
  if (!token || token.length < 24 || token.length > 256) return false;
  if (ALREADY_REDACTED_RE.test(token)) return false;
  if (UUID_LIKE_RE.test(token)) return false;
  if (PURE_HEX_RE.test(token)) return false;
  if (SYSTEM_ID_PREFIX_RE.test(token)) return false;
  if (SNAPSHOT_ID_RE.test(token)) return false;
  if (token.includes('/') || token.includes('\\') || token.includes('[[') || token.includes(']]')) return false;
  if (/^[a-zA-Z_]+$/.test(token) || /^[a-z0-9_]+$/.test(token)) return false;

  const segments = token.split('-');
  const hasHighEntropySegment = segments.some((seg) => {
    if (seg.length < 20) return false;
    return /[a-z]/.test(seg) && /[A-Z]/.test(seg) && /[0-9+/=]/.test(seg) && shannonEntropy(seg) >= 3.7;
  });
  if (!hasHighEntropySegment) return false;

  return shannonEntropy(token) >= 3.7;
}

/**
 * 创建会话级一致脱敏器（同会话相同秘密永远映射到相同占位符）
 * @returns {{ sanitize: (text: string) => { text: string, redactions: Array<object> }, getStats: () => object }}
 */
export function createSessionSanitizer() {
  const counters = {
    TOKEN: 0,
    HOST: 0,
    CONN: 0,
    PRIVATE_KEY: 0,
    COOKIE: 0,
    SECRET: 0
  };
  const mapping = new Map();

  function getPlaceholder(type, rawValue) {
    const key = `${type}::${rawValue}`;
    if (mapping.has(key)) {
      return mapping.get(key);
    }
    counters[type] = (counters[type] || 0) + 1;
    const placeholder = `[${type}_${counters[type]}]`;
    mapping.set(key, placeholder);
    return placeholder;
  }

  function sanitize(input) {
    if (input === null || input === undefined) {
      return { text: '', redactions: [] };
    }
    let text = String(input);
    const redactions = [];

    // 1. 私钥块
    text = text.replace(PRIVATE_KEY_RE, (match) => {
      const ph = getPlaceholder('PRIVATE_KEY', match);
      redactions.push({ type: 'PRIVATE_KEY', placeholder: ph });
      return ph;
    });

    // 2. 带账号密码的连接串 / URL
    text = text.replace(EMBEDDED_CRED_URL_RE, (match, proto, user, pass, host) => {
      const connPh = getPlaceholder('CONN', `${proto}://${user}:${pass}`);
      const hostPh = getPlaceholder('HOST', host);
      redactions.push({ type: 'CONN', placeholder: connPh });
      redactions.push({ type: 'HOST', placeholder: hostPh });
      return `${proto}://${connPh}@${hostPh}`;
    });

    // 3. ADO / ODBC Password=... 参数
    text = text.replace(CONN_PARAM_SECRET_RE, (match, key, val) => {
      if (ALREADY_REDACTED_RE.test(val.trim())) return match;
      const ph = getPlaceholder('SECRET', val.trim());
      redactions.push({ type: 'CONN_PARAM', placeholder: ph });
      return `${key}=${ph}`;
    });

    // 4. Cookie / Set-Cookie 头及 JSON 字段
    text = text.replace(JSON_COOKIE_RE, (match, kq, header, sep, vq, val) => {
      if (ALREADY_REDACTED_RE.test(val.trim())) return match;
      const ph = getPlaceholder('COOKIE', val.trim());
      redactions.push({ type: 'COOKIE', placeholder: ph });
      return `${kq}${header}${kq}${sep}${vq}${ph}${vq}`;
    });
    text = text.replace(COOKIE_HEADER_RE, (match, header, val) => {
      if (ALREADY_REDACTED_RE.test(val.trim())) return match;
      const ph = getPlaceholder('COOKIE', val.trim());
      redactions.push({ type: 'COOKIE', placeholder: ph });
      return `${header}: ${ph}`;
    });

    // 5. Authorization 头 (Bearer / Basic / Token), 独立 Bearer & JWT
    text = text.replace(AUTH_HEADER_CRED_RE, (match, prefix, tok) => {
      if (ALREADY_REDACTED_RE.test(tok)) return match;
      const ph = getPlaceholder('TOKEN', tok);
      redactions.push({ type: 'AUTH_HEADER', placeholder: ph });
      return `${prefix}${ph}`;
    });

    text = text.replace(BEARER_RE, (match, prefix, tok) => {
      if (tok.length < 10 || ALREADY_REDACTED_RE.test(tok)) return match;
      const ph = getPlaceholder('TOKEN', tok);
      redactions.push({ type: 'BEARER', placeholder: ph });
      return `${prefix} ${ph}`;
    });

    text = text.replace(BASIC_CRED_RE, (match, prefix, tok) => {
      if (tok.length < 10 || ALREADY_REDACTED_RE.test(tok)) return match;
      const looksLikeBase64Cred = /[0-9+/=]/.test(tok) || /[A-Z]/.test(tok.slice(1));
      if (!looksLikeBase64Cred) return match;
      const ph = getPlaceholder('TOKEN', tok);
      redactions.push({ type: 'BASIC_AUTH', placeholder: ph });
      return `${prefix} ${ph}`;
    });

    text = text.replace(JWT_RE, (match) => {
      if (!isValidJwtToken(match)) return match;
      const ph = getPlaceholder('TOKEN', match);
      redactions.push({ type: 'JWT', placeholder: ph });
      return ph;
    });

    // 6. 已知前缀 API Key
    text = text.replace(PREFIXED_KEY_RE, (match) => {
      if (!isValidPrefixedApiKey(match)) return match;
      const ph = getPlaceholder('TOKEN', match);
      redactions.push({ type: 'API_KEY', placeholder: ph });
      return ph;
    });

    // 7. Key-Value (支持 JSON 引号键值与常规键值) & CLI 参数形式秘密
    text = text.replace(KEY_VALUE_SECRET_RE, (match, keyQuote, key, sep, valQuote, val) => {
      if (isBenignSecretCandidate(val)) return match;
      const ph = getPlaceholder('SECRET', val);
      redactions.push({ type: 'KV_SECRET', placeholder: ph });
      return `${keyQuote}${key}${keyQuote}${sep}${valQuote}${ph}${valQuote}`;
    });

    text = text.replace(CLI_FLAG_SECRET_RE, (match, flag, quote, val) => {
      if (isBenignSecretCandidate(val)) return match;
      const ph = getPlaceholder('SECRET', val);
      redactions.push({ type: 'CLI_SECRET', placeholder: ph });
      return `${flag} ${quote}${ph}${quote}`;
    });

    // 8. 残留高熵随机密钥串探测 (使用线性 + 替代 {24,} 与 \b，避免多 MB base64 触发 V8 正则栈溢出)
    text = text.replace(/[A-Za-z0-9_+/=-]+/g, (token) => {
      if (!isLikelyHighEntropySecret(token)) return token;
      const ph = getPlaceholder('SECRET', token);
      redactions.push({ type: 'HIGH_ENTROPY', placeholder: ph });
      return ph;
    });

    return { text, redactions };
  }

  return {
    sanitize,
    getStats() {
      return { ...counters, uniqueSecrets: mapping.size };
    }
  };
}

const RAW_TRIGGER_RE = /(?:AgentMemory-Data[\\/]+|[\\/])raw/i;
const REL_RAW_TRIGGER_RE = /raw[\\/]/i;

function scrubRawPathsLinear(text) {
  if (!text || !/raw/i.test(text)) return text;
  let out = text;
  if (RAW_TRIGGER_RE.test(out)) {
    out = out.replace(/[^\s"'<>|*?]+/g, (token) => {
      if (!RAW_TRIGGER_RE.test(token)) return token;
      if (token.length <= 4096) {
        return token.replace(RAW_PATH_RE, '[REDACTED_RAW_PATH]');
      }
      // 防止超长无空白连续串触发 O(L^2) 回溯：仅在包含 raw 片段的安全边界窗口内清洗
      return token
        .replace(
          /[A-Za-z]:[\\/]{1,2}[^\s"'<>|*?;,(){}[\]]{0,1024}?(?:AgentMemory-Data[\\/]+raw|[\\/]raw)(?:[\\/]+[^\s"'<>|*?\r\n]{0,1024})?/gi,
          '[REDACTED_RAW_PATH]'
        )
        .replace(
          /[^\s"'<>|*?;,(){}[\]]{0,512}?AgentMemory-Data[\\/]+raw(?:[\\/]+[^\s"'<>|*?\r\n]{0,1024})?/gi,
          '[REDACTED_RAW_PATH]'
        );
    });
  }
  if (REL_RAW_TRIGGER_RE.test(out)) {
    out = out.replace(RELATIVE_RAW_PATH_RE, (m, p1) => m.replace(p1, '[REDACTED_RAW_PATH]'));
  }
  return out;
}

/**
 * 清理文本中的敏感凭据与 raw/ 源路径（用于 Exit B 全通道过滤）
 * @param {string} text
 * @param {{ sanitizer?: ReturnType<typeof createSessionSanitizer>, scrubRawPaths?: boolean }} [options]
 * @returns {string}
 */
export function sanitizeOutputText(text, options = {}) {
  if (text === null || text === undefined) return '';
  const sanitizer = options.sanitizer || createSessionSanitizer();
  const scrubRawPaths = options.scrubRawPaths !== false;

  let out = sanitizer.sanitize(String(text)).text;
  if (scrubRawPaths) {
    out = scrubRawPathsLinear(out);
  }
  return out;
}

/**
 * 递归清洗结构化返回值（Exit B：剥离非 sanitized 文档，清洗全部字符串字段与路径）
 * @param {any} value
 * @param {{ sanitizer?: ReturnType<typeof createSessionSanitizer> }} [options]
 * @returns {any}
 */
export function sanitizeObjectForExitB(value, options = {}) {
  const sanitizer = options.sanitizer || createSessionSanitizer();

  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    return sanitizeOutputText(value, { sanitizer, scrubRawPaths: true });
  }
  if (typeof value !== 'object') return value;

  if (Array.isArray(value)) {
    const cleaned = [];
    for (const item of value) {
      if (item && typeof item === 'object' && !Array.isArray(item) && 'privacy' in item && item.privacy !== 'sanitized') {
        continue;
      }
      cleaned.push(sanitizeObjectForExitB(item, { sanitizer }));
    }
    return cleaned;
  }

  // 若对象本身标记为非 sanitized 文档，直接剥离返回 null
  if ('privacy' in value && value.privacy !== 'sanitized') {
    return null;
  }

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (k === 'rawPath' || k === 'raw_path') {
      out[k] = '[REDACTED_RAW_PATH]';
      continue;
    }
    out[k] = sanitizeObjectForExitB(v, { sanitizer });
  }
  return out;
}

/**
 * 清洗异常消息与堆栈，防止 Exit B stderr/异常堆栈泄露秘密或 raw/ 路径
 * @param {unknown} err
 * @param {{ includeStack?: boolean }} [options]
 * @returns {string}
 */
export function formatSafeErrorForExitB(err, options = {}) {
  const sanitizer = createSessionSanitizer();
  const rawMessage = err instanceof Error ? err.message : String(err);
  const safeMessage = sanitizeOutputText(rawMessage, { sanitizer, scrubRawPaths: true });
  if (options.includeStack && err instanceof Error && err.stack) {
    const safeStack = sanitizeOutputText(err.stack, { sanitizer, scrubRawPaths: true });
    return `${safeMessage}\n${safeStack}`;
  }
  return safeMessage;
}

/**
 * 审计文本是否仍包含未脱敏的可疑秘密模式（供测试与出口门禁使用）
 * @param {string} text
 * @returns {{ clean: boolean, findings: string[] }}
 */
export function detectResidualSecrets(text) {
  if (!text) return { clean: true, findings: [] };
  const s = String(text);
  const findings = [];

  if (PRIVATE_KEY_RE.test(s)) findings.push('private_key');
  PRIVATE_KEY_RE.lastIndex = 0;

  if (EMBEDDED_CRED_URL_RE.test(s)) findings.push('embedded_cred_url');
  EMBEDDED_CRED_URL_RE.lastIndex = 0;

  let prefMatch;
  while ((prefMatch = PREFIXED_KEY_RE.exec(s)) !== null) {
    if (isValidPrefixedApiKey(prefMatch[0])) {
      findings.push('prefixed_api_key');
      break;
    }
  }
  PREFIXED_KEY_RE.lastIndex = 0;

  let jwtMatch;
  while ((jwtMatch = JWT_RE.exec(s)) !== null) {
    if (isValidJwtToken(jwtMatch[0])) {
      findings.push('jwt_token');
      break;
    }
  }
  JWT_RE.lastIndex = 0;

  if (AUTH_HEADER_CRED_RE.test(s)) {
    const m = s.match(AUTH_HEADER_CRED_RE) || [];
    if (m.some(part => !/\[TOKEN_\d+\]$/.test(part.trim()))) {
      findings.push('auth_header_cred');
    }
  }
  AUTH_HEADER_CRED_RE.lastIndex = 0;

  let bearerMatch;
  while ((bearerMatch = BEARER_RE.exec(s)) !== null) {
    const tok = bearerMatch[2];
    if (tok.length >= 10 && !ALREADY_REDACTED_RE.test(tok)) {
      findings.push('bearer_token');
      break;
    }
  }
  BEARER_RE.lastIndex = 0;

  let basicMatch;
  while ((basicMatch = BASIC_CRED_RE.exec(s)) !== null) {
    const tok = basicMatch[2];
    if (tok.length >= 10 && !ALREADY_REDACTED_RE.test(tok) && (/[0-9+/=]/.test(tok) || /[A-Z]/.test(tok.slice(1)))) {
      findings.push('basic_auth_cred');
      break;
    }
  }
  BASIC_CRED_RE.lastIndex = 0;

  if (JSON_COOKIE_RE.test(s)) {
    const m = s.match(JSON_COOKIE_RE) || [];
    if (m.some(line => !/\[COOKIE_\d+\]/.test(line))) {
      findings.push('cookie_header');
    }
  }
  JSON_COOKIE_RE.lastIndex = 0;

  if (COOKIE_HEADER_RE.test(s)) {
    const m = s.match(COOKIE_HEADER_RE) || [];
    if (m.some(line => !/\[COOKIE_\d+\]/.test(line))) {
      findings.push('cookie_header');
    }
  }
  COOKIE_HEADER_RE.lastIndex = 0;

  let kvMatch;
  while ((kvMatch = KEY_VALUE_SECRET_RE.exec(s)) !== null) {
    if (!isBenignSecretCandidate(kvMatch[5])) {
      findings.push('kv_secret');
      break;
    }
  }
  KEY_VALUE_SECRET_RE.lastIndex = 0;

  let connMatch;
  while ((connMatch = CONN_PARAM_SECRET_RE.exec(s)) !== null) {
    if (!ALREADY_REDACTED_RE.test(connMatch[2].trim())) {
      findings.push('conn_param_secret');
      break;
    }
  }
  CONN_PARAM_SECRET_RE.lastIndex = 0;

  let cliMatch;
  while ((cliMatch = CLI_FLAG_SECRET_RE.exec(s)) !== null) {
    if (!isBenignSecretCandidate(cliMatch[3])) {
      findings.push('cli_secret');
      break;
    }
  }
  CLI_FLAG_SECRET_RE.lastIndex = 0;

  if (RAW_PATH_RE.test(s) || RELATIVE_RAW_PATH_RE.test(s)) findings.push('raw_path');
  RAW_PATH_RE.lastIndex = 0;
  RELATIVE_RAW_PATH_RE.lastIndex = 0;

  return {
    clean: findings.length === 0,
    findings: [...new Set(findings)]
  };
}
