/** @typedef {"catastrophic"|"self"|"credentials"|"destructive"|"outward"|"opaque"} Risk */
/** @typedef {{risk: Risk, why: string[], commands?: string[]}} Verdict */
/** @typedef {{home: string, cwd: string, stateDir: string, configDir?: string}} Ctx */

const CATASTROPHIC = 'catastrophic';
const SELF = 'self';
const CREDENTIALS = 'credentials';
const DESTRUCTIVE = 'destructive';
const OUTWARD = 'outward';
const OPAQUE = 'opaque';

/** @type {Risk[]} */
export const RISK_ORDER = [CATASTROPHIC, SELF, CREDENTIALS, DESTRUCTIVE, OUTWARD, OPAQUE];

const MAX_COMMAND_LENGTH = 20000;
const MAX_NESTING = 12;
const MAX_BRACE_VARIANTS = 64;
const MAX_LOOP_VALUES = 64;
const MAX_DISPLAYED_COMMANDS = 40;
const MAX_DISPLAYED_LENGTH = 200;
const MAX_STRING_WALKS = 2048;

// Lexer. A word is a list of parts so the walker can tell literal text from
// expansions after the fact, when it knows which variables were assigned.

const LIT = 0;
const VAR = 1;
const SUB = 2;

const WORD = 0;
const OP = 1;
const REDIR = 2;
const ARITH = 3;

const WORD_BREAK = new Set([' ', '\t', '\n', ';', '&', '|', '(', ')', '<', '>']);
const CONTROL_OPS = [';;&', ';;', ';&', ';', '&&', '&', '||', '|&', '|'];
const REDIR_OPS = ['&>>', '&>', '<<<', '<<-', '<<', '<&', '<>', '<', '>>', '>&', '>|', '>'];
const ARRAY_ASSIGN_HEAD = /^[A-Za-z_]\w*\+?=$/;
const ANSI_ESCAPES = { n: '\n', t: '\t', r: '\r', a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' };
const CASE_OPENERS = new Set(['then', 'do', 'else', 'elif', '{', '!', '(']);

class ParseFailure extends Error {}

function fail(message) {
  throw new ParseFailure(message);
}

function isNameStart(c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c === '_';
}

function isNameChar(c) {
  return isNameStart(c) || (c >= '0' && c <= '9');
}

function isOctal(c) {
  return c >= '0' && c <= '7';
}

/** @param {string} src @param {boolean} [expansionsOnly] heredoc and arithmetic bodies expand but do not tokenize */
function lex(src, expansionsOnly = false) {
  const n = src.length;
  let i = 0;
  const pendingHeredocs = [];

  function skipBlanks() {
    while (i < n) {
      const c = src[i];
      if (c === ' ' || c === '\t') i++;
      else if (c === '\\' && src[i + 1] === '\n') i += 2;
      else break;
    }
  }

  function script(closer) {
    const out = [];
    let parens = 0;
    let cases = 0;
    for (;;) {
      skipBlanks();
      if (i >= n) {
        if (closer || parens > 0) fail('unterminated group');
        return out;
      }
      const c = src[i];
      if (c === '#') {
        while (i < n && src[i] !== '\n') i++;
        continue;
      }
      if (c === '\n') {
        i++;
        readHeredocs();
        out.push({ t: OP, op: '\n' });
        continue;
      }
      if (c === ')') {
        if (closer === ')' && parens === 0 && cases === 0) {
          i++;
          return out;
        }
        if (parens > 0) parens--;
        else if (cases === 0) fail('unbalanced )');
        i++;
        out.push({ t: OP, op: ')' });
        continue;
      }
      if (c === '(') {
        if (src[i + 1] === '(') {
          const subs = tryArithmetic(i + 2);
          if (subs) {
            out.push({ t: ARITH, subs });
            continue;
          }
        }
        parens++;
        i++;
        out.push({ t: OP, op: '(' });
        continue;
      }
      const startsProcSub = (c === '<' || c === '>') && src[i + 1] === '(';
      if (!startsProcSub && (c === '<' || c === '>' || (c === '&' && src[i + 1] === '>'))) {
        out.push(readRedirect(null));
        continue;
      }
      if (c === ';' || c === '&' || c === '|') {
        const op = CONTROL_OPS.find((candidate) => src.startsWith(candidate, i));
        i += op.length;
        out.push({ t: OP, op });
        continue;
      }
      const word = readWord();
      if (word.plain !== null && /^\d+$/.test(word.plain) && (src[i] === '<' || src[i] === '>') && src[i + 1] !== '(') {
        out.push(readRedirect(word.plain));
        continue;
      }
      if (word.plain === 'esac' && cases > 0) cases--;
      else if (word.plain === 'case' && atCommandStart(out)) cases++;
      out.push({ t: WORD, word });
    }
  }

  function atCommandStart(tokens) {
    const last = tokens[tokens.length - 1];
    if (!last || last.t === OP) return true;
    return last.t === WORD && CASE_OPENERS.has(last.word.plain);
  }

  function readWord() {
    const parts = [];
    let lit = '';
    const flush = () => {
      if (lit) {
        parts.push({ k: LIT, v: lit, q: false });
        lit = '';
      }
    };
    while (i < n) {
      const c = src[i];
      if ((c === '<' || c === '>') && src[i + 1] === '(') {
        flush();
        const start = i;
        i += 2;
        const tokens = script(')');
        parts.push({ k: SUB, tokens, raw: src.slice(start, i), q: false, proc: true });
        continue;
      }
      if (WORD_BREAK.has(c)) {
        if (c === '(' && parts.length === 0 && ARRAY_ASSIGN_HEAD.test(lit)) {
          flush();
          readArrayLiteral(parts);
          continue;
        }
        break;
      }
      if (c === '\\') {
        if (src[i + 1] === '\n') {
          i += 2;
          continue;
        }
        flush();
        if (i + 1 >= n) fail('trailing backslash');
        parts.push({ k: LIT, v: src[i + 1], q: true });
        i += 2;
      } else if (c === "'") {
        flush();
        const end = src.indexOf("'", i + 1);
        if (end < 0) fail('unterminated single quote');
        parts.push({ k: LIT, v: src.slice(i + 1, end), q: true });
        i = end + 1;
      } else if (c === '"') {
        flush();
        readDoubleQuoted(parts);
      } else if (c === '$') {
        if (src[i + 1] === "'") {
          flush();
          readAnsiC(parts);
        } else if (src[i + 1] === '"') {
          flush();
          i++;
          readDoubleQuoted(parts);
        } else {
          flush();
          readDollar(parts, false);
        }
      } else if (c === '`') {
        flush();
        readBacktick(parts, false);
      } else {
        lit += c;
        i++;
      }
    }
    flush();
    if (parts.length === 0) fail('expected a word');
    const only = parts.length === 1 ? parts[0] : null;
    return { parts, plain: only && only.k === LIT && !only.q ? only.v : null };
  }

  function readArrayLiteral(parts) {
    i++;
    for (;;) {
      skipBlanks();
      while (src[i] === '\n') {
        i++;
        skipBlanks();
      }
      if (i >= n) fail('unterminated array');
      if (src[i] === ')') {
        i++;
        return;
      }
      parts.push(...readWord().parts);
    }
  }

  function readDoubleQuoted(parts) {
    i++;
    let lit = '';
    let pushed = false;
    const flush = () => {
      parts.push({ k: LIT, v: lit, q: true });
      lit = '';
      pushed = true;
    };
    while (i < n) {
      const c = src[i];
      if (c === '"') {
        i++;
        if (lit || !pushed) flush();
        return;
      }
      if (c === '\\') {
        const next = src[i + 1];
        if (next === '\n') i += 2;
        else if (next === '$' || next === '`' || next === '"' || next === '\\') {
          lit += next;
          i += 2;
        } else {
          lit += c;
          i++;
        }
      } else if (c === '$') {
        if (lit) flush();
        readDollar(parts, true);
        pushed = true;
      } else if (c === '`') {
        if (lit) flush();
        readBacktick(parts, true);
        pushed = true;
      } else {
        lit += c;
        i++;
      }
    }
    fail('unterminated double quote');
  }

  function readAnsiC(parts) {
    i += 2;
    let out = '';
    while (i < n) {
      const c = src[i++];
      if (c === "'") {
        parts.push({ k: LIT, v: out, q: true });
        return;
      }
      if (c !== '\\') {
        out += c;
        continue;
      }
      const e = src[i++];
      if (e === 'x') out += readCodePoint(16, 2);
      else if (e === 'u') out += readCodePoint(16, 4);
      else if (e === 'U') out += readCodePoint(16, 8);
      else if (e !== undefined && isOctal(e)) {
        i--;
        out += readCodePoint(8, 3);
      } else if (e === 'c') out += String.fromCharCode((src.charCodeAt(i++) || 0) & 31);
      else out += ANSI_ESCAPES[e] ?? `\\${e}`;
    }
    fail('unterminated ansi-c quote');
  }

  function readCodePoint(radix, maxDigits) {
    const start = i;
    while (i < n && i - start < maxDigits && !Number.isNaN(Number.parseInt(src[i], radix))) i++;
    const code = Number.parseInt(src.slice(start, i), radix);
    return Number.isNaN(code) || code > 0x10ffff ? '' : String.fromCodePoint(code);
  }

  function readDollar(parts, q) {
    const start = i;
    const next = src[i + 1];
    if (next === '(') {
      if (src[i + 2] === '(') {
        const subs = tryArithmetic(i + 3);
        if (subs) {
          parts.push({ k: VAR, name: null, raw: src.slice(start, i), q, subs });
          return;
        }
      }
      i += 2;
      const tokens = script(')');
      parts.push({ k: SUB, tokens, raw: src.slice(start, i), q, proc: false });
    } else if (next === '{') {
      readBraceParameter(parts, q);
    } else if (next !== undefined && isNameStart(next)) {
      i += 2;
      while (i < n && isNameChar(src[i])) i++;
      parts.push({ k: VAR, name: src.slice(start + 1, i), raw: src.slice(start, i), q });
    } else if (next !== undefined && '@*#?$!-0123456789'.includes(next)) {
      i += 2;
      parts.push({ k: VAR, name: null, raw: src.slice(start, i), q });
    } else {
      i++;
      parts.push({ k: LIT, v: '$', q: true });
    }
  }

  function readBraceParameter(parts, q) {
    const start = i;
    i += 2;
    const subs = [];
    let depth = 1;
    while (i < n && depth > 0) {
      const c = src[i];
      if (c === '\\') i += 2;
      else if (c === '$') readDollar(subs, true);
      else if (c === '`') readBacktick(subs, true);
      else {
        if (c === '{') depth++;
        else if (c === '}') depth--;
        i++;
      }
    }
    if (depth > 0) fail('unterminated parameter expansion');
    const raw = src.slice(start, i);
    const inner = raw.slice(2, -1);
    parts.push({ k: VAR, name: /^[A-Za-z_]\w*$/.test(inner) ? inner : null, raw, q, subs });
  }

  function readBacktick(parts, q) {
    const start = i++;
    let inner = '';
    while (i < n && src[i] !== '`') {
      if (src[i] === '\\' && (src[i + 1] === '`' || src[i + 1] === '\\' || src[i + 1] === '$')) {
        inner += src[i + 1];
        i += 2;
      } else inner += src[i++];
    }
    if (i >= n) fail('unterminated backtick');
    i++;
    parts.push({ k: SUB, tokens: lex(inner), raw: src.slice(start, i), q, proc: false });
  }

  // Bash reads ((...)) as arithmetic only when the two closing parens touch.
  // Otherwise it reparses as nested subshells, so ((rm x); ls) must still run rm.
  function tryArithmetic(bodyStart) {
    let depth = 1;
    let j = bodyStart;
    for (; j < n; j++) {
      const c = src[j];
      if (c === '\\') j++;
      else if (c === '(') depth++;
      else if (c === ')') {
        depth--;
        if (depth === 0) break;
      }
    }
    if (depth !== 0 || src[j + 1] !== ')') return null;
    i = j + 2;
    return lex(src.slice(bodyStart, j), true);
  }

  function readRedirect(fd) {
    const op = REDIR_OPS.find((candidate) => src.startsWith(candidate, i));
    i += op.length;
    skipBlanks();
    if (i >= n || src[i] === '\n') fail('redirect without a target');
    const target = readWord();
    const token = { t: REDIR, op, fd, target, heredoc: null };
    if (op === '<<' || op === '<<-') {
      const delim = target.parts.map((part) => (part.k === LIT ? part.v : part.raw)).join('');
      token.heredoc = { delim, strip: op === '<<-', expand: !target.parts.some((part) => part.q), body: '' };
      pendingHeredocs.push(token.heredoc);
    }
    return token;
  }

  function readHeredocs() {
    for (const heredoc of pendingHeredocs.splice(0)) {
      const lines = [];
      while (i < n) {
        const lineEnd = src.indexOf('\n', i);
        const end = lineEnd < 0 ? n : lineEnd;
        let line = src.slice(i, end);
        i = Math.min(end + 1, n);
        if (heredoc.strip) line = line.replace(/^\t+/, '');
        if (line === heredoc.delim) break;
        lines.push(line);
      }
      heredoc.body = lines.join('\n');
    }
  }

  if (!expansionsOnly) return script(null);

  const expansions = [];
  while (i < n) {
    const c = src[i];
    if (c === '\\') i += 2;
    else if (c === '$') readDollar(expansions, true);
    else if (c === '`') readBacktick(expansions, true);
    else i++;
  }
  return expansions;
}

// Words. An Arg is a word after expansion: `text` is what matching sees and
// `script` keeps the $VAR spelling for re-parsing inside sh -c or eval.

/** @typedef {{text: string, script: string, dynamic: boolean, glob: boolean, proc: boolean, sole: boolean, quoted: boolean}} Arg */

const UNKNOWN = Symbol('unknown');
const GLOB_CHARS = /[*?]|\[[^\]]*\]/;

function lookupVar(name, st) {
  if (name === null) return undefined;
  if (st.env.has(name)) {
    const value = st.env.get(name);
    return value === UNKNOWN || st.ifsChanged ? undefined : value;
  }
  if (name === 'HOME') return st.home;
  if (name === 'PWD') return st.cwd;
  if (name === 'TMPDIR') return '/tmp';
  if (name === 'CLAUDE_CONFIG_DIR') return st.configDir ?? undefined;
  return undefined;
}

const TILDE_USER = /^~([A-Za-z_][\w.-]*)(?=\/|$)/;

function expandTilde(text, st) {
  if (text === '~') return st.home;
  if (text.startsWith('~/')) return st.home + text.slice(1);
  if (text === '~+' || text.startsWith('~+/')) return st.cwd + text.slice(2);
  const user = text[0] === '~' ? TILDE_USER.exec(text) : null;
  if (user) return `${st.home.slice(0, st.home.lastIndexOf('/'))}/${user[1]}${text.slice(user[0].length)}`;
  return text;
}

/** @returns {Arg} */
function literalArg(text, st) {
  const expanded = st ? expandTilde(text, st) : text;
  const glob = GLOB_CHARS.test(expanded);
  return { text: expanded, script: text, dynamic: glob, glob, proc: false, sole: false, quoted: false };
}

/** A placeholder for a value supplied at run time, one or many: `{}` in find -exec or xargs input. */
function listArg(text, script) {
  return { text, script, dynamic: true, glob: true, proc: false, sole: false, quoted: false };
}

function expandBraces(text, out) {
  if (out.length > MAX_BRACE_VARIANTS) return out;
  const match = /\{([^{}]*,[^{}]*)\}/.exec(text);
  if (!match) {
    out.push(text);
    return out;
  }
  for (const alternative of match[1].split(',')) {
    expandBraces(text.slice(0, match.index) + alternative + text.slice(match.index + match[0].length), out);
  }
  return out;
}

/** @returns {Arg[]} */
function resolveWord(word, st) {
  if (word.plain !== null && word.plain.includes('{')) {
    if (/\{[^{}]*\.\.[^{}]*\}/.test(word.plain)) return [listArg(word.plain, word.plain)];
    const variants = expandBraces(word.plain, []);
    if (variants.length > MAX_BRACE_VARIANTS) return [listArg(word.plain, word.plain)];
    return variants.map((variant) => literalArg(variant, st));
  }
  const parts = word.parts;
  /** @type {Arg} */
  const arg = { text: '', script: '', dynamic: false, glob: false, proc: false, sole: false, quoted: false };
  for (let p = 0; p < parts.length; p++) {
    const part = parts[p];
    if (part.k === LIT) {
      let value = part.v;
      if (part.q) arg.quoted = true;
      else {
        if (p === 0 && value[0] === '~') value = expandTilde(value, st);
        if (GLOB_CHARS.test(value)) arg.glob = arg.dynamic = true;
      }
      arg.text += value;
      arg.script += part.v;
    } else if (part.k === VAR) {
      const known = lookupVar(part.name, st);
      if (known === undefined) {
        arg.dynamic = true;
        arg.text += part.raw;
      } else {
        if (!part.q && parts.length === 1 && /\s/.test(known)) {
          return known.trim().split(/\s+/).map((piece) => literalArg(piece, st));
        }
        if (!part.q && GLOB_CHARS.test(known)) arg.glob = arg.dynamic = true;
        arg.text += known;
      }
      arg.script += part.raw;
    } else {
      arg.dynamic = true;
      arg.text += part.raw;
      arg.script += part.raw;
      if (part.proc) arg.proc = true;
    }
  }
  arg.sole = arg.dynamic && parts.length === 1 && parts[0].k !== LIT;
  return [arg];
}

function resolveOne(word, st) {
  return resolveWord(word, st)[0];
}

// Paths. Pure string math, no filesystem.

function normalizePath(path, cwd) {
  const absolute = path[0] === '/' ? path : `${cwd}/${path}`;
  const segments = [];
  for (const segment of absolute.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') segments.pop();
    else segments.push(segment);
  }
  const normalized = `/${segments.join('/')}`;
  return /^\/private\/(etc|var|tmp)(\/|$)/.test(normalized) ? normalized.slice('/private'.length) : normalized;
}

function resolvePath(text, st) {
  return normalizePath(expandTilde(text, st), st.cwd);
}

function isUnder(path, dir) {
  return path === dir || path.startsWith(dir === '/' ? '/' : `${dir}/`);
}

const OTHER_HOME = /^\/(?:(?:users|home)\/[^/]+|root)(?:\/(.*))?$/i;

/** @returns {string|null} the path relative to a home directory, '' for the home directory itself */
function homeRelative(path, st) {
  if (st.home !== '/' && isUnder(path, st.home)) return path.slice(st.home.length + 1);
  const other = OTHER_HOME.exec(path);
  return other ? (other[1] ?? '') : null;
}

const PROTECTED_ROOTS = new Set(['/', '/users', '/home', '/etc', '/usr', '/var', '/bin', '/sbin', '/lib', '/system', '/library', '/applications', '/opt', '/boot', '/dev', '/private']);
const SYSTEM_PATH = /^\/(etc|usr|var|bin|sbin|lib|system|library|applications|opt|boot)(\/|$)/i;
const SCRATCH_SYSTEM_PATH = /^\/var\/(tmp|folders)(\/|$)/i;
const BLOCK_DEVICE = /^\/dev\/(r?disk|sd|hd|vd|xvd|nvme|mmcblk|loop|dm-|mapper\/|md\d)/i;
const HARMLESS_DEVICE = /^\/dev\/(null|zero|stdout|stderr|stdin|tty|fd\/|random|urandom)/i;
const SETTINGS_PATH = /\/(?:managed-settings(?:\.d\/[^/]+|[^/]*)\.json|\.claude\.json|(?:\.claude[^/]*|\.config\/claude|\$\{?CLAUDE_CONFIG_DIR[^/]*)\/(?:[^/]+\/)*settings[^/]*\.json)$/i;
const SETTINGS_NAMES = ['settings.json', 'settings.local.json'];
const SECRET_FILE = /^(?:\.ssh\/id_(?!.*\.pub$).*|\.aws\/credentials|\.config\/gh\/hosts\.yml|\.netrc|\.npmrc|\.pypirc|\.docker\/config\.json|\.kube\/config|\.gnupg(?:\/.*)?)$/i;
const SECRET_DIR = /^(?:\.ssh|\.aws|\.kube|\.docker|\.config\/gh)(?:\/?$)/i;
const SECRET_GLOB = /^(?:\.ssh|\.aws|\.kube|\.docker|\.config\/gh)\//i;
const SECRET_HINT = /\.ssh|\.aws|\.netrc|\.npmrc|\.pypirc|\.docker|\.kube|\.gnupg|\.config\/gh/i;
const SECRET_IN_CODE = /\.ssh\/id_(?!\w*\.pub)|\.aws\/credentials|\.config\/gh\/hosts\.yml|\.netrc\b|\.npmrc\b|\.pypirc\b|\.docker\/config\.json|\.kube\/config|\.gnupg\//i;
const PERSISTENCE_HOME = /^(?:\.ssh\/(?:authorized_keys|config|rc)|\.bashrc|\.zshrc|\.zshenv|\.zprofile|\.profile|\.bash_profile|\.bash_login|library\/launchagents\/.+)$/i;
const PERSISTENCE_SYSTEM = /^\/(?:etc\/|library\/launchdaemons\/|library\/launchagents\/)/i;

function isProtectedRoot(path, st) {
  if (path === st.home) return true;
  return PROTECTED_ROOTS.has(path.toLowerCase()) || /^\/(?:(?:users|home)\/[^/]+|root)$/i.test(path);
}

function isPersistencePath(path, st) {
  if (PERSISTENCE_SYSTEM.test(path)) return true;
  const relative = homeRelative(path, st);
  return relative !== null && PERSISTENCE_HOME.test(relative);
}

function isSecretPath(path, st) {
  const relative = homeRelative(path, st);
  return relative !== null && SECRET_FILE.test(relative);
}

// Paths compare as paths. macOS folds case and normalizes Unicode, so `.SAYSO` and `.ſayso` are the state directory,
// and a glob segment counts as the name it could expand to.

const NON_ASCII = /[^\x00-\x7f]/;
const GLOB_SEGMENT = /[*?[]/;
// ${X:-value} reads as its fallback. Any other expansion could be anything, so it reads as a wildcard.
const EXPANSION_FALLBACK = /\$\{\w+:?[-=+]([^{}]*)\}/g;
const EXPANSION_PIECE = /\$\([^()]*\)|\$\{[^{}]*\}|\$[A-Za-z_]\w*/g;

function foldName(text) {
  return (NON_ASCII.test(text) ? text.normalize('NFKC') : text).toLowerCase();
}

function globRegExp(segment) {
  let source = '';
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i];
    if (c === '*') source += '.*';
    else if (c === '?') source += '.';
    else if (c === '[') {
      const end = segment.indexOf(']', i + 2);
      if (end < 0) source += '\\[';
      else {
        const inner = segment.slice(i + 1, end).replace(/\\/g, '\\\\');
        source += `[${inner[0] === '!' ? `^${inner.slice(1)}` : inner}]`;
        i = end;
      }
    } else source += c.replace(/[.+^${}()|\\\]]/, '\\$&');
  }
  return new RegExp(`^${source}$`);
}

/** Both sides already folded. A wildcard does not reach a dot name unless the glob starts with a dot, as in the shell. */
function segmentCouldBe(segment, name) {
  if (segment === name) return true;
  if (!GLOB_SEGMENT.test(segment)) return false;
  if (name[0] === '.' && segment[0] !== '.' && segment[0] !== '[') return false;
  try {
    return globRegExp(segment).test(name);
  } catch {
    return false;
  }
}

function pathReachesDir(path, dirSegments) {
  const segments = foldName(path).split('/').slice(1);
  if (segments.length < dirSegments.length) return false;
  return dirSegments.every((name, i) => segmentCouldBe(segments[i], name));
}

function namesStateDir(path, st) {
  if (st.stateBase[0] === '.' && foldName(path).split('/').includes(st.stateBase)) return true;
  return pathReachesDir(path, st.stateSegments);
}

function isSettingsPath(path, st) {
  if (SETTINGS_PATH.test(path)) return true;
  const folded = foldName(path);
  const segments = folded.split('/');
  const last = segments.pop();
  if (st.configSegments && /^settings.*\.json$/.test(last) && pathReachesDir(path, st.configSegments)) return true;
  if (!GLOB_SEGMENT.test(folded) || !SETTINGS_NAMES.some((name) => segmentCouldBe(last, name))) return false;
  return segments.some((segment) => segmentCouldBe(segment, '.claude'));
}

/** The path a flag or remote spec may be carrying: --key=PATH, @PATH, host:PATH. */
function pathCandidates(text) {
  const candidates = [text];
  for (const separator of ['=', '@', ':']) {
    const at = text.lastIndexOf(separator);
    if (at >= 0 && at < text.length - 1) candidates.push(text.slice(at + 1));
  }
  return candidates;
}

function wordNamesStateDir(text, st) {
  if (!foldName(text).includes(st.stateBase) && !/[*?[$]/.test(text)) return false;
  const pattern = text.includes('$') ? text.replace(EXPANSION_FALLBACK, '$1').replace(EXPANSION_PIECE, '*') : text;
  if (/\s/.test(pattern)) return namesStateDir(resolvePath(pattern, st), st);
  return pathCandidates(pattern).some((candidate) => namesStateDir(resolvePath(candidate, st), st));
}

const SOCKET_NAME = 'sayso.sock';

/** For a file name anywhere, a glob needs a few literal characters of its own: `ls *` is not aimed at it, `*.sock` is. */
function fileNameCouldBe(segment, name) {
  if (segment === name) return true;
  return GLOB_SEGMENT.test(segment) && segment.replace(/[*?]|\[[^\]]*\]/g, '').length >= 3 && segmentCouldBe(segment, name);
}

function wordNamesSocket(text) {
  if (/\s/.test(text)) return false;
  const folded = foldName(text);
  if (folded.includes(SOCKET_NAME)) return true;
  if (!GLOB_SEGMENT.test(folded)) return false;
  return pathCandidates(folded).some((candidate) => fileNameCouldBe(candidate.slice(candidate.lastIndexOf('/') + 1), SOCKET_NAME));
}

function wordNamesSecret(arg, st) {
  if (/\s/.test(arg.text)) return false;
  return pathCandidates(arg.text).some((candidate) => {
    const path = resolvePath(candidate, st);
    if (isSecretPath(path, st)) return true;
    if (!arg.glob) return false;
    const relative = homeRelative(path, st);
    return relative !== null && SECRET_GLOB.test(relative);
  });
}

// Classification state.

function newState(ctx) {
  const home = ctx?.home ? normalizePath(ctx.home, '/') : '/nonexistent-home';
  const cwd = ctx?.cwd ? normalizePath(expandTildeWith(ctx.cwd, home), '/') : home;
  const stateDir = normalizePath(expandTildeWith(ctx?.stateDir || `${home}/.sayso`, home), cwd);
  const configDir = ctx?.configDir ? normalizePath(expandTildeWith(ctx.configDir, home), cwd) : null;
  const foldedState = foldName(stateDir);
  return {
    home,
    cwd,
    stateDir,
    stateBase: foldedState.slice(foldedState.lastIndexOf('/') + 1),
    stateSegments: foldedState.split('/').slice(1),
    configDir,
    configSegments: configDir ? foldName(configDir).split('/').slice(1) : null,
    cwdInSecretDir: cwdHoldsSecrets(cwd, home),
    env: new Map(),
    ifsChanged: false,
    flags: [],
    argvs: [],
    depth: 0,
    loopBudget: MAX_LOOP_VALUES,
    stringWalks: { left: MAX_STRING_WALKS },
  };
}

function expandTildeWith(path, home) {
  return path === '~' || path.startsWith('~/') ? home + path.slice(1) : path;
}

function cwdHoldsSecrets(cwd, home) {
  return /\/\.(?:ssh|aws|kube|docker|gnupg)(?:\/|$)|\/\.config\/gh(?:\/|$)/i.test(cwd) || cwd === home;
}

/** Reasons never carry command text: aggregate reports print them and transcripts are private. */
function flag(st, risk, why) {
  st.flags.push({ risk, why });
}

function buildVerdict(st) {
  if (st.flags.length === 0) return null;
  const ranked = [...st.flags].sort((a, b) => RISK_ORDER.indexOf(a.risk) - RISK_ORDER.indexOf(b.risk));
  const commands = new Set();
  for (const argv of st.argvs) {
    if (commands.size >= MAX_DISPLAYED_COMMANDS) break;
    const line = argv.map((arg) => arg.text).join(' ');
    commands.add(line.length > MAX_DISPLAYED_LENGTH ? `${line.slice(0, MAX_DISPLAYED_LENGTH)}...` : line);
  }
  return { risk: ranked[0].risk, why: [...new Set(ranked.map((entry) => entry.why))], commands: [...commands] };
}

function opaqueVerdict(why) {
  return { risk: OPAQUE, why: [why], commands: [] };
}

// Walker. A linear scan over tokens with command position as the only grammar
// it needs: classification cares about simple commands, not nesting.

const KEYWORDS = new Set(['if', 'then', 'elif', 'else', 'fi', 'while', 'until', 'do', 'done', '!', '{', '}', 'coproc']);
const COMPOUND_CLOSERS = new Set(['fi', 'done', '}']);
const ASSIGNMENT = /^([A-Za-z_]\w*)(\[[^\]]*\])?\+?=/;

function emptyCommand() {
  return { assigns: [], words: [], redirs: [], afterCompound: false };
}

function walkTokens(tokens, st) {
  let cmd = emptyCommand();
  let piped = false;
  let previous = null;
  let caseDepth = 0;
  let inPattern = false;

  const flush = () => {
    const had = cmd.assigns.length || cmd.words.length || cmd.redirs.length;
    const finished = had ? visitCommand(cmd, piped, previous, st) : null;
    cmd = emptyCommand();
    return finished;
  };

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.t === REDIR) {
      if (!inPattern) cmd.redirs.push(token);
      continue;
    }
    if (token.t === ARITH) {
      walkParts(token.subs, st);
      flush();
      cmd.afterCompound = true;
      continue;
    }
    if (token.t === OP) {
      const op = token.op;
      if (op === '(' && cmd.words.length === 1 && cmd.assigns.length === 0 && tokens[i + 1]?.op === ')') {
        checkForkBomb(tokens, i + 2, cmd.words[0], st);
        cmd = emptyCommand();
        i++;
        continue;
      }
      if (inPattern) {
        if (op === ')') inPattern = false;
        continue;
      }
      if (op === '|' || op === '|&') {
        previous = flush();
        piped = true;
      } else if (op === '(' || op === ')') {
        flush();
        cmd.afterCompound = op === ')';
      } else {
        flush();
        piped = false;
        previous = null;
        if (op === ';;' || op === ';&' || op === ';;&') inPattern = caseDepth > 0;
      }
      continue;
    }

    const word = token.word;
    if (inPattern) {
      if (word.plain === 'esac') {
        caseDepth--;
        inPattern = false;
        cmd.afterCompound = true;
      } else walkWordParts(word, st);
      continue;
    }
    if (cmd.words.length > 0) {
      cmd.words.push(word);
      continue;
    }
    const plain = word.plain;
    if (plain !== null && cmd.assigns.length === 0) {
      if (KEYWORDS.has(plain)) {
        cmd.afterCompound = COMPOUND_CLOSERS.has(plain);
        continue;
      }
      if (plain === 'esac' && caseDepth > 0) {
        caseDepth--;
        cmd.afterCompound = true;
        continue;
      }
      if (plain === 'case') {
        const inAt = nextWordIndex(tokens, i + 1);
        if (inAt >= 0) walkWordParts(tokens[inAt].word, st);
        const keyword = inAt >= 0 ? nextWordIndex(tokens, inAt + 1) : -1;
        i = keyword >= 0 ? keyword : tokens.length;
        caseDepth++;
        inPattern = true;
        continue;
      }
      if (plain === 'for' || plain === 'select') {
        i = walkLoop(tokens, i + 1, st);
        cmd.afterCompound = true;
        continue;
      }
      if (plain === 'function') {
        const nameAt = nextWordIndex(tokens, i + 1);
        if (nameAt >= 0) {
          checkForkBomb(tokens, nameAt + 1, tokens[nameAt].word, st);
          i = nameAt;
        }
        continue;
      }
      if (plain === '[[') {
        i = skipConditional(tokens, i + 1, st);
        cmd.afterCompound = true;
        continue;
      }
    }
    const first = word.parts[0];
    const assignment = first.k === LIT && !first.q ? ASSIGNMENT.exec(first.v) : null;
    if (assignment) {
      cmd.assigns.push({
        name: assignment[1],
        value: { parts: [{ k: LIT, v: first.v.slice(assignment[0].length), q: true }, ...word.parts.slice(1)], plain: null, tilde: first.v[assignment[0].length] === '~' },
      });
      continue;
    }
    cmd.words.push(word);
  }
  flush();
}

function nextWordIndex(tokens, from) {
  for (let i = from; i < tokens.length; i++) {
    if (tokens[i].t === WORD) return i;
    if (tokens[i].op !== '\n') return -1;
  }
  return -1;
}

/** Runs the body once per literal list value, so `for c in "rm -rf /"; do eval "$c"; done` reads as what it does. */
function walkLoop(tokens, from, st) {
  const nameAt = nextWordIndex(tokens, from);
  if (nameAt < 0) return from - 1;
  const name = tokens[nameAt].word.plain;
  if (name) st.env.set(name, UNKNOWN);
  let i = nameAt + 1;
  while (tokens[i]?.t === OP && tokens[i].op === '\n') i++;
  if (tokens[i]?.t !== WORD || tokens[i].word.plain !== 'in') return nameAt;
  const values = [];
  for (i++; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.t === OP) break;
    if (token.t === WORD) {
      if (token.word.plain === 'do') break;
      walkWordParts(token.word, st);
      values.push(...resolveWord(token.word, st));
    }
  }
  const body = name ? findLoopBody(tokens, i) : null;
  if (!body || values.length > st.loopBudget || values.some((value) => value.dynamic)) return i - 1;
  st.loopBudget -= values.length;
  const bodyTokens = tokens.slice(body.start, body.end);
  for (const value of values) {
    st.env.set(name, value.text);
    walkTokens(bodyTokens, st);
  }
  st.env.set(name, UNKNOWN);
  return body.end;
}

function findLoopBody(tokens, from) {
  let i = from;
  while (tokens[i]?.t === OP && (tokens[i].op === ';' || tokens[i].op === '\n')) i++;
  if (tokens[i]?.t !== WORD || tokens[i].word.plain !== 'do') return null;
  const start = i + 1;
  let depth = 1;
  for (let j = start; j < tokens.length; j++) {
    const token = tokens[j];
    if (token.t !== WORD) continue;
    const before = tokens[j - 1];
    if (before.t !== OP && !CASE_OPENERS.has(before.word?.plain)) continue;
    if (token.word.plain === 'do') depth++;
    else if (token.word.plain === 'done' && --depth === 0) return { start, end: j };
  }
  return null;
}

function skipConditional(tokens, from, st) {
  for (let i = from; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.t === WORD) {
      if (token.word.plain === ']]') return i;
      walkWordParts(token.word, st);
    } else if (token.t === REDIR) {
      walkWordParts(token.target, st);
    }
  }
  return tokens.length;
}

/** The body of NAME() starts at `from`: a function that calls itself across a pipe or into the background is a fork bomb. */
function checkForkBomb(tokens, from, nameWord, st) {
  const name = nameWord.plain;
  if (name === null) return;
  let depth = 0;
  let selfCall = false;
  let spawns = false;
  for (let i = from; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.t === WORD) {
      if (token.word.plain === '{') depth++;
      else if (token.word.plain === '}') depth--;
      else if (token.word.plain === name && (tokens[i - 1].t === OP || tokens[i - 1].word?.plain === '{')) selfCall = true;
    } else if (token.t === OP) {
      if (token.op === '(') depth++;
      else if (token.op === ')') depth--;
      else if (token.op === '|' || token.op === '|&' || token.op === '&') spawns = true;
    }
    if (depth === 0 && i > from) break;
  }
  if (selfCall && spawns) flag(st, CATASTROPHIC, 'fork bomb');
}

function walkParts(parts, st) {
  for (const part of parts) {
    if (part.k === SUB) walkNested(part.tokens, st);
    else if (part.k === VAR && part.subs) walkParts(part.subs, st);
  }
}

function walkWordParts(word, st) {
  if (word.plain === null) walkParts(word.parts, st);
}

function walkNested(tokens, st) {
  if (st.depth >= MAX_NESTING) {
    flag(st, OPAQUE, TOO_DEEP);
    return;
  }
  st.depth++;
  walkTokens(tokens, st);
  st.depth--;
}

function walkString(source, st) {
  let tokens;
  try {
    tokens = lex(source);
  } catch (error) {
    if (!(error instanceof ParseFailure)) throw error;
    flag(st, OPAQUE, 'nested script could not be parsed');
    return;
  }
  walkNested(tokens, st);
}

// Strings that might be commands. Any program can run a string, so the walk does not need to know which ones do: a
// string that reads as a dangerous command is flagged wherever it sits. Unreadable ones stay quiet, since most strings
// are not commands, except when the walk itself gave up.

const TOO_DEEP = 'nesting too deep to read';
const TOO_MANY = 'too many nested strings to read';
const HAS_BLANK = /\s/;
const HAS_QUOTE = /["'`]/;
const RM_RECURSIVE = /(?:^|[\s;&|(`"'])(rm\s+-{1,2}[a-zA-Z-]*[rR][^\n]*)/;

function keepingRealRisks(st, visit) {
  const inner = { ...st, env: new Map(st.env), flags: [], argvs: [] };
  visit(inner);
  for (const entry of inner.flags) {
    if (entry.risk !== OPAQUE || entry.why === TOO_DEEP || entry.why === TOO_MANY) st.flags.push(entry);
  }
}

function spendStringWalk(st) {
  if (st.stringWalks.left > 0) {
    st.stringWalks.left--;
    return true;
  }
  flag(st, OPAQUE, TOO_MANY);
  return false;
}

/** A shell runs each line it could parse before it reaches one it cannot, so a bad line does not hide the good ones. */
function walkCandidate(source, st) {
  if (!spendStringWalk(st)) return;
  const text = source.replace(/^\s*:?!/, '').replace(/\$\{?IFS\}?/g, ' ');
  let tokens;
  try {
    tokens = lex(text);
  } catch (error) {
    if (!(error instanceof ParseFailure)) throw error;
    if (text.includes('\n')) for (const line of text.split('\n')) walkCandidate(line, st);
    return;
  }
  keepingRealRisks(st, (inner) => {
    // Plain text like "> quoted" lexes as a bare redirect. It only means truncation when a shell really reads it.
    inner.inString = true;
    walkNested(tokens, inner);
  });
}

const KEY_PREFIX = /^-{0,2}[\w.-]+(?:=|::?)\s*/;

/** The ways a value can sit inside one word: whole, after --opt= or key=, or glued to a short flag. */
function valuesIn(text) {
  const values = [text];
  let rest = text;
  for (let i = 0; i < 3; i++) {
    const key = KEY_PREFIX.exec(rest);
    if (!key || key[0].length === rest.length) break;
    rest = rest.slice(key[0].length);
    values.push(rest);
  }
  if (text[0] === '-' && text[1] !== '-') {
    for (let c = 2; c <= 4 && c < text.length && isNameStart(text[c - 1]); c++) values.push(text.slice(c));
  }
  return values;
}

// A flag or variable that holds a command by its name, so even a single word in it is a command to read.
const COMMAND_FLAG = /^--?(?:c|e|x|S|call|command|cmd|eval|exec|run|shell|split-string)$/;
const COMMAND_OPTION = /^--?(?:call|command|cmd|eval|exec|run|shell|split-string)=|^-[A-Za-z]*c[a-z]/;
const COMMAND_ENV = /(?:^|_)(?:COMMAND|CMD|EDITOR|PAGER|ASKPASS|RSH|BROWSER)$|^(?:VISUAL|LESSOPEN|LESSCLOSE|GIT_SSH|GIT_EXTERNAL_DIFF)$/;
const COMMAND_ENV_WORD = /^(?:(?:\w+_)?(?:COMMAND|CMD|EDITOR|PAGER|ASKPASS|RSH|BROWSER)|VISUAL|LESSOPEN|LESSCLOSE|GIT_SSH|GIT_EXTERNAL_DIFF)=/;
const TEXT_FLAGS = new Set(['--body', '--title', '--message', '--description', '--comment', '--subject', '--notes', '--summary', '--prompt', '--text', '--reason', '--label', '--grep', '--author', '--committer', '--format', '--pretty']);
const TEXT_OPTION = /^--(?:body|title|message|description|comment|subject|notes|summary|prompt|text|reason|label|grep|author|committer|format|pretty)=/;

function walkValue(script, isCommandSlot, st) {
  const blank = HAS_BLANK.test(script) || script.includes('IFS');
  if (!isCommandSlot && !blank) return;
  for (const value of valuesIn(script)) walkCandidate(value, st);
  if (blank && HAS_QUOTE.test(script)) checkEmbeddedShell(script, st, false);
  if (blank) {
    const rm = RM_RECURSIVE.exec(script);
    if (rm) walkCandidate(rm[1], st);
  }
}

function walkArgStrings(args, st) {
  for (let i = 0; i < args.length; i++) {
    const script = args[i].script;
    const before = args[i - 1]?.text;
    if (TEXT_FLAGS.has(before) || TEXT_OPTION.test(script)) continue;
    walkValue(script, COMMAND_FLAG.test(before ?? '') || COMMAND_OPTION.test(script) || COMMAND_ENV_WORD.test(script), st);
  }
}

const NO_IO = { piped: false, previous: null, heredoc: null, herestring: null, stdinUnknown: false, stdinEmpty: false, truncates: [] };

// Programs nobody names as a subcommand of something else, so `anything shred x` still means shred.
const NEVER_A_SUBCOMMAND = new Set(['mkfs', 'newfs', 'mke2fs', 'wipefs', 'blkdiscard', 'sgdisk', 'sfdisk', 'shred', 'dd']);
const RECURSIVE_FLAG = /^-(?:[a-zA-Z]*[rR][a-zA-Z]*|-recursive)$/;

function walkArgvTails(args, st) {
  for (let i = 0; i < args.length; i++) {
    const text = args[i].text;
    const name = text === '--' ? null : ruleKey(baseName(text));
    const tail = text === '--' ? args.slice(i + 1) : NEVER_A_SUBCOMMAND.has(name) || (name === 'rm' && RECURSIVE_FLAG.test(args[i + 1]?.text ?? '')) ? args.slice(i) : null;
    if (tail?.length && spendStringWalk(st)) keepingRealRisks(st, (inner) => dispatch(tail, NO_IO, inner));
    if (text === '--') return;
  }
}

/** Everything a program that is not data-only was handed: its arguments, its stdin, and what echo piped into it. */
function walkCommandStrings(args, io, st, stdinToo = true) {
  walkArgStrings(args, st);
  walkArgvTails(args, st);
  if (!stdinToo) return;
  if (io.heredoc) walkCandidate(io.heredoc, st);
  if (io.herestring) walkCandidate(io.herestring, st);
  const previous = io.piped ? io.previous : null;
  if (previous?.length > 1 && (previous[0].text === 'echo' || previous[0].text === 'printf')) {
    walkCandidate(previous.slice(1).map((arg) => arg.script).join(' '), st);
  }
}

function resolveAssignment(assign, st) {
  const arg = resolveOne(assign.value, st);
  if (assign.value.tilde) {
    arg.text = expandTilde(arg.text, st);
  }
  return arg;
}

const MKTEMP_SUBSTITUTION = /^\$\(mktemp(?:\s+-\w+)*(?:\s+(?:\/tmp\/|\$\{?TMPDIR)[^)\s]*)?\s*\)$/;

const TOOL_LOOKUP_SUBSTITUTION = /^\$\((?:command -v|which) ([\w.+-]+)\b/;

function recordAssignment(name, arg, st) {
  if (name === 'IFS') st.ifsChanged = true;
  const lookedUp = arg.dynamic ? TOOL_LOOKUP_SUBSTITUTION.exec(arg.text) : null;
  const fresh = lookedUp ? lookedUp[1] : arg.dynamic && MKTEMP_SUBSTITUTION.test(arg.text) ? '/tmp/mktemp-result' : null;
  const value = fresh ?? (arg.dynamic ? UNKNOWN : arg.text);
  st.env.set(name, st.env.has(name) && st.env.get(name) !== value ? UNKNOWN : value);
}

function visitCommand(cmd, piped, previous, st) {
  for (const assign of cmd.assigns) walkParts(assign.value.parts, st);
  for (const word of cmd.words) walkWordParts(word, st);
  const argv = [];
  for (const word of cmd.words) argv.push(...resolveWord(word, st));

  const io = { piped, previous, heredoc: null, herestring: null, stdinUnknown: false, stdinEmpty: false, truncates: [] };
  for (const redir of cmd.redirs) applyRedirect(redir, io, st);

  for (const assign of cmd.assigns) {
    const arg = resolveAssignment(assign, st);
    if (argv.length === 0) recordAssignment(assign.name, arg, st);
    scanWord(arg, st, false);
    const holdsCommand = COMMAND_ENV.test(assign.name);
    if (argv.length > 0 || holdsCommand) walkValue(arg.script, holdsCommand, st);
  }
  if (argv.length > 0) {
    st.argvs.push(argv);
    dispatch(argv, io, st);
  } else if (!cmd.afterCompound && !st.inString) {
    checkEmptiedFiles(io.truncates, st);
  }
  return argv;
}

const WRITE_REDIRECTS = new Set(['>', '>>', '>|', '&>', '&>>', '<>']);
const TRUNCATING_REDIRECTS = new Set(['>', '>|', '&>', '>&']);

function applyRedirect(redir, io, st) {
  walkWordParts(redir.target, st);
  if (redir.heredoc) {
    if (redir.heredoc.expand && (redir.heredoc.body.includes('$') || redir.heredoc.body.includes('`'))) {
      walkParts(lex(redir.heredoc.body, true), st);
    }
    io.heredoc = redir.heredoc.body;
    if (io.heredoc === '') io.stdinEmpty = true;
    return;
  }
  const target = resolveOne(redir.target, st);
  if (redir.op === '<<<') {
    io.herestring = target.script;
    return;
  }
  if ((redir.op === '>&' || redir.op === '<&') && /^(\d+-?|-)$/.test(target.text)) return;
  if (redir.op === '<' && target.dynamic) io.stdinUnknown = true;
  if (redir.op === '<' && target.text === '/dev/null') io.stdinEmpty = true;
  scanWord(target, st, false);
  if (WRITE_REDIRECTS.has(redir.op)) checkWriteTarget(target.text, st);
  if (TRUNCATING_REDIRECTS.has(redir.op)) io.truncates.push(target);
}

function checkWriteTarget(text, st) {
  const path = resolvePath(text, st);
  if (BLOCK_DEVICE.test(path)) flag(st, CATASTROPHIC, 'write to a raw disk device');
  if (isSettingsPath(path, st)) flag(st, SELF, 'write to agent settings');
  if (isPersistencePath(path, st)) flag(st, DESTRUCTIVE, 'write to a shell startup or system path');
}

// An ordinary write with content is normal work. These only empty a file, which is what `truncate` does.

function checkEmptiedFiles(targets, st) {
  for (const target of targets) {
    if (target.dynamic || isRebuildable(target) || isOsScratch(target, st)) continue;
    if (!resolvePath(target.text, st).startsWith('/dev/')) flag(st, DESTRUCTIVE, 'empties a file');
  }
}

const isEmptyWord = (arg) => !arg.dynamic && arg.text === '';

function printsNothing(key, args, io) {
  if (key === ':' || key === 'true' || key === 'false') return true;
  if (key === 'cat') {
    const files = positionals(args);
    return files.length > 0 ? files.every((file) => file.text === '/dev/null') : io.stdinEmpty;
  }
  if (key === 'echo') return args.every((arg) => /^-[neE]+$/.test(arg.text) || isEmptyWord(arg));
  if (key === 'printf') return args.length === 0 || (/^(?:%s)*$/.test(args[0].text) && !args[0].dynamic && args.slice(1).every(isEmptyWord));
  return false;
}

function scanWord(arg, st, skipSecrets) {
  const text = arg.text;
  if (wordNamesSocket(text)) flag(st, SELF, 'names the guard socket');
  else if (wordNamesStateDir(text, st)) flag(st, SELF, 'names the guard state directory');
  if (text.includes('/dev/')) {
    const tcp = DEV_TCP.exec(text);
    if (tcp && GUARD_PORT.test(tcp[2]) && LOOPBACK.test(tcp[1])) flag(st, SELF, 'talks to the guard port on loopback');
  }
  if (!skipSecrets && (st.cwdInSecretDir || SECRET_HINT.test(text)) && wordNamesSecret(arg, st)) {
    flag(st, CREDENTIALS, 'reads a secret file');
  }
}

// Dispatch: peel wrappers until the real command, then apply its rule.

const NAME_ALIASES = {
  __proto__: null,
  gtimeout: 'timeout',
  gtime: 'time',
  flyctl: 'fly',
  vc: 'vercel',
  tofu: 'terraform',
  nodejs: 'node',
  gawk: 'awk',
  mawk: 'awk',
  nawk: 'awk',
  egrep: 'grep',
  fgrep: 'grep',
  gsed: 'sed',
  gshred: 'shred',
  mariadb: 'mysql',
  sqlite: 'sqlite3',
  mongo: 'mongosh',
  ncat: 'nc',
  ash: 'sh',
  rbash: 'bash',
  mksh: 'ksh',
  mkdosfs: 'mkfs',
  mkntfs: 'mkfs',
  mkexfatfs: 'mkfs',
  mkswap: 'mkfs',
  mke2fs: 'mkfs',
  'sayso.mjs': 'sayso',
};

function ruleKey(name) {
  const lower = name.toLowerCase();
  if (lower.startsWith('python') && /^python[\d.]*$/.test(lower)) return 'python';
  if (lower.startsWith('mkfs')) return 'mkfs';
  if (lower.startsWith('newfs')) return 'newfs';
  return NAME_ALIASES[lower] ?? lower;
}

function baseName(text) {
  const at = text.lastIndexOf('/');
  return at >= 0 && at < text.length - 1 ? text.slice(at + 1) : text;
}

const WRAPPERS = {
  __proto__: null,
  sudo: { short: 'ugphCTrtUDR', long: ['--user', '--group', '--prompt', '--host', '--chdir', '--close-from', '--role', '--type', '--other-user', '--chroot'], assigns: true, noExec: ['-l', '-v', '-k', '-K', '-V', '--list', '--validate'] },
  doas: { short: 'uC' },
  env: { short: 'uC', long: ['--unset', '--chdir'], assigns: true },
  command: { noExec: ['-v', '-V'] },
  builtin: {},
  exec: { short: 'a' },
  nohup: {},
  nice: { short: 'n', long: ['--adjustment'] },
  ionice: { short: 'cnp', long: ['--class', '--classdata', '--pid'] },
  timeout: { short: 'ks', long: ['--kill-after', '--signal'], positional: 1 },
  stdbuf: { short: 'ioe', long: ['--input', '--output', '--error'] },
  busybox: {},
  time: { short: 'fo', long: ['--format', '--output'] },
  setsid: {},
  caffeinate: { short: 'tw' },
  chronic: {},
  unbuffer: {},
  rlwrap: {},
  flock: { short: 'wE', long: ['--timeout', '--conflict-exit-code'], positional: 1 },
  chroot: { positional: 1 },
  npx: { short: 'pc', long: ['--package', '--call'] },
  bunx: { short: 'p', long: ['--package'] },
  uvx: { short: 'p', long: ['--from', '--with', '--python'] },
};

// Tools that run another program behind a verb: `uv run X`, `pnpm exec X`.
const RUNNER_VERBS = {
  __proto__: null,
  uv: ['run'],
  poetry: ['run'],
  pipenv: ['run'],
  pipx: ['run'],
  rye: ['run'],
  pdm: ['run'],
  hatch: ['run'],
  npm: ['exec'],
  pnpm: ['exec', 'dlx'],
  yarn: ['exec', 'dlx'],
  bun: ['x'],
  bundle: ['exec'],
};
const RUNNER_VALUE_FLAGS = new Set(['--with', '--from', '-p', '--python', '--project', '--package', '--directory', '--env-file', '--extra', '-c', '--filter', '-F', '-C', '--dir', '--spec']);

function peelWrapper(spec, args) {
  let i = 0;
  let positional = spec.positional ?? 0;
  while (i < args.length) {
    const arg = args[i];
    const text = arg.text;
    if (text === '--') {
      i++;
      break;
    }
    if (text[0] === '-' && text.length > 1 && !arg.dynamic) {
      if (spec.noExec?.includes(text)) return null;
      if (text.startsWith('--')) {
        if (!text.includes('=') && spec.long?.includes(text)) i++;
      } else if (spec.short) {
        for (let c = 1; c < text.length; c++) {
          if (spec.short.includes(text[c])) {
            if (c === text.length - 1) i++;
            break;
          }
        }
      }
      i++;
      continue;
    }
    if (spec.assigns && ASSIGNMENT.test(text)) {
      i++;
      continue;
    }
    if (positional > 0) {
      positional--;
      i++;
      continue;
    }
    break;
  }
  return args.slice(i);
}

// Their arguments are text or paths they never run, so a string there that reads like a command is only data.
const DATA_ONLY = new Set(['echo', 'printf', 'grep', 'rg', 'ag', 'ack', 'cat', 'tee', 'head', 'tail', 'wc', 'cut', 'tr', 'uniq', 'ls', 'jq', 'yq', 'diff', 'test', '[', ':', 'true', 'false', 'which', 'type', 'basename', 'dirname', 'realpath', 'readlink', 'stat', 'file', 'touch', 'mkdir', 'date', 'sleep', 'base64', 'xxd', 'od', 'pbcopy', 'wl-copy', 'xclip', 'logger', 'say', 'notify-send', 'wall', 'export', 'declare', 'typeset', 'local', 'readonly', 'read', 'cd', 'pushd']);
// Their rules read their own strings, so the general walk would only read them twice.
const READS_OWN_STRINGS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'eval', 'su', 'trap', 'watch', 'parallel', 'xargs', 'find', 'git', 'sed', 'awk', 'psql', 'mysql', 'sqlite3', 'mongosh', 'cockroach', 'clickhouse-client']);
// Stdin here is data even though the arguments may not be.
const STDIN_IS_DATA = new Set(['sort', 'less', 'more', 'patch', 'curl', 'wget', 'nc', 'tar', 'gzip', 'gunzip', 'gh', 'mail', 'sendmail']);

function dispatch(argv, io, st) {
  const head = argv[0];
  if (!head) return;
  if (head.dynamic) flag(st, OPAQUE, 'command name is not literal');
  const key = ruleKey(baseName(head.text));
  const args = argv.slice(1);
  if (io.truncates.length > 0 && printsNothing(key, args, io)) checkEmptiedFiles(io.truncates, st);
  const wrapper = WRAPPERS[key];
  if (wrapper) {
    const inner = peelWrapper(wrapper, args);
    walkArgStrings(inner ? args.slice(0, args.length - inner.length) : args, st);
    if (key === 'env') checkEnvSplit(args, st);
    if (inner) {
      if (inner[0] && HAS_BLANK.test(inner[0].script)) walkValue(inner[0].script, false, st);
      dispatch(inner, io, st);
    }
    return;
  }
  scanCommandWords(key, argv, st);
  const targets = WRITE_TARGETS[key]?.(args);
  if (targets) for (const target of targets) checkWriteTarget(target.text, st);
  RULES[key]?.(args, io, st, key);
  if (!DATA_ONLY.has(key) && !READS_OWN_STRINGS.has(key) && !INLINE_CODE[key]) {
    walkCommandStrings(key === 'gh' ? withoutTextArgs(args, GH_TEXT) : args, io, st, !STDIN_IS_DATA.has(key));
  }
}

/** `env -S` splits its value and runs it, so it reads with the full shell rules, unreadable parts included. */
function checkEnvSplit(args, st) {
  for (let i = 0; i < args.length; i++) {
    const text = args[i].text;
    if (text === '--') return;
    if (text[0] !== '-') {
      if (!ASSIGNMENT.test(text)) return;
    } else if (text.startsWith('--split-string=')) walkString(args[i].script.slice('--split-string='.length), st);
    else if (text === '--split-string' || /^-[iv0]*S$/.test(text)) {
      if (args[i + 1]) walkString(args[i + 1].script, st);
      return;
    } else if (/^-[iv0]*S./.test(text)) walkString(text.slice(text.indexOf('S') + 1), st);
    else if (text === '-u' || text === '--unset' || text === '-C' || text === '--chdir') i++;
  }
}

/** Removes the values a program takes as prose: `{flags: exact, glued: /-mVALUE/}`. Used where the name alone is not enough. */
function withoutTextArgs(args, spec) {
  const kept = [];
  for (let i = 0; i < args.length; i++) {
    const text = args[i].text;
    if (spec.flags.has(text)) i++;
    else if (!spec.glued.test(text)) kept.push(args[i]);
  }
  return kept;
}

const GIT_TEXT = { flags: new Set(['-m', '-am', '-F', '-S', '-G']), glued: /^-(?:a?m|S|G|F)\S/ };
const GH_TEXT = { flags: new Set(['-b', '-t', '-n', '-m', '-S', '-d', '-q', '-f', '-F', '--jq', '--field', '--raw-field', '--search', '--template', '--body-file']), glued: /^-[btnmSdqfF]\S|^--(?:jq|field|raw-field|search|template)=/ };
// Their positional arguments are search terms or prose, not something to run.
const GIT_TEXT_SUBCOMMANDS = new Set(['grep', 'stash']);

const READS_NOTHING = new Set(['echo', 'printf', 'ls', 'stat', 'test', '[', 'chmod', 'chown', 'file', 'mkdir', 'touch', 'which', 'type', 'dirname', 'basename', 'realpath', 'readlink', 'ssh-add', 'ssh-keygen', 'ssh-copy-id']);
const USES_KEY_IN_PLACE = new Set(['ssh', 'scp', 'sftp', 'rsync', 'autossh']);
const SEARCH_TOOLS = new Set(['grep', 'rg', 'ag', 'ack']);
const SCRIPT_RUNNERS = new Set(['tsx', 'ts-node', 'esno', 'nodemon', 'pm2', 'forever', 'sh', 'bash', 'zsh', 'dash', 'ksh']);
const COPIES_TREES = new Set(['tar', 'zip', '7z', 'cp', 'rsync', 'scp', 'ditto']);

function scanCommandWords(key, argv, st) {
  const skipSecrets = READS_NOTHING.has(key);
  const searchPattern = SEARCH_TOOLS.has(key) ? patternIndex(argv) : -1;
  const keyUser = USES_KEY_IN_PLACE.has(key);
  const runsScripts = INLINE_CODE[key] !== undefined || SCRIPT_RUNNERS.has(key);
  for (let i = 0; i < argv.length; i++) {
    if (i === searchPattern) continue;
    const isKeyValue = keyUser && argv[i - 1]?.text === '-i';
    scanWord(argv[i], st, skipSecrets || isKeyValue);
    if (runsScripts && i > 0 && fileNameCouldBe(foldName(baseName(argv[i].text)), 'sayso.mjs')) flag(st, SELF, 'runs the guard through an interpreter');
    if (!DATA_ONLY.has(key) && argv[i].text.includes('7428') && URL_TO_GUARD.test(argv[i].text)) flag(st, SELF, 'talks to the guard port on loopback');
  }
  if (COPIES_TREES.has(key)) {
    for (let i = 1; i < argv.length; i++) {
      const relative = homeRelative(resolvePath(argv[i].text, st), st);
      if (relative !== null && SECRET_DIR.test(relative)) flag(st, CREDENTIALS, 'copies a directory of secrets');
    }
  }
}

function patternIndex(argv) {
  let first = -1;
  for (let i = 1; i < argv.length; i++) {
    const text = argv[i].text;
    if (text === '-e' || text === '-f' || text === '--regexp' || text === '--file') return -1;
    if (first < 0 && text[0] !== '-') first = i;
  }
  return first;
}

// Argument helpers.

const NO_VALUE_FLAGS = new Set();

function positionals(args, valueFlags = NO_VALUE_FLAGS) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const text = args[i].text;
    if (text === '--') {
      out.push(...args.slice(i + 1));
      break;
    }
    if (text[0] === '-' && text.length > 1) {
      if (valueFlags.has(text)) i++;
      continue;
    }
    out.push(args[i]);
  }
  return out;
}

function hasFlag(args, ...names) {
  return args.some((arg) => names.includes(arg.text));
}

function hasShortFlag(args, letter) {
  return args.some((arg) => arg.text[0] === '-' && arg.text[1] !== '-' && arg.text.includes(letter));
}

function flagValues(args, shortFlag, longFlag) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const text = args[i].text;
    if ((text === shortFlag || text === longFlag) && args[i + 1]) out.push(args[i + 1]);
    else if (longFlag && text.startsWith(`${longFlag}=`)) out.push({ text: text.slice(longFlag.length + 1) });
  }
  return out;
}

function isDryRun(args) {
  return args.some((arg) => arg.text === '--dry-run' || arg.text.startsWith('--dry-run=') || arg.text === '--dryrun');
}

const lastPositional = (args) => positionals(args).slice(-1);
const allPositionals = (args) => positionals(args);
const inPlaceEdits = (args) => (hasShortFlag(args, 'i') || hasFlag(args, '--in-place') ? positionals(args) : []);

const WRITE_TARGETS = {
  __proto__: null,
  tee: allPositionals,
  mv: allPositionals,
  rm: allPositionals,
  unlink: allPositionals,
  truncate: (args) => positionals(args, new Set(['-s', '--size', '-r', '--reference'])),
  touch: allPositionals,
  cp: lastPositional,
  ln: lastPositional,
  install: lastPositional,
  rsync: lastPositional,
  ditto: lastPositional,
  sed: inPlaceEdits,
  perl: inPlaceEdits,
  curl: (args) => flagValues(args, '-o', '--output'),
  wget: (args) => flagValues(args, '-O', '--output-document'),
  dd: (args) => args.filter((arg) => arg.text.startsWith('of=')).map((arg) => ({ text: arg.text.slice(3) })),
};

// Per-command rules. Each takes (args, io, st, key) and only flags.

const REBUILDABLE = new Set(['node_modules', 'dist', 'build', '.next', 'target', '__pycache__', '.cache', 'coverage', '.turbo', 'out', '.pytest_cache', '.venv', 'venv', 'tmp']);
const OS_SCRATCH_CHILD = /^\/(?:tmp|var\/tmp|var\/folders)\/./i;
const FIND_CLEANUP_NAME = /^(?:\*\.py[co]|\.DS_Store)$/;

function isRebuildable(arg) {
  if (arg.text[0] === '/' || arg.text[0] === '~') return false;
  if (arg.text.includes('$')) return false;
  const segments = arg.text.split('/').filter((segment) => segment !== '' && segment !== '.');
  if (segments.includes('..')) return false;
  for (const segment of segments) {
    if (REBUILDABLE.has(segment)) return true;
    if (GLOB_CHARS.test(segment)) return false;
  }
  return false;
}

/** Children of the OS temp roots go away on their own. Only when written as such: a relative path in a project that happens to live under /tmp is still that project. Normalizing first means /tmp/../etc is not one of them. */
function isOsScratch(arg, st) {
  return arg.text[0] === '/' && !arg.text.includes('$') && OS_SCRATCH_CHILD.test(deleteRootOf(arg, st));
}

function deleteRootOf(arg, st) {
  return resolvePath(arg.text.replace(/\/\*+\/?$/, '/'), st);
}

function classifyRecursiveDelete(target, st) {
  const root = deleteRootOf(target, st);
  if (isProtectedRoot(root, st) && (!target.dynamic || target.text.endsWith('*') || !target.text.includes('$'))) {
    flag(st, CATASTROPHIC, root === st.home ? 'recursive delete of home directory' : 'recursive delete of a system root');
    return;
  }
  if (isRebuildable(target) || isOsScratch(target, st)) return;
  if (target.dynamic) flag(st, DESTRUCTIVE, target.glob ? 'recursive delete of a glob' : 'recursive delete of a variable target');
  else flag(st, DESTRUCTIVE, 'recursive delete');
}

function classifyPlainDelete(target, st) {
  if (isOsScratch(target, st) || isRebuildable(target)) return;
  if (target.glob) {
    flag(st, DESTRUCTIVE, 'delete of a glob or dynamic file list');
    return;
  }
  if (target.dynamic) return;
  const path = resolvePath(target.text, st);
  if (SYSTEM_PATH.test(path) && !SCRATCH_SYSTEM_PATH.test(path)) {
    flag(st, DESTRUCTIVE, 'delete of a system path');
    return;
  }
  const relative = homeRelative(path, st);
  if (relative !== null && relative[0] === '.') flag(st, DESTRUCTIVE, 'delete of a home dot path');
}

function ruleRm(args, _io, st) {
  let recursive = false;
  let flagsEnded = false;
  const targets = [];
  for (const arg of args) {
    const text = arg.text;
    if (!flagsEnded && text === '--') {
      flagsEnded = true;
    } else if (!flagsEnded && text[0] === '-' && text.length > 1 && !arg.dynamic) {
      if (text.startsWith('--')) {
        if (text.length > 2 && '--recursive'.startsWith(text)) recursive = true;
        if (text.length > 4 && '--no-preserve-root'.startsWith(text)) flag(st, CATASTROPHIC, 'rm with --no-preserve-root');
      } else if (text.includes('r') || text.includes('R')) recursive = true;
    } else targets.push(arg);
  }
  for (const target of targets) {
    if (recursive) classifyRecursiveDelete(target, st);
    else classifyPlainDelete(target, st);
  }
}

function ruleRimraf(args, _io, st) {
  for (const target of positionals(args)) classifyRecursiveDelete(target, st);
}

function ruleCopyFromNull(args, _io, st) {
  const pos = positionals(args);
  if (pos.length === 2 && pos[0].text === '/dev/null') checkEmptiedFiles([pos[1]], st);
}

function ruleMv(args, io, st) {
  const pos = positionals(args);
  if (pos.length < 2) return;
  ruleCopyFromNull(args, io, st);
  if (resolvePath(pos[pos.length - 1].text, st) === '/dev/null') flag(st, DESTRUCTIVE, 'move into /dev/null');
  for (const source of pos.slice(0, -1)) {
    if (!source.dynamic && isProtectedRoot(resolvePath(source.text, st), st)) flag(st, DESTRUCTIVE, 'moves a protected root directory');
  }
}

function ruleTee(args, io, st) {
  const previous = io.piped ? io.previous : null;
  const empty = previous?.length > 0 ? printsNothing(ruleKey(baseName(previous[0].text)), previous.slice(1), NO_IO) : io.stdinEmpty;
  if (empty && !hasShortFlag(args, 'a') && !hasFlag(args, '--append')) checkEmptiedFiles(positionals(args), st);
}

function ruleDd(args, _io, st) {
  for (const arg of args) {
    if (!arg.text.startsWith('of=')) continue;
    const path = resolvePath(arg.text.slice(3), st);
    if (path.startsWith('/dev/')) {
      if (!HARMLESS_DEVICE.test(path)) flag(st, CATASTROPHIC, 'dd onto a device');
    } else flag(st, DESTRUCTIVE, 'dd overwrites a file');
  }
}

function ruleDdrescue(args, _io, st) {
  if (positionals(args).slice(1).some((arg) => BLOCK_DEVICE.test(resolvePath(arg.text, st)))) flag(st, CATASTROPHIC, 'dd onto a device');
}

function ruleShred(args, _io, st) {
  const onDevice = positionals(args).some((arg) => resolvePath(arg.text, st).startsWith('/dev/'));
  flag(st, onDevice ? CATASTROPHIC : DESTRUCTIVE, onDevice ? 'shred of a device' : 'shred of a file');
}

function rulePartition(key) {
  return (args, _io, st) => {
    if (hasShortFlag(args, 'l') || hasFlag(args, '--list')) return;
    flag(st, CATASTROPHIC, `${key} on a disk`);
  };
}

/** Anything but a named read-only flag writes the partition table, including no flags at all. */
function ruleDiskUnlessReading(key, readOnly) {
  return (args, _io, st) => {
    if (!args.some((arg) => readOnly.has(arg.text))) flag(st, CATASTROPHIC, `${key} on a disk`);
  };
}

/** A verb anywhere among the positionals, since value flags before it are not all known. */
function ruleDiskVerb(key, verbs, risk = CATASTROPHIC) {
  return (args, _io, st) => {
    if (positionals(args).some((arg) => verbs.test(arg.text))) flag(st, risk, `${key} destroys data`);
  };
}

function ruleDiskFlag(key, flags) {
  return (args, _io, st) => {
    if (args.some((arg) => flags.test(arg.text))) flag(st, CATASTROPHIC, `${key} destroys data`);
  };
}

function ruleZfs(args, io, st) {
  ruleDiskVerb('zfs', /^destroy$/i)(args, io, st);
  ruleDiskVerb('zfs', /^rollback$/i, DESTRUCTIVE)(args, io, st);
}

const DISKUTIL_DESTROYS = /^(?:secure)?erase|^zerodisk|^randomdisk|^reformat|^partitiondisk|^delete|^mergepartitions|^splitpartition|^addpartition|^resizevolume|^resizecontainer/i;

function ruleDiskutil(args, _io, st) {
  const [first, second] = positionals(args);
  if (DISKUTIL_DESTROYS.test(first?.text ?? '') || DISKUTIL_DESTROYS.test(second?.text ?? '')) flag(st, CATASTROPHIC, 'diskutil erase');
}

function ruleRsync(args, _io, st) {
  if (!args.some((arg) => arg.text.startsWith('--delete') || arg.text.startsWith('--remove-source-files'))) return;
  if (isDryRun(args) || hasFlag(args, '-n') || hasShortFlag(args, 'n')) return;
  const target = positionals(args).at(-1);
  if (target && !/^[^/]*:/.test(target.text) && !isRebuildable(target) && !isOsScratch(target, st)) flag(st, DESTRUCTIVE, 'rsync deletes files');
}

function rulePermissions(key) {
  return (args, _io, st) => {
    if (!hasShortFlag(args, 'R') && !hasFlag(args, '--recursive')) return;
    const pos = positionals(args);
    for (const target of pos.slice(1)) {
      if (isProtectedRoot(deleteRootOf(target, st), st)) {
        flag(st, CATASTROPHIC, `recursive ${key} of root or home`);
        return;
      }
    }
    if (key === 'chmod' && /^(0?777|a\+rwx|ugo\+rwx)$/.test(pos[0]?.text ?? '')) flag(st, DESTRUCTIVE, 'recursive chmod 777');
  };
}

function ruleCrontab(args, _io, st) {
  if (hasShortFlag(args, 'r')) flag(st, DESTRUCTIVE, 'removes the crontab');
  else if (positionals(args).length > 0 || hasFlag(args, '-')) flag(st, DESTRUCTIVE, 'installs a crontab');
}

const GUARD_PROCESS = /sayso|\brun\.sh\b|\bserver\.mjs\b|\bhook\.mjs\b|daemon\.pid/i;

/** pkill reads its argument as a regex, so `say.o` is aimed at the guard too. Short ones match everything by accident. */
function patternMatchesGuard(text) {
  if (text[0] === '-' || !/[.*?[(|\\]/.test(text)) return false;
  try {
    const pattern = new RegExp(text, 'i');
    return pattern.test('sayso') && (text.length >= 3 || new RegExp(`^(?:${text})$`, 'i').test('sayso'));
  } catch {
    return false;
  }
}

function ruleKill(args, _io, st, key) {
  if (args.some((arg) => GUARD_PROCESS.test(arg.text) || (key !== 'kill' && patternMatchesGuard(arg.text)))) flag(st, SELF, 'kills the guard');
  if (key !== 'kill') return;
  const pids = [];
  for (let i = 0; i < args.length; i++) {
    const text = args[i].text;
    if (text === '-s') i++;
    else if (i === 0 && text[0] === '-' && text !== '--') continue;
    else if (text !== '--') pids.push(text);
  }
  if (pids.includes('-1')) flag(st, DESTRUCTIVE, 'signals every process');
}

function always(risk, why) {
  return (_args, _io, st) => flag(st, risk, why);
}

function ruleSystemctl(args, _io, st) {
  const verb = positionals(args)[0]?.text;
  if (verb === 'poweroff' || verb === 'reboot' || verb === 'halt') flag(st, DESTRUCTIVE, 'shuts the machine down');
}

// git. Each entry returns a reason when the subcommand destroys work.

const GIT_GLOBAL_VALUE_FLAGS = new Set(['-C', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env', '--exec-path']);
const DOT_PATHS = new Set(['.', './', ':/', '*', ':(top)']);

function isForcePushFlag(text) {
  if (text === '--mirror' || text === '--delete' || text === '--prune') return true;
  if (text.startsWith('--force')) return true;
  if (text[0] === '-' && text[1] !== '-') return text.includes('f') || text.includes('d');
  return text[0] === ':' || text[0] === '+';
}

const GIT_RULES = {
  __proto__: null,
  push: (args) => (!isDryRun(args) && !hasFlag(args, '-n') && args.some((arg) => isForcePushFlag(arg.text)) ? 'git push that rewrites or deletes remote refs' : null),
  reset: (args) => (hasFlag(args, '--hard') ? 'git reset --hard' : null),
  clean: (args) => {
    if (hasFlag(args, '-n', '--dry-run') || hasShortFlag(args, 'n')) return null;
    return hasShortFlag(args, 'f') || hasFlag(args, '--force') ? 'git clean deletes untracked files' : null;
  },
  checkout: (args) => {
    if (hasFlag(args, '-f', '--force')) return 'git checkout --force discards local changes';
    const dashes = args.findIndex((arg) => arg.text === '--');
    if (dashes >= 0 && dashes < args.length - 1) return 'git checkout overwrites local files';
    const targets = positionals(args, new Set(['-b', '-B', '--orphan', '-t', '--track']));
    return targets.some((arg) => DOT_PATHS.has(arg.text) || arg.text === '..') ? 'git checkout overwrites local files' : null;
  },
  restore: (args) => {
    const worktree = hasFlag(args, '--worktree') || !(hasFlag(args, '--staged') || hasShortFlag(args, 'S'));
    return worktree && positionals(args).some((arg) => DOT_PATHS.has(arg.text)) ? 'git restore discards local changes' : null;
  },
  switch: (args) => (hasFlag(args, '-f', '--force', '--discard-changes') ? 'git switch discards local changes' : null),
  branch: (args) => (hasShortFlag(args, 'D') ? 'git branch -D' : null),
  stash: (args) => (['drop', 'clear'].includes(positionals(args)[0]?.text) ? 'git stash drop or clear' : null),
  'filter-branch': () => 'git filter-branch rewrites history',
  'filter-repo': () => 'git filter-repo rewrites history',
  reflog: (args) => (['expire', 'delete'].includes(positionals(args)[0]?.text) ? 'git reflog expire' : null),
  gc: (args) => (hasFlag(args, '--prune=now') ? 'git gc --prune=now' : null),
  'update-ref': (args) => (hasShortFlag(args, 'd') ? 'git update-ref -d' : null),
  tag: (args) => (hasShortFlag(args, 'd') || hasFlag(args, '--delete') ? 'git tag -d' : null),
};

function ruleGit(args, _io, st) {
  const aliases = new Map();
  let i = 0;
  for (; i < args.length; i++) {
    const text = args[i].text;
    if (text[0] !== '-') break;
    if (text === '-c') {
      const setting = args[i + 1];
      const alias = /^alias\.([^=]+)=(.*)$/s.exec(setting?.text ?? '');
      if (alias) aliases.set(alias[1], alias[2]);
      else if (setting) checkGitSetting(setting.script, st);
      i++;
    } else if (text.startsWith('-c')) checkGitSetting(args[i].script.slice(2), st);
    else if (GIT_GLOBAL_VALUE_FLAGS.has(text)) i++;
  }
  if (i >= args.length) return;
  let subcommand = args[i].text;
  let rest = args.slice(i + 1);
  const alias = aliases.get(subcommand);
  if (alias !== undefined) {
    if (alias[0] === '!') {
      walkString(alias.slice(1), st);
      return;
    }
    const pieces = alias.trim().split(/\s+/);
    subcommand = pieces[0];
    rest = [...pieces.slice(1).map((piece) => literalArg(piece, st)), ...rest];
  }
  const why = GIT_RULES[subcommand]?.(rest);
  if (why) flag(st, DESTRUCTIVE, why);
  const verb = positionals(rest)[0]?.text;
  if ((subcommand === 'bisect' && verb === 'run') || (subcommand === 'submodule' && verb === 'foreach')) {
    const at = rest.findIndex((arg) => arg.text === verb);
    keepingRealRisks(st, (inner) => dispatch(rest.slice(at + 1), NO_IO, inner));
  }
  if (!GIT_TEXT_SUBCOMMANDS.has(subcommand)) walkCommandStrings(withoutTextArgs(rest, GIT_TEXT), NO_IO, st, false);
}

/** Git runs many settings as shell: core.pager, core.sshCommand, core.fsmonitor, diff.external and more. */
function checkGitSetting(script, st) {
  const equals = script.indexOf('=');
  if (equals > 0) walkCandidate(script.slice(equals + 1), st);
}

// Tools whose danger is a verb. Keys are one or two leading positionals.

const VERB_VALUE_FLAGS = new Set(['-n', '--namespace', '--context', '--kubeconfig', '--cluster', '--user', '-s', '--server', '--profile', '--region', '--output', '--endpoint-url', '-c', '-H', '--host', '--config', '-f', '--file', '-p', '--project-name', '--env-file', '--prefix', '--filter', '-w', '--workspace', '-C', '--cwd', '--dir', '-a', '--app', '--stack', '-R', '--repo', '--hostname']);

const VERB_RULES = {
  __proto__: null,
  npm: { publish: OUTWARD },
  yarn: { publish: OUTWARD, 'npm publish': OUTWARD },
  pnpm: { publish: OUTWARD },
  bun: { publish: OUTWARD },
  cargo: { publish: OUTWARD },
  twine: { upload: OUTWARD },
  gem: { push: OUTWARD },
  vsce: { publish: OUTWARD },
  poetry: { publish: OUTWARD },
  uv: { publish: OUTWARD },
  wrangler: { deploy: OUTWARD },
  pulumi: { up: OUTWARD, destroy: DESTRUCTIVE },
  kubectl: { apply: OUTWARD, delete: DESTRUCTIVE, drain: DESTRUCTIVE },
  helm: { uninstall: DESTRUCTIVE, delete: DESTRUCTIVE, install: OUTWARD, upgrade: OUTWARD },
  fly: { deploy: OUTWARD, destroy: DESTRUCTIVE, 'apps destroy': DESTRUCTIVE },
  vercel: { rm: DESTRUCTIVE, remove: DESTRUCTIVE },
  heroku: { 'apps:destroy': DESTRUCTIVE },
  docker: { push: OUTWARD, 'system prune': DESTRUCTIVE, 'volume rm': DESTRUCTIVE, 'volume prune': DESTRUCTIVE },
  aws: { 's3 rm': DESTRUCTIVE, 's3 rb': DESTRUCTIVE },
  prisma: { 'migrate reset': DESTRUCTIVE },
  rails: { 'db:drop': DESTRUCTIVE, 'db:reset': DESTRUCTIVE },
  rake: { 'db:drop': DESTRUCTIVE, 'db:reset': DESTRUCTIVE },
  'manage.py': { flush: DESTRUCTIVE },
  gh: { 'repo delete': DESTRUCTIVE, 'release delete': DESTRUCTIVE, 'pr merge': OUTWARD, 'release create': OUTWARD },
};

function verbRule(key, table) {
  const runnerVerbs = RUNNER_VERBS[key];
  return (args, io, st) => {
    const pos = positionals(args, VERB_VALUE_FLAGS);
    const first = pos[0]?.text;
    if (first === undefined) return;
    if (runnerVerbs?.includes(first)) {
      const at = args.indexOf(pos[0]);
      const inner = peelWrapper({ long: [...RUNNER_VALUE_FLAGS], short: 'pcFC' }, args.slice(at + 1));
      dispatch(inner, io, st);
      return;
    }
    if (isDryRun(args)) return;
    const risk = table[first] ?? table[`${first} ${pos[1]?.text}`];
    if (risk) flag(st, risk, `${key} ${table[first] ? first : `${first} ${pos[1].text}`}`);
  };
}

const EXTRA_VERB_CHECKS = {
  __proto__: null,
  terraform: (args, st, pos) => {
    if (pos[0]?.text === 'destroy' || (pos[0]?.text === 'apply' && hasFlag(args, '-destroy', '--destroy'))) flag(st, DESTRUCTIVE, 'terraform destroy');
    else if (pos[0]?.text === 'apply') flag(st, OUTWARD, 'terraform apply');
  },
  vercel: (args, st) => {
    if (hasFlag(args, '--prod', '--production')) flag(st, OUTWARD, 'vercel production deploy');
  },
  docker: (args, st, pos) => {
    if (pos[0]?.text === 'compose' && pos[1]?.text === 'down' && (hasFlag(args, '-v', '--volumes'))) flag(st, DESTRUCTIVE, 'docker compose down deletes volumes');
  },
  'docker-compose': (args, st, pos) => {
    if (pos[0]?.text === 'down' && hasFlag(args, '-v', '--volumes')) flag(st, DESTRUCTIVE, 'docker compose down deletes volumes');
  },
  aws: (_args, st, pos) => {
    if (/^(delete|terminate)-/.test(pos[1]?.text ?? '')) flag(st, DESTRUCTIVE, 'aws delete or terminate');
  },
  gcloud: (_args, st, pos) => {
    if (pos.some((arg) => arg.text === 'delete')) flag(st, DESTRUCTIVE, 'gcloud delete');
  },
  az: (_args, st, pos) => {
    if (pos.some((arg) => arg.text === 'delete')) flag(st, DESTRUCTIVE, 'az delete');
  },
  gh: (args, st, pos) => {
    const noun = pos[0]?.text;
    const verb = pos[1]?.text;
    if (noun === 'repo' && verb === 'edit' && args.some((arg) => arg.text.startsWith('--visibility'))) flag(st, DESTRUCTIVE, 'gh repo edit visibility');
    if (noun === 'repo' && verb === 'create' && hasFlag(args, '--public')) flag(st, OUTWARD, 'gh repo create --public');
    if (noun === 'auth' && verb === 'token') flag(st, CREDENTIALS, 'prints a github token');
    if (noun === 'api') {
      const method = flagValues(args, '-X', '--method')[0]?.text ?? args.find((arg) => arg.text.startsWith('-X') && arg.text.length > 2)?.text.slice(2);
      if (method?.toUpperCase() === 'DELETE') flag(st, DESTRUCTIVE, 'gh api delete');
    }
  },
};

// psql and mysql take `\! cmd`, mysql `system cmd`, sqlite3 `.shell cmd` and `.system cmd`.
const SQL_SHELL_ESCAPE = /(?:^|[\n;])\s*(?:\\!|\.shell|\.system|system)\s+([^\n;]+)/gi;

function ruleSql(args, io, st) {
  const sources = args.map((arg) => arg.text);
  if (io.heredoc) sources.push(io.heredoc);
  if (io.herestring) sources.push(io.herestring);
  if (io.piped && io.previous) sources.push(...io.previous.slice(1).map((arg) => arg.text));
  for (const source of sources) {
    const why = dangerousSql(source);
    if (why) flag(st, DESTRUCTIVE, why);
    for (const escape of source.matchAll(SQL_SHELL_ESCAPE)) walkCandidate(escape[1], st);
  }
}

function dangerousSql(source) {
  const sql = source.toLowerCase();
  if (/\bdrop\s+(table|database|schema)\b/.test(sql) || sql.includes('dropdatabase(')) return 'sql drop';
  if (/\btruncate\s+(table\s+)?[\w"`.]/.test(sql)) return 'sql truncate';
  if (sql.includes('delete')) {
    for (const statement of sql.split(';')) {
      if (/\bdelete\s+from\b/.test(statement) && !/\bwhere\b/.test(statement)) return 'sql delete with no where';
    }
  }
  return null;
}

function ruleRedis(args, _io, st) {
  if (args.some((arg) => /^flush(all|db)$/i.test(arg.text))) flag(st, DESTRUCTIVE, 'redis flush');
}

// Credentials and guard self-protection.

function ruleSecurity(args, _io, st) {
  const verb = positionals(args, new Set(['-s', '-a', '-l', '-c', '-D']))[0]?.text;
  if (/^find-(generic|internet)-password$/.test(verb ?? '') && (hasShortFlag(args, 'w') || hasShortFlag(args, 'g'))) {
    flag(st, CREDENTIALS, 'reads a keychain password');
  }
  if (verb === 'dump-keychain') flag(st, CREDENTIALS, 'dumps the keychain');
}

const UPLOADED_SECRET = /(?:^|[=@/])\.env(?:\.[\w.-]+)?$|\.(?:pem|key|p12|pfx)$/i;
const UPLOAD_FLAGS = new Set(['-d', '--data', '--data-binary', '--data-raw', '--data-urlencode', '--data-ascii', '-F', '--form', '-T', '--upload-file']);
const LOOPBACK_HOST = String.raw`127(?:\.\d+){1,3}|localhost\.?|\[?::1\]?|\[?::ffff:127[\d.]*\]?|\[::\]|0\.0\.0\.0|0|2130706433|0x7f[\da-f.x]*|0177[\d.]*`;
const LOOPBACK = new RegExp(String.raw`(?:^|[/@:\s=])(?:${LOOPBACK_HOST})(?:$|[:/\s])`, 'i');
const LOOPBACK_IN_CODE = /127\.\d+|localhost|::1|0\.0\.0\.0/i;
const GUARD_PORT = /(?:^|\D)7428(?:$|\D)/;
const URL_TO_GUARD = new RegExp(String.raw`(?:^|[/@=])(?:${LOOPBACK_HOST}):7428(?:$|\D)`, 'i');
const DEV_TCP = /\/dev\/(?:tcp|udp)\/([^/]+)\/(\S+)/;
const COMPUTED_PORT = /\$\(\(/;

function ruleLoopbackClient(args, _io, st) {
  const words = args.map((arg) => arg.text);
  if (words.some((word) => LOOPBACK.test(word)) && words.some((word) => GUARD_PORT.test(word) || COMPUTED_PORT.test(word))) {
    flag(st, SELF, 'talks to the guard port on loopback');
  }
}

function ruleCurl(args, io, st, key) {
  ruleLoopbackClient(args, io, st, key);
  for (let i = 0; i < args.length; i++) {
    const text = args[i].text;
    const isValue = UPLOAD_FLAGS.has(args[i - 1]?.text) || /^--(?:data[\w-]*|form|upload-file)=/.test(text);
    if (isValue && UPLOADED_SECRET.test(text)) flag(st, CREDENTIALS, 'uploads a secret file');
  }
}

const SAYSO_READ_ONLY = new Set(['status', 'doctor', 'audit']);

function ruleSayso(args, _io, st) {
  const subcommand = positionals(args)[0]?.text;
  if (subcommand !== undefined && !SAYSO_READ_ONLY.has(subcommand)) flag(st, SELF, 'changes the guard through its cli');
}

// Script runners: shells, eval, ssh and friends, whose arguments are more shell.

const SHELL_VALUE_LONG = new Set(['--rcfile', '--init-file']);

function ruleShell(args, io, st) {
  let i = 0;
  let readsStdin = false;
  for (; i < args.length; i++) {
    const text = args[i].text;
    if (text === '--') {
      i++;
      break;
    }
    if (text.startsWith('--')) {
      if (SHELL_VALUE_LONG.has(text)) i++;
      continue;
    }
    if ((text[0] !== '-' && text[0] !== '+') || text.length === 1) break;
    if (text[0] === '-' && text.includes('c')) {
      const script = args[i + 1];
      if (script) walkString(script.script, st);
      walkArgStrings(args.slice(i + 2), st);
      return;
    }
    if (text.includes('s')) readsStdin = true;
    if (text.endsWith('o') || text.endsWith('O')) i++;
  }
  const scriptArg = args[i];
  if (!readsStdin && scriptArg && scriptArg.text !== '-' && scriptArg.text !== '/dev/stdin') {
    if (scriptArg.dynamic) flag(st, OPAQUE, 'runs a script chosen at run time');
    walkArgStrings(args.slice(i + 1), st);
    return;
  }
  if (io.heredoc !== null) walkString(io.heredoc, st);
  else if (io.herestring !== null) walkString(io.herestring, st);
  else if (io.piped || io.stdinUnknown) flag(st, OPAQUE, 'pipeline into a shell');
}

// Well-known tools that print shell setup for their caller to eval.
const ENV_SETUP_SUBSTITUTION = /^\$\(\s*(?:\S*\/)?(?:brew shellenv|ssh-agent(?: -s)?|pyenv init -(?:-path)?|rbenv init -|nodenv init -|fnm env(?: --[\w-]+)*|direnv hook \w+|mise activate \w+|zoxide init \w+|starship init \w+|conda shell\.\w+ hook)\s*\)$/;

function ruleEval(args, _io, st) {
  if (args.length === 1 && ENV_SETUP_SUBSTITUTION.test(args[0].text)) return;
  if (args.some((arg) => arg.dynamic)) flag(st, OPAQUE, 'eval of a non-literal argument');
  const source = args.filter((arg) => arg.text !== '--').map((arg) => arg.script).join(' ');
  if (source) walkString(source, st);
}

function ruleSource(args, io, st) {
  const file = args[0];
  if (file?.proc) flag(st, OPAQUE, 'source of a process substitution');
  else if (io.piped && (file?.text === '/dev/stdin' || file?.text === '/dev/fd/0')) flag(st, OPAQUE, 'pipeline into source');
}

// at and batch read their command from stdin, and walkCommandStrings already reads the literal forms of that.
function ruleAt(_args, io, st) {
  const literal = io.previous?.[0]?.text === 'echo' || io.previous?.[0]?.text === 'printf';
  if (io.piped && !literal) flag(st, OPAQUE, 'pipeline into a scheduler');
  else if (io.stdinUnknown) flag(st, OPAQUE, 'pipeline into a scheduler');
}

// Runners that take the program as plain trailing words, behind their own flags and names.
function ruleArgvRunner(args, _io, st) {
  for (let i = 0; i < args.length; i++) {
    if (RULES[ruleKey(baseName(args[i].text))] && spendStringWalk(st)) keepingRealRisks(st, (inner) => dispatch(args.slice(i), NO_IO, inner));
  }
}

const SSH_VALUE_FLAGS = new Set(['-b', '-c', '-D', '-E', '-e', '-F', '-I', '-i', '-J', '-L', '-l', '-m', '-O', '-o', '-p', '-Q', '-R', '-S', '-W', '-w', '-B']);
const SSH_COMMAND_OPTION = /^(?:ProxyCommand|LocalCommand|RemoteCommand|KnownHostsCommand)(?:\s*=\s*|\s+)(.*)$/is;

function checkSshOptions(args, st) {
  for (let i = 0; i < args.length; i++) {
    const text = args[i].text;
    const option = text === '-o' ? args[i + 1]?.script : text.startsWith('-o') ? args[i].script.slice(2) : null;
    const command = option ? SSH_COMMAND_OPTION.exec(option) : null;
    if (command) walkCandidate(command[1], st);
  }
}

function ruleScp(args, _io, st) {
  checkSshOptions(args, st);
}

function ruleSsh(args, _io, st) {
  checkSshOptions(args, st);
  for (let i = 0; i < args.length; i++) {
    const text = args[i].text;
    if (text[0] === '-') {
      if (SSH_VALUE_FLAGS.has(text)) i++;
      continue;
    }
    const remote = args.slice(i + 1).map((arg) => arg.script).join(' ');
    if (remote) walkString(remote, st);
    return;
  }
}

function ruleTrap(args, _io, st) {
  if (args[0] && args[0].text !== '-' && args[0].text[0] !== '-') walkString(args[0].script, st);
}

function ruleSu(args, _io, st) {
  const script = flagValues(args, '-c', '--command')[0];
  if (script) walkString(script.script ?? script.text, st);
}

function ruleWatch(args, _io, st) {
  const inner = peelWrapper({ short: 'nq', long: ['--interval', '--equexit', '--queue'] }, args);
  if (inner.length) walkString(inner.map((arg) => arg.script).join(' '), st);
}

function withPlaceholder(arg, placeholder) {
  if (!arg.text.includes(placeholder)) return arg;
  return listArg(arg.text, arg.script.replaceAll(placeholder, '$__item'));
}

const FIND_ACTION = new Set(['-delete', '-exec', '-execdir', '-ok', '-okdir']);
const FIND_WIDENS = new Set(['-o', '-or', ',', '!', '-not']);

/** Only `-name dist -delete` shapes are cleanup. Find evaluates left to right, so a test after the action narrows nothing, and OR or NOT reach beyond the name. */
function cleansOnlyRebuildables(args) {
  const action = args.findIndex((arg) => FIND_ACTION.has(arg.text));
  const names = flagValues(args.slice(0, action < 0 ? args.length : action), '-name').map((arg) => arg.text);
  if (names.length === 0 || !names.every((name) => REBUILDABLE.has(name) || FIND_CLEANUP_NAME.test(name))) return false;
  return !args.some((arg) => FIND_WIDENS.has(arg.text));
}

function ruleFind(args, io, st) {
  let root = null;
  const cleansRebuildables = cleansOnlyRebuildables(args);
  for (let i = 0; i < args.length; i++) {
    const text = args[i].text;
    if (root === null && text[0] !== '-' && text !== '(' && text !== '!') root = args[i];
    if (text === '-delete') {
      const scope = root && !root.dynamic ? resolvePath(root.text, st) : null;
      if (scope && isProtectedRoot(scope, st)) flag(st, CATASTROPHIC, 'find -delete from a protected root');
      else if (!cleansRebuildables) flag(st, DESTRUCTIVE, 'find -delete');
    } else if (text === '-exec' || text === '-execdir' || text === '-ok' || text === '-okdir') {
      const inner = [];
      for (i++; i < args.length; i++) {
        const piece = args[i].text;
        if (piece === ';' || piece === '+') break;
        inner.push(withPlaceholder(args[i], '{}'));
      }
      const removesOnlyMatch = ruleKey(baseName(inner[0]?.text ?? '')) === 'rm' && positionals(inner.slice(1)).every((arg) => arg.text === '{}');
      if (!(cleansRebuildables && removesOnlyMatch)) {
        dispatch(inner, { ...io, piped: false, heredoc: null, herestring: null, truncates: [] }, st);
      }
    }
  }
}

function ruleXargs(args, io, st) {
  const spec = { short: 'IJdELnPsaS', long: ['--replace', '--delimiter', '--eof', '--max-lines', '--max-args', '--max-procs', '--max-chars', '--arg-file'] };
  const inner = peelWrapper(spec, args);
  if (!inner || inner.length === 0) return;
  const before = args.slice(0, args.length - inner.length);
  const replaced = flagValues(before, '-I', '--replace')[0]?.text ?? flagValues(before, '-J')[0]?.text ?? before.find((arg) => /^-[IJ]./.test(arg.text))?.text.slice(2);
  const argv = replaced ? inner.map((arg) => withPlaceholder(arg, replaced)) : [...inner, listArg('{}', '$__item')];
  dispatch(argv, { ...io, piped: false, truncates: [] }, st);
}

const PARALLEL_VALUE_FLAGS = 'jPSaIn';

function ruleParallel(args, io, st) {
  const peeled = peelWrapper({ short: PARALLEL_VALUE_FLAGS, long: ['--jobs', '--arg-file', '--delay', '--timeout', '--results', '--joblog', '--sshlogin'] }, args);
  const separator = peeled.findIndex((arg) => arg.text === ':::' || arg.text === '::::' || arg.text === ':::+');
  const command = separator >= 0 ? peeled.slice(0, separator) : peeled;
  if (command.length === 0) {
    if (separator >= 0) for (const item of peeled.slice(separator + 1)) walkString(item.script, st);
    else if (io.piped) flag(st, OPAQUE, 'pipeline into parallel with no command');
    return;
  }
  const source = command.map((arg) => arg.script).join(' ');
  walkString(source.includes('{}') ? source.replaceAll('{}', '$__item') : `${source} $__item`, st);
}

// Inline code in other languages.

const CODE_PATTERNS = [
  [/rmtree|os\.remove|\bunlink|\brmdir|rm_rf|fs\.rm\b|rmSync|FileUtils\.rm/, 'inline code deletes files'],
  [/(?<![.\w])system\(|\.system\(|subprocess|child_process|(?<![.\w])exec\(|os\.exec|os\.execute|execSync|\bspawn|\bpopen|shell_exec|passthru|proc_open|pcntl_exec|Open3|do shell script/i, 'inline code runs a process'],
  [/(?<![.\w])eval\(|b64decode/, 'inline code evaluates generated code'],
];
// A heredoc script reaches as far as `python3 script.py`, which passes unread, so process use alone is not a signal there.
const SCRIPT_PATTERNS = [
  [/rmtree|rm_rf|rmSync|fs\.rm\b|FileUtils\.rm/, 'inline script deletes a tree'],
  [/b64decode[\s\S]*(?:exec|eval)\(|(?:exec|eval)\([\s\S]*b64decode/, 'inline script runs decoded code'],
];
// Perl, Ruby and PHP also run a process with no parenthesis at all.
const BARE_PROCESS = /`|(?<![.\w$@%])(?:system|exec)\s+["'$@%(\[]|%x[({[<|!/]|\bqx\s*[({[<|!/]|\bopen\s*\(?[^,\n]*,\s*["'](?:\||-\||\|-)|\|["']\s*\)/;
const PROCESS_EXEC = /system|subprocess|child_process|exec|spawn|popen|shell_exec|passthru|proc_open|open3|do shell script|%x|\bqx\b|`|\|\s*["']|["']\s*\|/i;
const STRING_LITERAL = /(["'`])((?:\\.|(?!\1)[^\\])*)\1/g;
// `["rm", "-rf", "x"]`, `system "rm", "-rf", "x"` and `spawn("rm", ["-rf", "x"])` are one command in several strings.
const STRING_RUN = /(?:["'][^"'\n]*["']\s*,\s*\[?\s*)+["'][^"'\n]*["']/g;
const QUOTE_OPERATOR = /(?:%[xqQwW]|\b(?:qx|qq|qw|q))\s*(?:\(([^)]*)\)|\{([^}]*)\}|\[([^\]]*)\]|<([^>]*)>|\|([^|]*)\||!([^!]*)!|\/([^/]*)\/)/g;
const WRITES_A_FILE = /writeFile|write_text|write_bytes|appendFile|json\.dump|open\([^)]*["'][wax]b?\+?["']|File\.write/;

function codeNamesGuard(code, st) {
  const folded = foldName(code);
  return folded.includes(SOCKET_NAME) || folded.includes(st.stateBase) || folded.includes('sayso.mjs') || folded.includes(st.stateSegments.join('/'));
}

function checkInlineCode(code, sole, st, patterns = CODE_PATTERNS, runsBare = false) {
  if (sole) {
    flag(st, OPAQUE, 'inline code is not literal');
    return;
  }
  for (const [pattern, why] of patterns) {
    if (pattern.test(code)) flag(st, OPAQUE, why);
  }
  if (runsBare && BARE_PROCESS.test(code)) flag(st, OPAQUE, 'inline code runs a process');
  if (SECRET_IN_CODE.test(code)) flag(st, CREDENTIALS, 'inline code names a secret file');
  if (codeNamesGuard(code, st)) flag(st, SELF, 'inline code names the guard state');
  if (code.includes('7428') && LOOPBACK_IN_CODE.test(code)) flag(st, SELF, 'talks to the guard port on loopback');
  checkEmbeddedShell(code, st, PROCESS_EXEC.test(code));
  checkPathsInCode(code, st);
}

/** A glob or a case change in a string literal aims at the same directory a plain spelling would. */
function checkPathsInCode(code, st) {
  if (!code.includes('/')) return;
  for (const match of code.matchAll(STRING_LITERAL)) {
    const text = match[2];
    if (HAS_BLANK.test(text) || !text.includes('/')) continue;
    if (wordNamesStateDir(text, st)) flag(st, SELF, 'inline code names the guard state');
    if (WRITES_A_FILE.test(code) && isSettingsPath(resolvePath(text, st), st)) flag(st, SELF, 'write to agent settings');
  }
}

/** A literal shell string inside code is read with the shell rules, so os.system('rm -rf /') scores as rm -rf /. */
function checkEmbeddedShell(code, st, singleWords) {
  const candidates = [];
  for (const match of code.matchAll(STRING_LITERAL)) candidates.push(match[2]);
  for (const match of code.matchAll(STRING_RUN)) {
    candidates.push([...match[0].matchAll(/["']([^"']*)["']/g)].map((piece) => piece[1]).join(' '));
  }
  if (code.includes('%') || code.includes('q')) {
    for (const match of code.matchAll(QUOTE_OPERATOR)) candidates.push(match.slice(1).find((body) => body !== undefined));
  }
  for (const candidate of candidates) {
    if (!singleWords && !HAS_BLANK.test(candidate)) continue;
    for (const value of valuesIn(candidate)) walkCandidate(value, st);
  }
}

const INLINE_CODE = {
  __proto__: null,
  python: { code: /^-[A-Za-z]*c$/, glued: 'c', stop: 'WXm', values: new Set(['-W', '-X']) },
  node: { code: /^(?:-e|--eval|-p|--print|-pe)$/, values: new Set(['-r', '--require', '--import', '--loader', '--experimental-loader']) },
  perl: { code: /^-[A-Za-z0-9.]*[eE]$/, glued: 'eE', stop: 'IMmxiCDFd', runsBare: true, values: new Set(['-I', '-M']) },
  ruby: { code: /^-[A-Za-z]*e$/, glued: 'e', stop: 'IrEKCFTWx', runsBare: true, values: new Set(['-I', '-r']) },
  php: { code: /^-r$/, glued: 'r', stop: 'cdfzt', runsBare: true, values: new Set(['-c', '-d']) },
  osascript: { code: /^-e$/, glued: 'e', stop: 'l', values: new Set(['-l']) },
  bun: { code: /^(?:-e|--eval|-p|--print)$/, values: new Set() },
  deno: { code: /^(?:-e|--eval)$/, values: new Set(), evalVerb: true },
  lua: { code: /^-e$/, glued: 'e', stop: 'l', values: new Set() },
  rscript: { code: /^-e$/, glued: 'e', stop: '', values: new Set() },
};

/** `python3 -c'code'` is one shell word, and the interpreter still runs what follows the flag. */
function gluedCode(text, spec) {
  if (!spec.glued || text[0] !== '-' || text[1] === '-') return null;
  for (let c = 1; c < text.length; c++) {
    const letter = text[c];
    if (spec.glued.includes(letter)) return text.slice(c + 1) || null;
    if (!isNameStart(letter) || spec.stop.includes(letter)) return null;
  }
  return null;
}

function interpreterRule(spec) {
  return (args, io, st) => {
    const inline = (code, sole) => checkInlineCode(code, sole, st, CODE_PATTERNS, spec.runsBare);
    const notCode = [];
    let hasProgram = false;
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      const text = arg.text;
      if (text === '-') {
        notCode.push(...args.slice(i + 1));
        break;
      }
      if (spec.evalVerb && text === 'eval' && !hasProgram) {
        const code = args[i + 1];
        if (code) inline(code.text, code.sole);
        return;
      }
      if (spec.code.test(text)) {
        const code = args[++i];
        if (code) inline(code.text, code.sole);
        hasProgram = true;
        continue;
      }
      const glued = gluedCode(text, spec);
      if (glued !== null) {
        inline(glued, false);
        hasProgram = true;
        continue;
      }
      const inlineFlag = text.startsWith('--eval=') ? '--eval=' : text.startsWith('--print=') ? '--print=' : null;
      if (inlineFlag) {
        inline(text.slice(inlineFlag.length), false);
        hasProgram = true;
        continue;
      }
      if (text === '-m') {
        const module = args.slice(i + 1);
        if (module.length) dispatch(module, { ...io, piped: false }, st);
        return;
      }
      if (spec.values.has(text)) {
        i++;
        continue;
      }
      if (text[0] === '-' && text.length > 1) {
        notCode.push(arg);
        continue;
      }
      hasProgram = true;
      if (baseName(text) === 'manage.py') RULES['manage.py'](args.slice(i + 1), io, st, 'manage.py');
      notCode.push(...args.slice(i));
      break;
    }
    walkCommandStrings(notCode, io, st, hasProgram);
    if (hasProgram) return;
    if (io.heredoc !== null) checkInlineCode(io.heredoc, false, st, SCRIPT_PATTERNS);
    else if (io.herestring !== null) inline(io.herestring, false);
    else if (io.piped || io.stdinUnknown) flag(st, OPAQUE, 'pipeline into an interpreter');
  };
}

function awkProgramsPipeUnknown(program) {
  const stripped = program.replace(STRING_LITERAL, '""');
  return /\bprintf?\b[^;}\n]*(?<!\|)\|&?\s*(?!["|\s])/.test(stripped) || /[\w)\]]\s*\|&?\s*getline/.test(stripped);
}

function ruleAwk(args, _io, st) {
  const program = positionals(args, new Set(['-F', '-v', '-f']))[0];
  if (hasShortFlag(args, 'f') || !program) return;
  const text = program.text;
  if (/\bsystem\s*\(|\|\s*["']?(?:sh|bash)\b|["']\s*\|&?\s*getline/.test(text) || awkProgramsPipeUnknown(text)) flag(st, OPAQUE, 'inline code runs a process');
  checkEmbeddedShell(text, st, /\bsystem\b|\|/.test(text));
  if (codeNamesGuard(text, st)) flag(st, SELF, 'inline code names the guard state');
  walkArgStrings(args.filter((arg) => arg !== program), st);
}

const SED_RUNS_COMMAND = /(?:^|[;{}\n\d$/])\s*e\s+([^;}\n]+)/g;
const SED_EVAL_FLAG = /\bs([^\w\s])(?:\\.|(?!\1)[^\\])*\1(?:\\.|(?!\1)[^\\])*\1[gpiImM\d]*e/;

/** GNU sed runs commands with its `e` command and the `e` flag of `s`. */
function ruleSed(args, _io, st) {
  const scripts = flagValues(args, '-e', '--expression');
  const first = positionals(args, new Set(['-e', '--expression', '-f', '--file', '-l', '-E']))[0];
  if (first && scripts.length === 0) scripts.push(first);
  for (const script of scripts) {
    if (SED_EVAL_FLAG.test(script.text)) flag(st, OPAQUE, 'inline code runs a process');
    for (const match of script.text.matchAll(SED_RUNS_COMMAND)) walkCandidate(match[1], st);
  }
}

function ruleExportLike(args, _io, st) {
  for (const arg of args) {
    const match = ASSIGNMENT.exec(arg.text);
    if (!match) continue;
    recordAssignment(match[1], arg.dynamic ? { dynamic: true } : literalArg(arg.text.slice(match[0].length), st), st);
    if (COMMAND_ENV.test(match[1])) walkCandidate(arg.script.slice(match[0].length), st);
  }
}

function ruleRead(args, _io, st) {
  for (const arg of positionals(args, new Set(['-p', '-d', '-n', '-t', '-u', '-a']))) st.env.set(arg.text, UNKNOWN);
}

function ruleCd(args, _io, st) {
  const target = positionals(args)[0];
  if (!target || target.dynamic || target.text === '-') return;
  st.cwd = resolvePath(target.text, st);
  st.cwdInSecretDir = cwdHoldsSecrets(st.cwd, st.home);
}

const RULES = {
  __proto__: null,
  rm: ruleRm,
  unlink: ruleRm,
  rimraf: ruleRimraf,
  mv: ruleMv,
  cp: ruleCopyFromNull,
  install: ruleCopyFromNull,
  ln: ruleCopyFromNull,
  tee: ruleTee,
  rsync: ruleRsync,
  dd: ruleDd,
  dcfldd: ruleDd,
  dc3dd: ruleDd,
  ddrescue: ruleDdrescue,
  mkfs: always(CATASTROPHIC, 'formats a filesystem'),
  newfs: always(CATASTROPHIC, 'formats a filesystem'),
  wipefs: always(CATASTROPHIC, 'wipes filesystem signatures'),
  blkdiscard: always(CATASTROPHIC, 'discards every block on a device'),
  nwipe: always(CATASTROPHIC, 'wipes a disk'),
  lvremove: always(CATASTROPHIC, 'removes a logical volume'),
  vgremove: always(CATASTROPHIC, 'removes a volume group'),
  pvremove: always(CATASTROPHIC, 'removes a physical volume'),
  fdisk: rulePartition('fdisk'),
  gdisk: rulePartition('gdisk'),
  cgdisk: rulePartition('cgdisk'),
  cfdisk: rulePartition('cfdisk'),
  parted: rulePartition('parted'),
  sgdisk: ruleDiskUnlessReading('sgdisk', new Set(['-p', '--print', '-i', '--info', '-v', '--verify', '-P', '--pretend', '-L', '--list-types', '-V', '--version', '-?', '--help'])),
  sfdisk: ruleDiskUnlessReading('sfdisk', new Set(['-l', '--list', '-d', '--dump', '-s', '--show-size', '-V', '--verify', '-J', '--json', '-g', '--show-geometry', '-n', '--no-act', '-F', '--list-free', '-v', '--version', '-h', '--help'])),
  cryptsetup: ruleDiskVerb('cryptsetup', /^(?:luksFormat|erase|luksErase|reencrypt|luksRemoveKey|luksKillSlot)$/i),
  zpool: ruleDiskVerb('zpool', /^(?:destroy|labelclear)$/i),
  zfs: ruleZfs,
  nvme: ruleDiskVerb('nvme', /^(?:format|sanitize|delete-ns|ns-delete|write-zeroes|write-uncor)$/i),
  gpt: ruleDiskVerb('gpt', /^(?:destroy|remove)$/i),
  dmsetup: ruleDiskVerb('dmsetup', /^(?:remove|remove_all|wipe_table)$/i, DESTRUCTIVE),
  tmutil: ruleDiskVerb('tmutil', /^delete/i, DESTRUCTIVE),
  hdparm: ruleDiskFlag('hdparm', /^--(?:security-erase|trim-sector-ranges|write-sector|make-bad-sector)/),
  badblocks: ruleDiskFlag('badblocks', /^-[a-zA-Z]*w/),
  mdadm: ruleDiskFlag('mdadm', /^(?:--zero-superblock|--create|-C)$/),
  asr: ruleDiskFlag('asr', /^--erase$/),
  diskutil: ruleDiskutil,
  shred: ruleShred,
  wipe: ruleShred,
  scrub: ruleShred,
  sdelete: ruleShred,
  srm: always(DESTRUCTIVE, 'secure delete'),
  truncate: always(DESTRUCTIVE, 'truncates a file'),
  chmod: rulePermissions('chmod'),
  chown: rulePermissions('chown'),
  crontab: ruleCrontab,
  kill: ruleKill,
  pkill: ruleKill,
  killall: ruleKill,
  shutdown: always(DESTRUCTIVE, 'shuts the machine down'),
  reboot: always(DESTRUCTIVE, 'shuts the machine down'),
  halt: always(DESTRUCTIVE, 'shuts the machine down'),
  poweroff: always(DESTRUCTIVE, 'shuts the machine down'),
  systemctl: ruleSystemctl,
  git: ruleGit,
  psql: ruleSql,
  mysql: ruleSql,
  sqlite3: ruleSql,
  mongosh: ruleSql,
  cockroach: ruleSql,
  'clickhouse-client': ruleSql,
  'redis-cli': ruleRedis,
  dropdb: always(DESTRUCTIVE, 'dropdb'),
  sendmail: always(OUTWARD, 'sendmail'),
  security: ruleSecurity,
  curl: ruleCurl,
  wget: ruleLoopbackClient,
  nc: ruleLoopbackClient,
  socat: ruleLoopbackClient,
  telnet: ruleLoopbackClient,
  http: ruleLoopbackClient,
  xh: ruleLoopbackClient,
  sayso: ruleSayso,
  sh: ruleShell,
  bash: ruleShell,
  zsh: ruleShell,
  dash: ruleShell,
  ksh: ruleShell,
  fish: ruleShell,
  eval: ruleEval,
  source: ruleSource,
  '.': ruleSource,
  at: ruleAt,
  batch: ruleAt,
  ssh: ruleSsh,
  autossh: ruleSsh,
  scp: ruleScp,
  sftp: ruleScp,
  su: ruleSu,
  trap: ruleTrap,
  watch: ruleWatch,
  find: ruleFind,
  xargs: ruleXargs,
  parallel: ruleParallel,
  awk: ruleAwk,
  sed: ruleSed,
  export: ruleExportLike,
  declare: ruleExportLike,
  typeset: ruleExportLike,
  local: ruleExportLike,
  readonly: ruleExportLike,
  read: ruleRead,
  cd: ruleCd,
  pushd: ruleCd,
};

for (const name of ['tmux', 'screen', 'dtach', 'abduco', 'script', 'systemd-run', 'nsenter', 'unshare', 'firejail', 'bwrap', 'sandbox-exec', 'strace', 'ltrace', 'dtruss', 'gdb', 'valgrind', 'perf', 'entr', 'direnv', 'mise', 'asdf', 'rbenv', 'pyenv', 'nodenv', 'conda', 'dotenv', 'op', 'doppler', 'aws-vault', 'launchctl', 'pkexec', 'runuser', 'setpriv', 'taskset', 'numactl', 'prlimit', 'cpulimit', 'proxychains', 'proxychains4', 'torsocks', 'nix-shell', 'devbox']) {
  RULES[name] = ruleArgvRunner;
}

for (const [name, spec] of Object.entries(INLINE_CODE)) {
  const interpret = interpreterRule(spec);
  const existing = VERB_RULES[name] ? verbRule(name, VERB_RULES[name]) : null;
  RULES[name] = existing
    ? (args, io, st, key) => {
        existing(args, io, st, key);
        interpret(args, io, st, key);
      }
    : interpret;
}

for (const [name, table] of Object.entries(VERB_RULES)) {
  if (!RULES[name]) RULES[name] = verbRule(name, table);
}

for (const name of Object.keys(RUNNER_VERBS)) {
  if (!RULES[name]) RULES[name] = verbRule(name, {});
}

for (const [name, check] of Object.entries(EXTRA_VERB_CHECKS)) {
  const base = RULES[name];
  RULES[name] = (args, io, st, key) => {
    base?.(args, io, st, key);
    if (!isDryRun(args)) check(args, st, positionals(args, VERB_VALUE_FLAGS));
  };
}

// Public API.

/** @param {string} command @param {Ctx} ctx @returns {Verdict|null} */
export function classifyShell(command, ctx) {
  if (typeof command !== 'string') return opaqueVerdict('command is not text');
  if (command.length > MAX_COMMAND_LENGTH) return opaqueVerdict('command is too long to read');
  try {
    const st = newState(ctx);
    walkTokens(lex(command), st);
    return buildVerdict(st);
  } catch (error) {
    // Stack overflow from absurd nesting lands here too: the guard fails closed.
    return opaqueVerdict(error instanceof ParseFailure ? 'shell syntax could not be parsed' : 'classifier could not read the command');
  }
}

function classifyFileWrite(input, ctx) {
  const file = input.file_path ?? input.notebook_path;
  if (typeof file !== 'string') return null;
  const st = newState(ctx);
  const path = resolvePath(file, st);
  if (namesStateDir(path, st)) flag(st, SELF, 'write under the guard state directory');
  if (isSettingsPath(path, st)) flag(st, SELF, 'write to agent settings');
  if (isSecretPath(path, st)) flag(st, CREDENTIALS, 'write to a secret file');
  if (isPersistencePath(path, st)) flag(st, DESTRUCTIVE, 'write to a shell startup or system path');
  return fileVerdict(st);
}

function classifyFileRead(input, ctx) {
  if (typeof input.file_path !== 'string') return null;
  const st = newState(ctx);
  const path = resolvePath(input.file_path, st);
  if (namesStateDir(path, st)) flag(st, SELF, 'read under the guard state directory');
  if (isSecretPath(path, st)) flag(st, CREDENTIALS, 'reads a secret file');
  return fileVerdict(st);
}

/** Grep and Glob read under a directory, so a search rooted in the state directory reads it too. */
function classifySearch(input, ctx) {
  if (typeof input.path !== 'string') return null;
  const st = newState(ctx);
  if (namesStateDir(resolvePath(input.path, st), st)) flag(st, SELF, 'read under the guard state directory');
  return fileVerdict(st);
}

function fileVerdict(st) {
  if (st.flags.length === 0) return null;
  const { risk, why } = buildVerdict(st);
  return { risk, why };
}

const classifyCommandInput = (input, ctx) => classifyShell(input.command, ctx);

const TOOL_RULES = {
  __proto__: null,
  Bash: classifyCommandInput,
  Monitor: classifyCommandInput,
  Write: classifyFileWrite,
  Edit: classifyFileWrite,
  MultiEdit: classifyFileWrite,
  NotebookEdit: classifyFileWrite,
  Read: classifyFileRead,
  Grep: classifySearch,
  Glob: classifySearch,
};

// `send`, `drop` and `pay` only count as whole name segments: `dropdown`, `payload` and `resend_status` are not actions.
const MCP_OUTWARD_TOOL = /delete|destroy|remove|purge|wipe|terminate|revoke|publish|deploy|transfer|(?:^|[_-])(?:drop|send|pay)(?:[_-]|$)/;

function classifyMcpTool(toolName) {
  const separator = toolName.indexOf('__', 'mcp__'.length);
  if (separator < 0) return null;
  const server = toolName.slice('mcp__'.length, separator);
  if (server === 'sayso') return null;
  const tool = toolName.slice(separator + 2).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
  return MCP_OUTWARD_TOOL.test(tool) ? { risk: OUTWARD, why: ['mcp tool name looks like an action with outside effects'] } : null;
}

/** @param {string} toolName @param {object} toolInput @param {Ctx} ctx @returns {Verdict|null} */
export function classifyToolCall(toolName, toolInput, ctx) {
  if (typeof toolName !== 'string') return null;
  if (toolName.startsWith('mcp__')) return classifyMcpTool(toolName);
  const rule = TOOL_RULES[toolName];
  return rule ? rule(toolInput ?? {}, ctx) : null;
}
