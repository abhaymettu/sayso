/** @typedef {"catastrophic"|"self"|"credentials"|"destructive"|"outward"|"opaque"} Risk */
/** @typedef {{risk: Risk, why: string[], commands?: string[]}} Verdict */
/** @typedef {{home: string, cwd: string, stateDir: string}} Ctx */

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
  return undefined;
}

function expandTilde(text, st) {
  if (text === '~') return st.home;
  if (text.startsWith('~/')) return st.home + text.slice(1);
  if (text === '~+' || text.startsWith('~+/')) return st.cwd + text.slice(2);
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
const BLOCK_DEVICE = /^\/dev\/(r?disk|sd|hd|vd|xvd|nvme|mmcblk|loop)/i;
const HARMLESS_DEVICE = /^\/dev\/(null|zero|stdout|stderr|stdin|tty|fd\/|random|urandom)/i;
const SETTINGS_PATH = /\/(?:\.claude\/settings(?:\.local)?\.json|managed-settings\.json|\.claude\.json)$/i;
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

function namesStateDir(path, st) {
  return isUnder(path, st.stateDir) || (st.stateBase[0] === '.' && path.split('/').includes(st.stateBase));
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
  if (!text.includes(st.stateBase)) return false;
  if (/\s/.test(text)) return namesStateDir(resolvePath(text, st), st);
  return pathCandidates(text).some((candidate) => namesStateDir(resolvePath(candidate, st), st));
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
  return {
    home,
    cwd,
    stateDir,
    stateBase: stateDir.slice(stateDir.lastIndexOf('/') + 1),
    cwdInSecretDir: cwdHoldsSecrets(cwd, home),
    env: new Map(),
    ifsChanged: false,
    flags: [],
    argvs: [],
    depth: 0,
    loopBudget: MAX_LOOP_VALUES,
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
const ASSIGNMENT = /^([A-Za-z_]\w*)(\[[^\]]*\])?\+?=/;

function emptyCommand() {
  return { assigns: [], words: [], redirs: [] };
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
      } else walkWordParts(word, st);
      continue;
    }
    if (cmd.words.length > 0) {
      cmd.words.push(word);
      continue;
    }
    const plain = word.plain;
    if (plain !== null && cmd.assigns.length === 0) {
      if (KEYWORDS.has(plain)) continue;
      if (plain === 'esac' && caseDepth > 0) {
        caseDepth--;
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
    flag(st, OPAQUE, 'nesting too deep to read');
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

  const io = { piped, previous, heredoc: null, herestring: null, stdinUnknown: false };
  for (const redir of cmd.redirs) applyRedirect(redir, io, st);

  for (const assign of cmd.assigns) {
    const arg = resolveAssignment(assign, st);
    if (argv.length === 0) recordAssignment(assign.name, arg, st);
    scanWord(arg, st, false);
  }
  if (argv.length > 0) {
    st.argvs.push(argv);
    dispatch(argv, io, st);
  }
  return argv;
}

const WRITE_REDIRECTS = new Set(['>', '>>', '>|', '&>', '&>>', '<>']);

function applyRedirect(redir, io, st) {
  walkWordParts(redir.target, st);
  if (redir.heredoc) {
    if (redir.heredoc.expand && (redir.heredoc.body.includes('$') || redir.heredoc.body.includes('`'))) {
      walkParts(lex(redir.heredoc.body, true), st);
    }
    io.heredoc = redir.heredoc.body;
    return;
  }
  const target = resolveOne(redir.target, st);
  if (redir.op === '<<<') {
    io.herestring = target.script;
    return;
  }
  if ((redir.op === '>&' || redir.op === '<&') && /^(\d+-?|-)$/.test(target.text)) return;
  if (redir.op === '<' && target.dynamic) io.stdinUnknown = true;
  scanWord(target, st, false);
  if (WRITE_REDIRECTS.has(redir.op)) checkWriteTarget(target.text, st);
}

function checkWriteTarget(text, st) {
  const path = resolvePath(text, st);
  if (BLOCK_DEVICE.test(path)) flag(st, CATASTROPHIC, 'write to a raw disk device');
  if (SETTINGS_PATH.test(path)) flag(st, SELF, 'write to agent settings');
  if (isPersistencePath(path, st)) flag(st, DESTRUCTIVE, 'write to a shell startup or system path');
}

function scanWord(arg, st, skipSecrets) {
  const text = arg.text;
  if (!/\s/.test(text) && text.includes('sayso.sock')) flag(st, SELF, 'names the guard socket');
  else if (wordNamesStateDir(text, st)) flag(st, SELF, 'names the guard state directory');
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
};

function ruleKey(name) {
  const lower = name.toLowerCase();
  if (lower.startsWith('python') && /^python[\d.]*$/.test(lower)) return 'python';
  if (lower.startsWith('mkfs')) return 'mkfs';
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

function dispatch(argv, io, st) {
  const head = argv[0];
  if (!head) return;
  if (head.dynamic) flag(st, OPAQUE, 'command name is not literal');
  const key = ruleKey(baseName(head.text));
  const args = argv.slice(1);
  const wrapper = WRAPPERS[key];
  if (wrapper) {
    const inner = peelWrapper(wrapper, args);
    if (inner) dispatch(inner, io, st);
    return;
  }
  scanCommandWords(key, argv, st);
  const targets = WRITE_TARGETS[key]?.(args);
  if (targets) for (const target of targets) checkWriteTarget(target.text, st);
  RULES[key]?.(args, io, st, key);
}

const READS_NOTHING = new Set(['echo', 'printf', 'ls', 'stat', 'test', '[', 'chmod', 'chown', 'file', 'mkdir', 'touch', 'which', 'type', 'dirname', 'basename', 'realpath', 'readlink', 'ssh-add', 'ssh-keygen', 'ssh-copy-id']);
const USES_KEY_IN_PLACE = new Set(['ssh', 'scp', 'sftp', 'rsync', 'autossh']);
const SEARCH_TOOLS = new Set(['grep', 'rg', 'ag', 'ack']);
const COPIES_TREES = new Set(['tar', 'zip', '7z', 'cp', 'rsync', 'scp', 'ditto']);

function scanCommandWords(key, argv, st) {
  const skipSecrets = READS_NOTHING.has(key);
  const searchPattern = SEARCH_TOOLS.has(key) ? patternIndex(argv) : -1;
  const keyUser = USES_KEY_IN_PLACE.has(key);
  for (let i = 0; i < argv.length; i++) {
    if (i === searchPattern) continue;
    const isKeyValue = keyUser && argv[i - 1]?.text === '-i';
    scanWord(argv[i], st, skipSecrets || isKeyValue);
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

const REBUILDABLE = new Set(['node_modules', 'dist', 'build', '.next', 'target', '__pycache__', '.cache', 'coverage', '.turbo', 'out', '.pytest_cache', '.venv', 'venv', 'tmp', 'scratch', '.scratch', '.playwright-mcp']);
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

/** Children of the OS temp roots go away on their own. Normalizing first means /tmp/../etc is not one of them. */
function isOsScratch(arg, st) {
  return !arg.text.includes('$') && OS_SCRATCH_CHILD.test(deleteRootOf(arg, st));
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

function ruleMv(args, _io, st) {
  const pos = positionals(args);
  if (pos.length < 2) return;
  if (resolvePath(pos[pos.length - 1].text, st) === '/dev/null') flag(st, DESTRUCTIVE, 'move into /dev/null');
  for (const source of pos.slice(0, -1)) {
    if (!source.dynamic && isProtectedRoot(resolvePath(source.text, st), st)) flag(st, DESTRUCTIVE, 'moves a protected root directory');
  }
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

function ruleDiskutil(args, _io, st) {
  const verb = positionals(args)[0]?.text ?? '';
  if (/^(secure)?erase|^zerodisk|^randomdisk|^reformat|^partitiondisk/i.test(verb)) flag(st, CATASTROPHIC, 'diskutil erase');
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
}

function ruleKill(args, _io, st, key) {
  if (args.some((arg) => /sayso/i.test(arg.text))) flag(st, SELF, 'kills the guard');
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
      const alias = /^alias\.([^=]+)=(.*)$/s.exec(args[i + 1]?.text ?? '');
      if (alias) aliases.set(alias[1], alias[2]);
      i++;
    } else if (GIT_GLOBAL_VALUE_FLAGS.has(text)) i++;
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

function ruleSql(args, io, st) {
  const sources = args.map((arg) => arg.text);
  if (io.heredoc) sources.push(io.heredoc);
  if (io.herestring) sources.push(io.herestring);
  if (io.piped && io.previous) sources.push(...io.previous.slice(1).map((arg) => arg.text));
  for (const source of sources) {
    const why = dangerousSql(source);
    if (why) flag(st, DESTRUCTIVE, why);
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
const LOOPBACK = /(?:^|[/@:\s=])(?:127\.0\.0\.1|localhost|\[::1\]|::1|0\.0\.0\.0)(?:$|[:/\s])/i;
const GUARD_PORT = /(?:^|\D)7428(?:$|\D)/;

function ruleLoopbackClient(args, _io, st) {
  const words = args.map((arg) => arg.text);
  if (words.some((word) => LOOPBACK.test(word)) && words.some((word) => GUARD_PORT.test(word))) {
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
      return;
    }
    if (text.includes('s')) readsStdin = true;
    if (text.endsWith('o') || text.endsWith('O')) i++;
  }
  const scriptArg = args[i];
  if (!readsStdin && scriptArg && scriptArg.text !== '-' && scriptArg.text !== '/dev/stdin') {
    if (scriptArg.dynamic) flag(st, OPAQUE, 'runs a script chosen at run time');
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

function ruleSource(args, _io, st) {
  const file = args[0];
  if (file?.proc) flag(st, OPAQUE, 'source of a process substitution');
}

const SSH_VALUE_FLAGS = new Set(['-b', '-c', '-D', '-E', '-e', '-F', '-I', '-i', '-J', '-L', '-l', '-m', '-O', '-o', '-p', '-Q', '-R', '-S', '-W', '-w', '-B']);

function ruleSsh(args, _io, st) {
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

function ruleFind(args, io, st) {
  let root = null;
  const names = flagValues(args, '-name').map((arg) => arg.text);
  const cleansRebuildables = names.length > 0 && names.every((name) => REBUILDABLE.has(name) || FIND_CLEANUP_NAME.test(name));
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
      if (!(cleansRebuildables && ruleKey(baseName(inner[0]?.text ?? '')) === 'rm')) {
        dispatch(inner, { ...io, piped: false, heredoc: null, herestring: null }, st);
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
  dispatch(argv, { ...io, piped: false }, st);
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
  [/(?<![.\w])system\(|\.system\(|subprocess|child_process|(?<![.\w])exec\(|os\.exec|execSync|\bspawn|\bpopen|shell_exec|passthru|do shell script/i, 'inline code runs a process'],
  [/(?<![.\w])eval\(|b64decode/, 'inline code evaluates generated code'],
];
// A heredoc script reaches as far as `python3 script.py`, which passes unread, so process use alone is not a signal there.
const SCRIPT_PATTERNS = [
  [/rmtree|rm_rf|rmSync|fs\.rm\b|FileUtils\.rm/, 'inline script deletes a tree'],
  [/b64decode[\s\S]*(?:exec|eval)\(|(?:exec|eval)\([\s\S]*b64decode/, 'inline script runs decoded code'],
];
const PROCESS_EXEC = /system\(|subprocess|child_process|exec|spawn|popen|shell_exec|passthru|do shell script/i;
const STRING_LITERAL = /(["'`])((?:\\.|(?!\1)[^\\])*)\1/g;
const STRING_LIST = /\[\s*((?:["'][^"']*["']\s*,?\s*)+)\]/g;

function checkInlineCode(code, sole, st, patterns = CODE_PATTERNS) {
  if (sole) {
    flag(st, OPAQUE, 'inline code is not literal');
    return;
  }
  for (const [pattern, why] of patterns) {
    if (pattern.test(code)) flag(st, OPAQUE, why);
  }
  if (SECRET_IN_CODE.test(code)) flag(st, CREDENTIALS, 'inline code names a secret file');
  if (code.includes('sayso.sock') || code.includes(st.stateDir)) flag(st, SELF, 'inline code names the guard state');
  if (PROCESS_EXEC.test(code)) checkEmbeddedShell(code, st);
}

/** A literal shell string inside code is read with the shell rules, so os.system('rm -rf /') scores as rm -rf /. */
function checkEmbeddedShell(code, st) {
  const candidates = [];
  for (const match of code.matchAll(STRING_LITERAL)) candidates.push(match[2]);
  for (const match of code.matchAll(STRING_LIST)) {
    candidates.push([...match[1].matchAll(/["']([^"']*)["']/g)].map((piece) => piece[1]).join(' '));
  }
  for (const candidate of candidates) {
    if (!candidate.includes(' ') || candidate.length > 2000) continue;
    const inner = { ...st, env: new Map(st.env), flags: [], argvs: [] };
    try {
      walkNested(lex(candidate), inner);
    } catch {
      continue;
    }
    for (const entry of inner.flags) {
      if (entry.risk !== OPAQUE) st.flags.push(entry);
    }
  }
}

const INLINE_CODE = {
  __proto__: null,
  python: { code: /^-[A-Za-z]*c$/, values: new Set(['-W', '-X']) },
  node: { code: /^(?:-e|--eval|-p|--print|-pe)$/, values: new Set(['-r', '--require', '--import', '--loader', '--experimental-loader']) },
  perl: { code: /^-[A-Za-z0-9.]*[eE]$/, values: new Set(['-I', '-M']) },
  ruby: { code: /^-[A-Za-z]*e$/, values: new Set(['-I', '-r']) },
  php: { code: /^-r$/, values: new Set(['-c', '-d']) },
  osascript: { code: /^-e$/, values: new Set(['-l']) },
  bun: { code: /^(?:-e|--eval|-p|--print)$/, values: new Set() },
  deno: { code: /^(?:-e|--eval)$/, values: new Set(), evalVerb: true },
  lua: { code: /^-e$/, values: new Set() },
  rscript: { code: /^-e$/, values: new Set() },
};

function interpreterRule(spec) {
  return (args, io, st) => {
    let hasProgram = false;
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      const text = arg.text;
      if (text === '-') break;
      if (spec.evalVerb && text === 'eval' && !hasProgram) {
        const code = args[i + 1];
        if (code) checkInlineCode(code.text, code.sole, st);
        return;
      }
      if (spec.code.test(text)) {
        const code = args[++i];
        if (code) checkInlineCode(code.text, code.sole, st);
        hasProgram = true;
        continue;
      }
      if (text.startsWith('--eval=')) {
        checkInlineCode(text.slice('--eval='.length), false, st);
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
      if (text[0] === '-' && text.length > 1) continue;
      hasProgram = true;
      if (baseName(text) === 'manage.py') RULES['manage.py'](args.slice(i + 1), io, st, 'manage.py');
      break;
    }
    if (hasProgram) return;
    if (io.heredoc !== null) checkInlineCode(io.heredoc, false, st, SCRIPT_PATTERNS);
    else if (io.herestring !== null) checkInlineCode(io.herestring, false, st);
    else if (io.piped || io.stdinUnknown) flag(st, OPAQUE, 'pipeline into an interpreter');
  };
}

function ruleAwk(args, _io, st) {
  const program = positionals(args, new Set(['-F', '-v', '-f']))[0];
  if (hasShortFlag(args, 'f') || !program) return;
  if (/\bsystem\s*\(|\|\s*["']?(?:sh|bash)\b|["']\s*\|\s*getline/.test(program.text)) flag(st, OPAQUE, 'inline code runs a process');
}

function ruleExportLike(args, _io, st) {
  for (const arg of args) {
    const match = ASSIGNMENT.exec(arg.text);
    if (match) recordAssignment(match[1], arg.dynamic ? { dynamic: true } : literalArg(arg.text.slice(match[0].length), st), st);
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
  dd: ruleDd,
  mkfs: always(CATASTROPHIC, 'formats a filesystem'),
  wipefs: always(CATASTROPHIC, 'wipes filesystem signatures'),
  fdisk: rulePartition('fdisk'),
  parted: rulePartition('parted'),
  diskutil: ruleDiskutil,
  shred: ruleShred,
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
  ssh: ruleSsh,
  su: ruleSu,
  trap: ruleTrap,
  watch: ruleWatch,
  find: ruleFind,
  xargs: ruleXargs,
  parallel: ruleParallel,
  awk: ruleAwk,
  export: ruleExportLike,
  declare: ruleExportLike,
  typeset: ruleExportLike,
  local: ruleExportLike,
  readonly: ruleExportLike,
  read: ruleRead,
  cd: ruleCd,
  pushd: ruleCd,
};

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
  if (isUnder(path, st.stateDir)) flag(st, SELF, 'write under the guard state directory');
  if (SETTINGS_PATH.test(path)) flag(st, SELF, 'write to agent settings');
  if (isSecretPath(path, st)) flag(st, CREDENTIALS, 'write to a secret file');
  if (isPersistencePath(path, st)) flag(st, DESTRUCTIVE, 'write to a shell startup or system path');
  return fileVerdict(st);
}

function classifyFileRead(input, ctx) {
  if (typeof input.file_path !== 'string') return null;
  const st = newState(ctx);
  const path = resolvePath(input.file_path, st);
  if (isUnder(path, st.stateDir)) flag(st, SELF, 'read under the guard state directory');
  if (isSecretPath(path, st)) flag(st, CREDENTIALS, 'reads a secret file');
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
