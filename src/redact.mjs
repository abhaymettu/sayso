// Everything a session produces passes through here before it reaches an agent, a webhook, the page or the audit log.
// Two jobs: secrets never leave, and what a person reads is what would actually run.

// Nothing past this is read, so every pattern below has a ceiling on its cost whatever a session sends.
const MAX_SCANNED = 16000;
// Past this a word stays as written. Padding must not be able to turn the command after it into a redaction marker.
const MAX_ENCODED_WORDS = 64;

// A pattern cannot tell live quotes from quoted quotes: in `echo 'TOKEN="'; rm -rf ~; echo '"'` the `"..."` holds a
// command. So no value swallows anything a shell could act on, quoted or not, and a secret holding one of these stays
// visible. Hiding a command from the person signing is the worse of the two.
const QUOTED_VALUE = String.raw`"(?:[^"\`;&|<>\n$\\]|\\.|\$(?!\())*"|'(?:[^'\`;&|<>\n$]|\$(?!\())*'`;
const PLAIN_CHAR = String.raw`(?:[^\s"'\`;&|<>()$\\]|\\\S|\$(?!\())`;
const COOKIE_CHAR = String.raw`[^\s"'\`;&|<>()$\\]`;
const VALUE = `${QUOTED_VALUE}|${PLAIN_CHAR}+`;
const LONG_VALUE = `${QUOTED_VALUE}|${PLAIN_CHAR}{6,}`;

const SECRET_NAME = /api[_-]?key|secret|token|passw(?:or)?d|passphrase|credential|creds?\b|private[_-]?key|access[_-]?key|account[_-]?key|auth(?!or(?:s|ity)?\b)|(?<![A-Za-z])pass(?![A-Za-z])|[_-]pwd(?![A-Za-z])|dbpwd|[_-]key$|[_-]pw$|^pw$|[_-]tok$/i;
// Prose after the word `password` is common in a command's comment or message, and hiding it would hide what runs.
const NOT_A_PASSWORD = String.raw`(?!(?:is|was|for|to|the|of|and|or|in|on|not|must|reset|change|prompt|file|field|manager|hash|policy|login|required|expired|wrong|authentication)\b)`;
const PEM_GAP = String.raw`(?:\s|\\n|\\r)+`;
const PEM_HEADER = String.raw`[A-Za-z-]+:[ \t][^\n;&|\`$]*`;
const BASE64 = "[A-Za-z0-9+/=]";

const NAME_AND_GAP = /(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+)\\?["']?\s*[=:]\s*/g;
const VALUE_HERE = new RegExp(String.raw`\\"(?:[^"\\\`;&|<>\n$]|\$(?!\())*\\"|${VALUE}`, "y");

/** Only a secret's name takes its value, so the pair inside `https://x/?password=y` or `http.extraHeader='TOKEN: y'` is still read. */
function hideNamedValues(text) {
  let out = "";
  let copied = 0;
  NAME_AND_GAP.lastIndex = 0;
  for (let found = NAME_AND_GAP.exec(text); found; found = NAME_AND_GAP.exec(text)) {
    if (!SECRET_NAME.test(found[1])) continue;
    VALUE_HERE.lastIndex = NAME_AND_GAP.lastIndex;
    if (!VALUE_HERE.test(text)) continue;
    out += `${text.slice(copied, NAME_AND_GAP.lastIndex)}[redacted]`;
    copied = NAME_AND_GAP.lastIndex = VALUE_HERE.lastIndex;
  }
  return out + text.slice(copied);
}

/** A program that takes a secret after one of its own flags. The flag's distance is bounded so `mysql mysql mysql ...` stays linear. */
const programFlag = (programs, flag, flags = "g") => [new RegExp(String.raw`((?:^|[\s/])(?:${programs})\b[^\n;&|]{0,512}?\s${flag})(${VALUE})`, flags), "$1[redacted]"];

const SECRET_PATTERNS = [
  // Whole base64 lines only, so a command on the next line of a block with no END stays visible.
  [new RegExp(String.raw`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----(?:(?:${PEM_GAP}(?:${PEM_HEADER}|${BASE64}+))*(?:${PEM_GAP})?-----END [A-Z0-9 ]*-----|(?:${PEM_GAP}(?:${PEM_HEADER}|${BASE64}{20,}))*)`, "g"), "[redacted private key]"],
  [new RegExp(String.raw`PuTTY-User-Key-File-\d[^\n]*(?:\n${PEM_HEADER}|\n${BASE64}{16,}|\n${BASE64}+(?=\n[A-Za-z-]+:[ \t]))*`, "g"), "[redacted private key]"],
  [/\b(?:sk|pk|rk)-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_-]{16,}/g, "[redacted key]"],
  [/\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}/g, "[redacted key]"],
  [/\bsayso_agent_[A-Za-z0-9_-]+/g, "[redacted token]"],
  [/\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}/g, "[redacted token]"],
  [/\bxox[abeprs]-[A-Za-z0-9-]{10,}/g, "[redacted token]"],
  [/\bxapp-[A-Za-z0-9-]{10,}/g, "[redacted token]"],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[redacted key]"],
  [/\bAIza[A-Za-z0-9_-]{30,}/g, "[redacted key]"],
  [/\bnpm_[A-Za-z0-9]{30,}/g, "[redacted token]"],
  [/\bgl(?:pat|dt|rt|ptt|cbt|soat|ffct|imt)-[A-Za-z0-9_-]{16,}/g, "[redacted token]"],
  [/\b(?:hf|gsk|shpat|shpss|lin_api|figd|ntn|rnd|vcp|sbp|dckr_pat|dckr_oat|sntrys|sntryu|glsa|glc|fo1|tskey)_[A-Za-z0-9_-]{16,}/g, "[redacted token]"],
  [/\bsecret_[A-Za-z0-9]{32,}/g, "[redacted token]"],
  [/\bhv[sbr]\.[A-Za-z0-9_-]{16,}/g, "[redacted token]"],
  [/\b(?:xai|pplx|tvly|pypi|tskey)-[A-Za-z0-9_-]{16,}/g, "[redacted key]"],
  [/\bSG\.[A-Za-z0-9_-]{16,}(?:\.[A-Za-z0-9_-]{16,})?/g, "[redacted key]"],
  [/\bya29\.[A-Za-z0-9_-]{16,}/g, "[redacted token]"],
  [/\bre_[A-Za-z0-9_]{16,}/g, "[redacted key]"],
  [/\bdo[por]_v1_[A-Za-z0-9]{16,}/g, "[redacted token]"],
  [/\bwhsec_[A-Za-z0-9+/=]{16,}/g, "[redacted key]"],
  [/\bAGE-SECRET-KEY-[A-Z0-9]{16,}/g, "[redacted key]"],
  [/\bSK[0-9a-fA-F]{32}\b/g, "[redacted key]"],
  [/\b(?:PMAK|NRAK)-[A-Za-z0-9_-]{16,}/g, "[redacted key]"],
  [/\b\d{8,10}:[A-Za-z0-9_-]{30,46}\b/g, "[redacted token]"],
  [/\b[MNO][A-Za-z0-9_-]{17,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/g, "[redacted token]"],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+/g, "[redacted jwt]"],
  [/\bhooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/g, "hooks.slack.com/services/[redacted]"],
  [/\b(discord(?:app)?\.com\/api\/webhooks\/)[A-Za-z0-9/_-]+/g, "$1[redacted]"],
  [/\b(Bearer|Basic|Token)\s+[A-Za-z0-9+/._~=-]{8,}/gi, "$1 [redacted]"],
  [/\b([a-z][a-z0-9+.-]{0,30}:\/\/)[^\s:/@]{20,256}(?=[:@])/gi, "$1[redacted]"],
  [/\b([a-z][a-z0-9+.-]{0,30}:\/\/[^\s:/@]{0,256}):(?!\d+\/)[^\s@"'`;&|<>()$\\]{1,512}@/gi, "$1:[redacted]@"],
  [/([?&](?:sig|signature|x-amz-signature|x-goog-signature)=)[^\s&"'`;|<>()$]+/gi, "$1[redacted]"],
  [new RegExp(String.raw`((?:^|\s)(?:-u|--user)(?:\s+|=)?["']?[^\s:"']+:)(?!\d+(?:\s|$))(${VALUE})`, "g"), "$1[redacted]"],
  [new RegExp(String.raw`((?:^|[\s"'])(?:set-)?cookie:\s*)${COOKIE_CHAR}+(?:;\s*[\w.-]+=${COOKIE_CHAR}*(?=[;"'\n]|\s*$))*`, "gi"), "$1[redacted]"],
  [new RegExp(String.raw`\b(pass:)${PLAIN_CHAR}+`, "g"), "$1[redacted]"],
  [hideNamedValues],
  [new RegExp(String.raw`((?:^|\s)--?(?:password|passwd|passphrase|token|secret|api-key|apikey|auth|key)(?:\s+|=))(?!-)(${LONG_VALUE})`, "gi"), "$1[redacted]"],
  [new RegExp(String.raw`((?:^|\s)--[\w-]*(?:password|passwd|passphrase|token|secret|api-key|apikey|access-key|private-key)[\w-]*(?<!-file|-stdin|-env|-path)\s+)(?!-)(${LONG_VALUE})`, "gi"), "$1[redacted]"],
  // `-p` also means parents, port and a dozen other things, so its value must not look like a path or a port map.
  [new RegExp(String.raw`((?:^|\s)-p(?:\s+|=))(?!-)(?![^\s"']*\/)(?!\d+(?::\d+)*(?:\s|$))(${LONG_VALUE})`, "g"), "$1[redacted]"],
  programFlag(String.raw`mysql\w*|mariadb[\w-]*|mycli|sshpass|7z[az]?|rar|unrar`, "-p(?=\\S)", "gi"),
  programFlag("zip|unzip", "-P\\s*"),
  programFlag("redis-cli", "-a\\s+"),
  programFlag("sqlcmd|bcp", "-P\\s*"),
  programFlag("ldap(?:search|add|modify|delete|whoami)", "-w\\s*"),
  programFlag("openssl", "-k\\s+"),
  programFlag("ssh-keygen", "-[PN]\\s*"),
  programFlag("smbclient", "-U\\s*[^\\s%]+%"),
  programFlag("htpasswd", "-\\w*b\\w*\\s+\\S+\\s+\\S+\\s+"),
  programFlag("curl|xh|wget|http", "(?:-b|--cookie)[\\s=]*"),
  [new RegExp(String.raw`\b((?:echo|printf)\s+(?:-n\s+)?)(${VALUE})(?=\s*\|[^|\n]{0,256}--password-stdin)`, "g"), "$1[redacted]"],
  [new RegExp(String.raw`(--password-stdin[^\n;&|]{0,256}?<<<\s*)(${VALUE})`, "g"), "$1[redacted]"],
  // Glued to an unknown program: only when the value mixes letters and digits, so -pthread and -print0 stay readable.
  [/((?:^|\s)-p)(?!rint0)(?=[A-Za-z0-9!@#%^*_+~.-]*\d)(?=[0-9!@#%^*_+~.-]*[A-Za-z])([A-Za-z0-9!@#%^*_+~.-]{6,})(?=\s|$)/g, "$1[redacted]"],
  [new RegExp(String.raw`(\b(?:password|passphrase)\s+)${NOT_A_PASSWORD}(?![=:-])(${VALUE})`, "gi"), "$1[redacted]"],
  [new RegExp(String.raw`(\b[A-Za-z0-9]+_(?:secret|api_?key|access_?key|token|password)[A-Za-z0-9_]*\s+)(?![=:-])(${LONG_VALUE})`, "gi"), "$1[redacted]"],
  [/\b[A-Fa-f0-9]{48,}\b/g, "[redacted hex]"],
  // A long path has this shape too. Base64 has about one slash in 64 characters, so a slash every 15 or fewer is a path.
  [/\b[A-Za-z0-9+/_-]{60,}={0,2}/g, (blob) => ((blob.match(/\//g)?.length ?? 0) * 15 >= blob.length ? blob : "[redacted blob]")],
];

function applyPatterns(text) {
  let out = text;
  for (const [pattern, replacement] of SECRET_PATTERNS) out = replacement ? out.replace(pattern, replacement) : pattern(out);
  return out;
}

const SHELL_WORD = /[^\s;&|<>()`]+/g;
const HIDDEN_MARK = /[\u00ad\u034f\u200b-\u200d\u2060-\u2064\ufeff]/;
const HIDDEN_MARKS = new RegExp(HIDDEN_MARK.source, "g");
const PERCENT = /%([0-9A-Fa-f]{2})/g;
const ESCAPED_BYTE = /\\(?:u00|x)([0-9A-Fa-f]{2})/g;
const fromHex = (_, code) => String.fromCharCode(Number.parseInt(code, 16));
const OPENLY_QUOTED = /^(?:[\w.-]*=)?(?:"[^"']*"|'[^"']*')$/;

/** The word a program would receive once percent escapes, invisible characters and shell quote splits are gone. */
function plainForm(word) {
  let plain = word.replace(HIDDEN_MARKS, "").replace(ESCAPED_BYTE, fromHex);
  for (let round = 0; round < 3 && plain.includes("%"); round++) {
    const decoded = plain.replace(PERCENT, fromHex);
    if (decoded === plain) break;
    plain = decoded;
  }
  return plain.includes('"') || plain.includes("'") ? plain.replace(/["']/g, "") : plain;
}

/** `sk%2Dant%2D...`, `password%3Dx`, `K="sk-ant-"'api03-...'`: the patterns read the plain form, and the whole word goes if it holds a secret. */
function hideEncodedSecrets(text) {
  let checked = 0;
  return text.replace(SHELL_WORD, (word) => {
    const quoted = (word.includes('"') || word.includes("'")) && !word.includes("$") && !OPENLY_QUOTED.test(word);
    if (!quoted && !word.includes("%") && !word.includes("\\") && !HIDDEN_MARK.test(word)) return word;
    const plain = plainForm(word);
    if (plain === word || ++checked > MAX_ENCODED_WORDS) return word;
    return applyPatterns(plain) === plain ? word : "[redacted encoded]";
  });
}

function clamped(input) {
  if (input.length <= MAX_SCANNED) return input;
  const keep = MAX_SCANNED / 2;
  return `${input.slice(0, keep)}\n⟦${input.length - MAX_SCANNED} characters not read⟧\n${input.slice(-keep)}`;
}

const scrub = (text) => hideEncodedSecrets(applyPatterns(text));

export function redact(text) {
  return scrub(clamped(String(text ?? "")));
}

const hex = (cp) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;

const inRanges = (cp, ranges) => ranges.some(([low, high]) => cp >= low && cp <= high);

// Format, combining and private-use characters, whichever a list would miss. Each can make two paths look like one.
const NO_GLYPH_OF_ITS_OWN = /[\p{Cf}\p{Mn}\p{Me}\p{Co}\uFFFC\u{1D159}]/u;
const INVISIBLE = [[0x00ad, 0x00ad], [0x034f, 0x034f], [0x200b, 0x200d], [0x2060, 0x2060], [0x2061, 0x2064], [0xfe00, 0xfe0f], [0xfeff, 0xfeff], [0xfff9, 0xfffb], [0x1d173, 0x1d17a], [0xe0100, 0xe01ef]];
// Characters that print as nothing but are not a shell's word separator, so `rm\u00a0-rf` shown plainly would read as `rm -rf`.
const BLANKS = "\\u00a0\\u1680\\u180e\\u2000-\\u200a\\u202f\\u205f\\u2800\\u3000\\u3164\\uffa0\\u115f\\u1160\\u17b4\\u17b5";
const BLANK_CHAR = new RegExp(`[${BLANKS}]`);
const BLANK_RUN = new RegExp(`[ \\t${BLANKS}]{16,}`, "g");
// Letters that can pass for Latin ones. A warning, not a verdict: the real code points are shown either way.
const LOOK_ALIKE = [[0x017f, 0x017f], [0x0370, 0x058f], [0x13a0, 0x13ff], [0x1d00, 0x1dbf], [0x1f00, 0x1fff], [0x2044, 0x2044], [0x2100, 0x218f], [0x2215, 0x2215], [0x2c80, 0x2cff], [0xa4d0, 0xa4ff], [0xa720, 0xa7ff], [0xff00, 0xffef], [0x1d400, 0x1d7ff]];

const NO_COMMAND_LINE = /^[ \t]*(?:#.*|:|true|\\)?[ \t]*$/;
const MAX_FILLER_RUN = 8;
const MANY_LINES = 30;

/** Padding pushes the real target off the screen, and a person has to be told to read to the end. */
function fillerWarning(text, warnings) {
  const lines = text.split("\n");
  let run = 0;
  for (const line of lines) {
    run = NO_COMMAND_LINE.test(line) ? run + 1 : 0;
    if (run >= MAX_FILLER_RUN) {
      warnings.add("long run of lines with no command in them");
      return;
    }
  }
  if (lines.length > MANY_LINES) warnings.add("many lines to read");
}

// Text an attacker chose must not be able to look like something else: hidden characters become visible marks and
// each kind raises a warning the reader sees before deciding.
export function faithful(text) {
  const warnings = new Set();
  let out = "";
  const collapsed = String(text ?? "").replace(BLANK_RUN, (run) => {
    warnings.add("long run of spaces");
    return run.trim() === "" && /^ +$/.test(run) ? `⟦${run.length} spaces⟧` : `⟦${run.length} blank characters⟧`;
  });
  for (const ch of collapsed) {
    const cp = ch.codePointAt(0);
    if (ch === "\n") out += "\n";
    else if (ch === "\t") out += "\t";
    else if (cp < 0x20 || (cp >= 0x7f && cp < 0xa0) || cp === 0x2028 || cp === 0x2029) {
      warnings.add("control characters");
      out += `⟦${hex(cp)}⟧`;
    } else if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0x200e || cp === 0x200f || cp === 0x061c) {
      warnings.add("text direction overrides");
      out += `⟦${hex(cp)}⟧`;
    } else if (inRanges(cp, INVISIBLE)) {
      warnings.add("invisible characters");
      out += `⟦${hex(cp)}⟧`;
    } else if (cp >= 0xe0000 && cp <= 0xe007f) {
      warnings.add("hidden tag characters");
      out += `⟦tag ${String.fromCodePoint(cp - 0xe0000)}⟧`;
    } else if (BLANK_CHAR.test(ch)) {
      warnings.add("unusual blank characters");
      out += `⟦${hex(cp)}⟧`;
    } else if (NO_GLYPH_OF_ITS_OWN.test(ch)) {
      warnings.add("invisible characters");
      out += `⟦${hex(cp)}⟧`;
    } else {
      if (inRanges(cp, LOOK_ALIKE)) warnings.add("look-alike letters");
      out += ch;
    }
  }
  out = out.replace(/(?:[ \t]*\n){4,}/g, (run) => {
    warnings.add("long run of blank lines");
    return `\n⟦${run.split("\n").length - 1} blank lines⟧\n`;
  });
  fillerWarning(out, warnings);
  return { text: out, warnings: [...warnings] };
}

/** `redacted` says a pattern changed the text, which can hide part of a command as well as a secret. The caller decides what to do with that. */
export function forDisplay(text, limit = 2000) {
  const input = String(text ?? "");
  const scanned = clamped(input);
  const clean = scrub(scanned);
  const redacted = clean !== scanned;
  const { text: shown, warnings } = faithful(clean);
  const unread = input.length - Math.min(input.length, MAX_SCANNED);
  if (shown.length <= limit && unread === 0) return { text: shown, warnings, truncated: false, redacted };
  const longWarnings = [...warnings, "too long to show in full"];
  if (shown.length <= limit) return { text: shown, warnings: longWarnings, truncated: true, redacted };
  const keep = Math.floor(limit / 2);
  const hidden = shown.length - keep * 2 + unread;
  return {
    text: `${shown.slice(0, keep)}\n⟦${hidden} characters not shown⟧\n${shown.slice(-keep)}`,
    warnings: longWarnings,
    truncated: true,
    redacted,
  };
}
