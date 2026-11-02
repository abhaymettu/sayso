// Everything a session produces passes through here before it reaches an agent, a webhook, the page or the audit log.
// Two jobs: secrets never leave, and what a person reads is what would actually run.

const SECRET_KEY_NAME = String.raw`api[_-]?key|secret|token|passw(?:or)?d|passphrase|credential|creds?\b|private[_-]?key|access[_-]?key|auth(?!or(?:s|ity)?\b)|(?<![A-Za-z])pass(?![A-Za-z])|[_-]pwd(?![A-Za-z])|dbpwd`;
// Prose after the word `password` is common in a command's comment or message, and hiding it would hide what runs.
const NOT_A_PASSWORD = String.raw`(?!(?:is|was|for|to|the|of|and|or|in|on|not|must|reset|change|prompt|file|field|manager|hash|policy|login|required|expired|wrong|authentication)\b)`;

const SECRET_PATTERNS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[redacted private key]"],
  [/\b(?:sk|pk|rk)-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_-]{16,}/g, "[redacted key]"],
  [/\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}/g, "[redacted key]"],
  [/\bsayso_agent_[A-Za-z0-9_-]+/g, "[redacted token]"],
  [/\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}/g, "[redacted token]"],
  [/\bxox[abeprs]-[A-Za-z0-9-]{10,}/g, "[redacted token]"],
  [/\bxapp-[A-Za-z0-9-]{10,}/g, "[redacted token]"],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[redacted key]"],
  [/\bAIza[A-Za-z0-9_-]{30,}/g, "[redacted key]"],
  [/\bnpm_[A-Za-z0-9]{30,}/g, "[redacted token]"],
  [/\bglpat-[A-Za-z0-9_-]{16,}/g, "[redacted token]"],
  [/\b(?:hf|gsk|shpat|lin_api|figd|ntn|rnd|vcp)_[A-Za-z0-9_]{16,}/g, "[redacted token]"],
  [/\b(?:xai|pplx|tvly)-[A-Za-z0-9_-]{16,}/g, "[redacted key]"],
  [/\bSG\.[A-Za-z0-9_-]{16,}(?:\.[A-Za-z0-9_-]{16,})?/g, "[redacted key]"],
  [/\bya29\.[A-Za-z0-9_-]{16,}/g, "[redacted token]"],
  [/\bre_[A-Za-z0-9_]{16,}/g, "[redacted key]"],
  [/\bdop_v1_[A-Za-z0-9]{16,}/g, "[redacted token]"],
  [/\bwhsec_[A-Za-z0-9+/=]{16,}/g, "[redacted key]"],
  [/\bAGE-SECRET-KEY-[A-Z0-9]{16,}/g, "[redacted key]"],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+/g, "[redacted jwt]"],
  [/\b(Bearer|Basic|Token)\s+[A-Za-z0-9+/._~=-]{8,}/gi, "$1 [redacted]"],
  [/\b([a-z][a-z0-9+.-]*:\/\/[^\s:/@]+):[^\s@/]+@/gi, "$1:[redacted]@"],
  [/((?:^|\s)(?:-u|--user)(?:\s+|=)?["']?[^\s:"']+:)(?!\d+(?:\s|$))("[^"]*"|'[^']*'|[^\s"']+)/g, "$1[redacted]"],
  [/((?:^|\s)cookie:\s*)[^"'\n]+/gi, "$1[redacted]"],
  [/\b(pass:)\S+/g, "$1[redacted]"],
  [
    new RegExp(String.raw`((?:["'])?\b[A-Za-z0-9_.-]*(?:${SECRET_KEY_NAME})[A-Za-z0-9_.-]*(?:["'])?\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s"',;&|)]+)`, "gi"),
    "$1[redacted]",
  ],
  [/((?:^|\s)--?(?:password|passwd|passphrase|token|secret|api-key|apikey|auth|key)(?:\s+|=))(?!-)("[^"]*"|'[^']*'|[^\s]{6,})/gi, "$1[redacted]"],
  // `-p` also means parents, port and a dozen other things, so its value must not look like a path or a port map.
  [/((?:^|\s)-p(?:\s+|=))(?!-)(?![^\s"']*\/)(?!\d+(?::\d+)*(?:\s|$))("[^"]*"|'[^']*'|[^\s]{6,})/g, "$1[redacted]"],
  [/((?:^|[\s/])(?:mysql\w*|mariadb[\w-]*|mycli|sshpass|7z[az]?|rar|unrar)\b[^\n;&|]*?\s-p)(?=\S)("[^"]*"|'[^']*'|[^\s]+)/gi, "$1[redacted]"],
  [/((?:^|[\s/])(?:zip|unzip)\b[^\n;&|]*?\s-P\s*)("[^"]*"|'[^']*'|[^\s]+)/g, "$1[redacted]"],
  [/((?:^|[\s/])redis-cli\b[^\n;&|]*?\s-a\s+)("[^"]*"|'[^']*'|[^\s]+)/g, "$1[redacted]"],
  // Glued to an unknown program: only when the value mixes letters and digits, so -pthread and -print0 stay readable.
  [/((?:^|\s)-p)(?!rint0)(?=[A-Za-z0-9!@#$%^*_+~.-]*\d)(?=[0-9!@#$%^*_+~.-]*[A-Za-z])([A-Za-z0-9!@#$%^*_+~.-]{6,})(?=\s|$)/g, "$1[redacted]"],
  [new RegExp(String.raw`(\b(?:password|passphrase)\s+)${NOT_A_PASSWORD}(?![=:-])("[^"]*"|'[^']*'|[^\s]+)`, "gi"), "$1[redacted]"],
  [/(\b[A-Za-z0-9]+_(?:secret|api_?key|access_?key|token|password)[A-Za-z0-9_]*\s+)(?![=:-])("[^"]*"|'[^']*'|[^\s]{6,})/gi, "$1[redacted]"],
  [/\b[A-Fa-f0-9]{48,}\b/g, "[redacted hex]"],
  [/\b[A-Za-z0-9+/_-]{60,}={0,2}/g, "[redacted blob]"],
];

export function redact(text) {
  let out = String(text ?? "");
  for (const [pattern, replacement] of SECRET_PATTERNS) out = out.replace(pattern, replacement);
  return out;
}

const hex = (cp) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;

const inRanges = (cp, ranges) => ranges.some(([low, high]) => cp >= low && cp <= high);

const INVISIBLE = [[0x00ad, 0x00ad], [0x034f, 0x034f], [0x200b, 0x200d], [0x2060, 0x2060], [0x2061, 0x2064], [0xfe00, 0xfe0f], [0xfeff, 0xfeff], [0xfff9, 0xfffb], [0x1d173, 0x1d17a], [0xe0100, 0xe01ef]];
// Characters that print as nothing but are not a shell's word separator, so `rm\u00a0-rf` shown plainly would read as `rm -rf`.
const BLANKS = "\\u00a0\\u1680\\u180e\\u2000-\\u200a\\u202f\\u205f\\u2800\\u3000\\u3164\\uffa0\\u115f\\u1160\\u17b4\\u17b5";
const BLANK_CHAR = new RegExp(`[${BLANKS}]`);
const BLANK_RUN = new RegExp(`[ \\t${BLANKS}]{16,}`, "g");
// Letters that can pass for Latin ones. A warning, not a verdict: the real code points are shown either way.
const LOOK_ALIKE = [[0x017f, 0x017f], [0x0370, 0x058f], [0x13a0, 0x13ff], [0x1d00, 0x1dbf], [0x1f00, 0x1fff], [0x2044, 0x2044], [0x2100, 0x218f], [0x2215, 0x2215], [0x2c80, 0x2cff], [0xa4d0, 0xa4ff], [0xa720, 0xa7ff], [0xff00, 0xffef], [0x1d400, 0x1d7ff]];

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
    } else {
      if (inRanges(cp, LOOK_ALIKE)) warnings.add("look-alike letters");
      out += ch;
    }
  }
  out = out.replace(/(?:[ \t]*\n){4,}/g, (run) => {
    warnings.add("long run of blank lines");
    return `\n⟦${run.split("\n").length - 1} blank lines⟧\n`;
  });
  return { text: out, warnings: [...warnings] };
}

export function forDisplay(text, limit = 2000) {
  const { text: shown, warnings } = faithful(redact(text));
  if (shown.length <= limit) return { text: shown, warnings, truncated: false };
  const keep = Math.floor(limit / 2);
  const hidden = shown.length - keep * 2;
  return {
    text: `${shown.slice(0, keep)}\n⟦${hidden} characters not shown⟧\n${shown.slice(-keep)}`,
    warnings: [...warnings, "too long to show in full"],
    truncated: true,
  };
}
