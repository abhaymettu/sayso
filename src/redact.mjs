// Everything a session produces passes through here before it reaches an agent, a webhook, the page or the audit log.
// Two jobs: secrets never leave, and what a person reads is what would actually run.

const SECRET_PATTERNS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[redacted private key]"],
  [/\b(?:sk|pk|rk)-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_-]{16,}/g, "[redacted key]"],
  [/\bsayso_agent_[A-Za-z0-9_-]+/g, "[redacted token]"],
  [/\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}/g, "[redacted token]"],
  [/\bxox[abeprs]-[A-Za-z0-9-]{10,}/g, "[redacted token]"],
  [/\bxapp-[A-Za-z0-9-]{10,}/g, "[redacted token]"],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[redacted key]"],
  [/\bAIza[A-Za-z0-9_-]{30,}/g, "[redacted key]"],
  [/\bnpm_[A-Za-z0-9]{30,}/g, "[redacted token]"],
  [/\bglpat-[A-Za-z0-9_-]{16,}/g, "[redacted token]"],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+/g, "[redacted jwt]"],
  [/\b(Bearer|Basic|Token)\s+[A-Za-z0-9+/._~=-]{8,}/gi, "$1 [redacted]"],
  [/\b([a-z][a-z0-9+.-]*:\/\/[^\s:/@]+):[^\s@/]+@/gi, "$1:[redacted]@"],
  [
    /((?:["'])?\b[A-Za-z0-9_.-]*(?:api[_-]?key|secret|token|passw(?:or)?d|passphrase|credential|private[_-]?key|access[_-]?key|auth)[A-Za-z0-9_.-]*(?:["'])?\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s"',;&|)]+)/gi,
    "$1[redacted]",
  ],
  [/((?:^|\s)(?:--?(?:password|passwd|token|secret|api-key|apikey|auth|key)|-p)(?:\s+|=))(?!-)("[^"]*"|'[^']*'|[^\s]{6,})/gi, "$1[redacted]"],
  [/\b[A-Fa-f0-9]{48,}\b/g, "[redacted hex]"],
  [/\b[A-Za-z0-9+/_-]{60,}={0,2}/g, "[redacted blob]"],
];

export function redact(text) {
  let out = String(text ?? "");
  for (const [pattern, replacement] of SECRET_PATTERNS) out = out.replace(pattern, replacement);
  return out;
}

const hex = (cp) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;

// Text an attacker chose must not be able to look like something else: hidden characters become visible marks and
// each kind raises a warning the reader sees before deciding.
export function faithful(text) {
  const warnings = new Set();
  let out = "";
  for (const ch of String(text ?? "")) {
    const cp = ch.codePointAt(0);
    if (ch === "\n") out += "\n";
    else if (ch === "\t") out += "\t";
    else if (cp < 0x20 || (cp >= 0x7f && cp < 0xa0)) {
      warnings.add("control characters");
      out += `⟦${hex(cp)}⟧`;
    } else if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0x200e || cp === 0x200f || cp === 0x061c) {
      warnings.add("text direction overrides");
      out += `⟦${hex(cp)}⟧`;
    } else if ((cp >= 0x200b && cp <= 0x200d) || cp === 0x2060 || cp === 0xfeff || cp === 0x00ad) {
      warnings.add("invisible characters");
      out += `⟦${hex(cp)}⟧`;
    } else if (cp >= 0xe0000 && cp <= 0xe007f) {
      warnings.add("hidden tag characters");
      out += `⟦tag ${String.fromCodePoint(cp - 0xe0000)}⟧`;
    } else {
      if ((cp >= 0x0370 && cp <= 0x04ff) || (cp >= 0xff00 && cp <= 0xffef) || (cp >= 0x2100 && cp <= 0x214f)) warnings.add("look-alike letters");
      out += ch;
    }
  }
  out = out.replace(/ {16,}/g, (run) => {
    warnings.add("long run of spaces");
    return `⟦${run.length} spaces⟧`;
  });
  out = out.replace(/\n{4,}/g, (run) => {
    warnings.add("long run of blank lines");
    return `\n⟦${run.length} blank lines⟧\n`;
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
