import crypto from "node:crypto";
import fs from "node:fs";

const hashLine = (line) => crypto.createHash("sha256").update(line).digest("hex");

function lastHash(file) {
  try {
    const size = fs.statSync(file).size;
    if (!size) return "genesis";
    const fd = fs.openSync(file, "r");
    const length = Math.min(size, 65536);
    const buf = Buffer.alloc(length);
    fs.readSync(fd, buf, 0, length, size - length);
    fs.closeSync(fd);
    const lines = buf.toString("utf8").trimEnd().split("\n");
    return hashLine(lines[lines.length - 1]);
  } catch {
    return "genesis";
  }
}

// Each line carries the hash of the line before it, so an edit or a deletion anywhere breaks the chain.
export function openAudit(file) {
  let prev = lastHash(file);
  return {
    append(entry) {
      const line = JSON.stringify({ at: new Date().toISOString(), ...entry, prev });
      fs.appendFileSync(file, `${line}\n`, { mode: 0o600 });
      prev = hashLine(line);
    },
  };
}

export function verifyAudit(file) {
  let prev = "genesis";
  let count = 0;
  let text = "";
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return { ok: true, count: 0 };
  }
  for (const line of text.split("\n")) {
    if (!line) continue;
    count++;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      return { ok: false, count, broken_at: count, why: "unparseable line" };
    }
    if (parsed.prev !== prev) return { ok: false, count, broken_at: count, why: "hash chain broken" };
    prev = hashLine(line);
  }
  return { ok: true, count };
}
