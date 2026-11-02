import crypto from "node:crypto";
import fs from "node:fs";

const sealOf = (prev, body) => crypto.createHash("sha256").update(`${prev}\n${body}`).digest("hex");

function lastSeal(file) {
  try {
    const size = fs.statSync(file).size;
    if (!size) return "genesis";
    const fd = fs.openSync(file, "r");
    const length = Math.min(size, 65536);
    const buf = Buffer.alloc(length);
    fs.readSync(fd, buf, 0, length, size - length);
    fs.closeSync(fd);
    return JSON.parse(buf.toString("utf8").trimEnd().split("\n").at(-1)).seal ?? "genesis";
  } catch {
    return "genesis";
  }
}

export function openAudit(file) {
  let prev = lastSeal(file);
  return {
    append(entry) {
      const body = JSON.stringify({ at: new Date().toISOString(), ...entry });
      const seal = sealOf(prev, body);
      fs.appendFileSync(file, `${JSON.stringify({ ...JSON.parse(body), seal })}\n`, { mode: 0o600 });
      prev = seal;
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
    const { seal, ...rest } = parsed;
    if (seal !== sealOf(prev, JSON.stringify(rest))) return { ok: false, count, broken_at: count, why: "seal does not match" };
    prev = seal;
  }
  return { ok: true, count };
}
