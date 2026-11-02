import crypto from "node:crypto";

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const SIGNING_CONTEXT = "sayso-approval-v1\n";

export const b64url = (buf) => Buffer.from(buf).toString("base64url");
export const keyIdOf = (rawPublicKey) => crypto.createHash("sha256").update(rawPublicKey).digest("hex").slice(0, 8);
export const signingBytes = (doc) => Buffer.from(SIGNING_CONTEXT + doc, "utf8");

export function generatePairing() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(SPKI_ED25519_PREFIX.length);
  return { id: keyIdOf(raw), public_key: b64url(raw), pkcs8: b64url(privateKey.export({ format: "der", type: "pkcs8" })) };
}

export function encodeDoc(doc) {
  return b64url(JSON.stringify(doc));
}

export function verifyApproval(doc, code, keys) {
  const match = /^sayso1\.([a-f0-9]{8})\.([A-Za-z0-9_-]{86})$/.exec(String(code ?? "").trim());
  if (!match) return { ok: false, why: "not a sayso approval code" };
  const key = keys.find((k) => k.id === match[1]);
  if (!key) return { ok: false, why: "signed by a key that is not paired" };
  const publicKey = crypto.createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(key.public_key, "base64url")]), format: "der", type: "spki" });
  const ok = crypto.verify(null, signingBytes(doc), publicKey, Buffer.from(match[2], "base64url"));
  return ok ? { ok: true, key_id: key.id, key_name: key.name } : { ok: false, why: "signature does not match this request" };
}

export function signAsDevice(doc, pkcs8, keyId) {
  const key = crypto.createPrivateKey({ key: Buffer.from(pkcs8, "base64url"), format: "der", type: "pkcs8" });
  return `sayso1.${keyId}.${b64url(crypto.sign(null, signingBytes(doc), key))}`;
}
