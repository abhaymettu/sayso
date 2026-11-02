const HOLD_MS = 800;
const RETREAT_RATE = 4;
const DRIFT_PX = 16;
const URGENT_MS = 60_000;
const SIGNING_CONTEXT = "sayso-approval-v1\n";
const BROWSERS = "Safari 17, Chrome 137 or Firefox 130";

const RISKS = new Map([
  ["catastrophic", { words: "Could wipe this machine", tone: "stop" }],
  ["self", { words: "Touches sayso itself", tone: "stop" }],
  ["credentials", { words: "Reads credentials", tone: "caution" }],
  ["destructive", { words: "Deletes files", tone: "caution" }],
  ["outward", { words: "Publishes something", tone: "caution" }],
  ["opaque", { words: "Runs code sayso cannot read", tone: "caution" }],
  ["prompt", { words: "Asks permission", tone: "ask" }],
  ["plan", { words: "Wants to start a plan", tone: "ask" }],
  ["question", { words: "Asks a question", tone: "ask" }],
]);
const UNKNOWN_RISK = { words: "Needs your say-so", tone: "caution" };

const WARNINGS = new Map([
  ["invisible characters", "This command contains hidden characters"],
  ["hidden tag characters", "This command contains hidden characters"],
  ["control characters", "This command contains hidden control characters"],
  ["text direction overrides", "This command contains characters that reverse how text reads"],
  ["look-alike letters", "This command contains letters that look like other letters"],
  ["long run of spaces", "This command contains a long run of spaces"],
  ["long run of blank lines", "This command contains a long run of blank lines"],
  ["too long to show in full", "This command is too long to show in full"],
]);

// The daemon already marks these, but session and folder names reach the page unmarked, and the page is what the person trusts.
const HIDDEN = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f­؜​-‏ -‮⁠-⁯﻿\u{e0000}-\u{e007f}]/gu;
const reveal = (text) => text.replace(HIDDEN, (ch) => `⟦U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}⟧`);

const b64urlToBytes = (text) => Uint8Array.from(atob(text.replaceAll("-", "+").replaceAll("_", "/")), (ch) => ch.charCodeAt(0));
const bytesToB64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
const signingBytes = (doc) => new TextEncoder().encode(SIGNING_CONTEXT + doc);
const encodeDoc = (fields) => bytesToB64url(new TextEncoder().encode(JSON.stringify(fields)));
const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

const cloneRaw = (templateId) => document.getElementById(templateId).content.firstElementChild.cloneNode(true);

function clone(templateId) {
  const root = cloneRaw(templateId);
  root.querySelector('[data-slot="brand"]')?.replaceWith(cloneRaw("t-brand"));
  return root;
}
const field = (root, name) => root.querySelector(`[data-field="${name}"]`);
const slot = (root, name) => root.querySelector(`[data-slot="${name}"]`);
const setText = (root, fields) => {
  for (const [name, text] of Object.entries(fields)) field(root, name).textContent = text;
};
const showView = (view) => document.getElementById("app").replaceChildren(view);

function messageView(title, detail) {
  const view = clone("t-message");
  setText(view, { title, detail });
  return view;
}

async function supportsEd25519() {
  try {
    await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
    return true;
  } catch {
    return false;
  }
}

function openKeyStore() {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("sayso", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("keys", { keyPath: "id" });
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}

async function addKey(record) {
  const db = await openKeyStore();
  try {
    return await new Promise((resolve, reject) => {
      const add = db.transaction("keys", "readwrite").objectStore("keys").add(record);
      add.onsuccess = () => resolve(true);
      add.onerror = (event) => {
        if (add.error?.name !== "ConstraintError") return reject(add.error);
        event.preventDefault();
        resolve(false);
      };
    });
  } finally {
    db.close();
  }
}

async function newestKey() {
  const db = await openKeyStore();
  try {
    const keys = await new Promise((resolve, reject) => {
      const all = db.transaction("keys").objectStore("keys").getAll();
      all.onsuccess = () => resolve(all.result);
      all.onerror = () => reject(all.error);
    });
    return keys.reduce((newest, key) => (!newest || key.paired_at > newest.paired_at ? key : newest), null);
  } finally {
    db.close();
  }
}

function parseRequest(doc) {
  if (!/^[A-Za-z0-9_-]+$/.test(doc)) throw new Error("not base64url");
  const raw = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(b64urlToBytes(doc)));
  const expiresAt = Date.parse(raw?.expires_at);
  if (raw?.v !== 1 || typeof raw.display !== "string" || !Number.isFinite(expiresAt)) throw new Error("unexpected shape");
  const strings = (list) => (Array.isArray(list) ? list.filter((item) => typeof item === "string") : []);
  return {
    session: String(raw.session ?? ""),
    cwd: String(raw.cwd ?? ""),
    tool: String(raw.tool ?? ""),
    risk: String(raw.risk ?? ""),
    why: strings(raw.why),
    warnings: strings(raw.warnings),
    display: raw.display,
    expiresAt,
  };
}

function warningSentences(request) {
  const sentences = new Set(request.warnings.map((text) => WARNINGS.get(text) ?? `This command was flagged: ${reveal(text)}`));
  if (reveal(request.display) !== request.display) sentences.add("This command contains hidden characters");
  if (reveal(request.session + request.cwd) !== request.session + request.cwd) sentences.add("The session or folder name contains hidden characters");
  return [...sentences];
}

function renderCommand(target, text) {
  target.replaceChildren();
  for (const part of reveal(text).split(/(⟦[^⟧]*⟧)/u)) {
    if (!part) continue;
    if (!part.startsWith("⟦")) {
      target.append(part);
      continue;
    }
    const mark = document.createElement("span");
    mark.className = "hidden-mark";
    mark.textContent = part;
    target.append(mark);
  }
}

function formatRemaining(ms) {
  const total = Math.ceil(ms / 1000);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = String(total % 60).padStart(2, "0");
  return hours ? `${hours}:${String(minutes).padStart(2, "0")}:${seconds}` : `${minutes}:${seconds}`;
}

function startCountdown(target, expiresAt, onExpire) {
  const tick = () => {
    const left = expiresAt - Date.now();
    if (left <= 0) {
      clearInterval(timer);
      target.textContent = "Expired";
      target.dataset.state = "over";
      onExpire();
      return;
    }
    const text = `Expires in ${formatRemaining(left)}`;
    if (target.textContent !== text) target.textContent = text;
    if (left <= URGENT_MS) target.dataset.state = "urgent";
  };
  const timer = setInterval(tick, 250);
  tick();
  return () => clearInterval(timer);
}

// One animation is the whole gesture: pressing plays it, letting go runs it backwards from wherever the fill has got to.
function holdToConfirm(button, onConfirm) {
  const fill = button.querySelector(".hold-fill");
  const run = fill.animate([{ clipPath: "inset(0 100% 0 0)" }, { clipPath: "inset(0 0 0 0)" }], { duration: HOLD_MS, easing: "linear", fill: "both" });
  run.pause();
  let pressed = false;

  const press = () => {
    if (pressed) return;
    pressed = true;
    button.dataset.pressed = "";
    run.playbackRate = 1;
    run.play();
  };
  const release = () => {
    if (!pressed) return;
    pressed = false;
    delete button.dataset.pressed;
    if (run.currentTime > 0) {
      run.playbackRate = -RETREAT_RATE;
      run.play();
    } else {
      run.pause();
    }
  };
  run.onfinish = () => {
    if (run.playbackRate < 0 || !pressed) return;
    pressed = false;
    delete button.dataset.pressed;
    navigator.vibrate?.(12);
    onConfirm();
  };

  const within = (event) => {
    const box = button.getBoundingClientRect();
    return event.clientX >= box.left - DRIFT_PX && event.clientX <= box.right + DRIFT_PX && event.clientY >= box.top - DRIFT_PX && event.clientY <= box.bottom + DRIFT_PX;
  };
  let pointer = null;
  button.addEventListener("pointerdown", (event) => {
    if (pointer !== null || event.button !== 0) return;
    pointer = event.pointerId;
    button.setPointerCapture(pointer);
    press();
  });
  button.addEventListener("pointermove", (event) => {
    if (event.pointerId !== pointer) return;
    if (within(event)) press();
    else release();
  });
  const endPointer = (event) => {
    if (event.pointerId !== pointer) return;
    pointer = null;
    release();
  };
  button.addEventListener("pointerup", endPointer);
  button.addEventListener("pointercancel", endPointer);
  button.addEventListener("lostpointercapture", endPointer);
  button.addEventListener("contextmenu", (event) => event.preventDefault());
  button.addEventListener("keydown", (event) => {
    if (event.key !== " " && event.key !== "Enter") return;
    event.preventDefault();
    if (!event.repeat) press();
  });
  button.addEventListener("keyup", (event) => {
    if (event.key === " " || event.key === "Enter") release();
  });
  button.addEventListener("blur", release);
  const onHidden = () => {
    if (document.hidden) release();
  };
  document.addEventListener("visibilitychange", onHidden);

  return () => {
    document.removeEventListener("visibilitychange", onHidden);
    run.cancel();
  };
}

function selectText(element) {
  const range = document.createRange();
  range.selectNodeContents(element);
  const selection = getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
}

function wireCopyAndShare(panel, code) {
  const label = field(panel, "copy-label");
  let reset;
  panel.querySelector('[data-action="copy"]').addEventListener("click", async () => {
    clearTimeout(reset);
    try {
      await navigator.clipboard.writeText(code);
      label.textContent = "Copied";
      reset = setTimeout(() => (label.textContent = "Copy code"), 2000);
    } catch {
      selectText(field(panel, "code"));
      label.textContent = "Selected. Copy it from the menu.";
    }
  });
  if (!navigator.share) return;
  const share = panel.querySelector('[data-action="share"]');
  share.hidden = false;
  share.addEventListener("click", () => navigator.share({ text: code }).catch(() => {}));
}

function revealPanel(actions, focusTarget) {
  actions.scrollIntoView({ block: "nearest", behavior: reducedMotion() ? "auto" : "smooth" });
  focusTarget?.focus({ preventScroll: true });
}

function realSignedPanel(sheetState) {
  const panel = clone("t-signed");
  setText(panel, { code: sheetState.code });
  wireCopyAndShare(panel, sheetState.code);
  sheetState.markStale = () => setText(panel, { "signed-note": "This request has expired, so this code will be refused. Your agent can ask again." });
  return { panel, focus: panel.querySelector('[data-action="copy"]') };
}

// A phase is what the action area shows. Everything else on the sheet stays put, so the request never moves while it is being judged.
const PHASES = {
  ready(state) {
    const panel = clone("t-ready");
    state.dispose = holdToConfirm(panel.querySelector(".hold"), () => state.approve());
    panel.querySelector('[data-action="decline"]').addEventListener("click", () => state.show("declined"));
    return { panel };
  },
  declined(state) {
    const panel = clone("t-declined");
    panel.querySelector('[data-action="undecline"]').addEventListener("click", () => state.show("ready"));
    return { panel };
  },
  expired() {
    return { panel: clone("t-expired") };
  },
  signed(state) {
    return state.signedPanel(state);
  },
  unpaired() {
    const panel = clone("t-notice");
    setText(panel, { title: "This device is not paired", detail: "To pair, run sayso pair in your own terminal and open the link it gives you on this device." });
    return { panel };
  },
  unsupported() {
    const panel = clone("t-notice");
    setText(panel, { title: "This browser cannot sign", detail: `sayso needs Ed25519 in WebCrypto. Use ${BROWSERS}, or newer.` });
    return { panel };
  },
  broken() {
    const panel = clone("t-notice");
    setText(panel, { title: "Signing failed on this device", detail: "The stored key did not work. Run sayso pair in your own terminal to pair again." });
    return { panel };
  },
};

function mountSheet({ doc, request, signer, lead, headingLevel, signedPanel }) {
  const sheet = clone("t-sheet");
  const risk = RISKS.get(request.risk) ?? UNKNOWN_RISK;
  const heading = sheet.querySelector(".risk");
  heading.dataset.tone = risk.tone;
  heading.setAttribute("aria-level", String(headingLevel));
  field(sheet, "risk-icon").setAttribute("href", `#i-${risk.tone}`);
  slot(sheet, "lead").replaceWith(lead);
  renderCommand(field(sheet, "display"), request.display);
  setText(sheet, { risk: risk.words, tool: reveal(request.tool), session: reveal(request.session), cwd: reveal(request.cwd) });

  const warnings = warningSentences(request);
  if (warnings.length) {
    slot(sheet, "warnings").hidden = false;
    field(sheet, "warnings").append(...warnings.map((text) => Object.assign(document.createElement("li"), { textContent: text })));
  }
  if (request.why.length) {
    slot(sheet, "why").hidden = false;
    field(sheet, "why").append(...request.why.map((text) => Object.assign(document.createElement("li"), { textContent: reveal(text) })));
  }

  const actions = slot(sheet, "actions");
  const state = {
    phase: null,
    code: null,
    dispose: null,
    markStale: null,
    signedPanel,
    signer,
    doc,
    show(phase) {
      state.dispose?.();
      state.dispose = null;
      state.phase = phase;
      actions.dataset.phase = phase;
      const { panel, focus } = PHASES[phase](state);
      actions.replaceChildren(panel);
      if (focus) revealPanel(actions, focus);
    },
    async approve() {
      if (Date.now() >= request.expiresAt) return state.show("expired");
      try {
        const signature = await crypto.subtle.sign("Ed25519", signer.key, signingBytes(doc));
        state.signature = signature;
        state.code = `sayso1.${signer.id}.${bytesToB64url(signature)}`;
        field(sheet, "announce").textContent = "Approved. The code is ready to copy.";
        state.show("signed");
      } catch {
        state.show("broken");
      }
    },
  };

  const stopCountdown = startCountdown(field(sheet, "countdown"), request.expiresAt, () => {
    field(sheet, "announce").textContent = "This request expired.";
    if (state.phase === "ready" || state.phase === "declined") state.show("expired");
    if (state.phase === "signed") state.markStale?.();
  });
  state.show(signer.phase);
  return { sheet, state, stop: stopCountdown };
}

async function pairView(hash) {
  const params = new URLSearchParams(hash.slice(1));
  history.replaceState(null, "", location.pathname + location.search);

  const id = params.get("id") ?? "";
  const name = reveal((params.get("name") ?? "").slice(0, 80));
  if (!/^[a-f0-9]{8}$/.test(id) || !/^[A-Za-z0-9_-]+$/.test(params.get("pair") ?? "")) {
    return messageView("This pairing link is damaged", "Nothing was stored. Run sayso pair in your own terminal to get a new one.");
  }
  if (!(await supportsEd25519())) {
    return messageView("This browser cannot hold the key", `sayso needs Ed25519 in WebCrypto. Use ${BROWSERS}, or newer, then run sayso pair again.`);
  }

  let secret;
  let key;
  try {
    secret = b64urlToBytes(params.get("pair"));
    key = await crypto.subtle.importKey("pkcs8", secret, "Ed25519", false, ["sign"]);
  } catch {
    return messageView("This pairing link is damaged", "Nothing was stored. Run sayso pair in your own terminal to get a new one.");
  } finally {
    secret?.fill(0);
  }

  let added;
  try {
    added = await addKey({ id, name, key, paired_at: Date.now() });
  } catch {
    return messageView("This browser would not store the key", "Private browsing usually blocks this. Open the link in a normal tab, or run sayso pair again.");
  }

  const view = clone("t-paired");
  setText(view, {
    title: added ? "This device is paired" : "Already paired",
    id,
    name,
    detail: added ? "You can close this page. Approvals you make here are signed with this key." : "This device already has this key, so it kept it. You can close this page.",
  });
  slot(view, "name").hidden = !name;
  return view;
}

async function requestSigner() {
  if (!(await supportsEd25519())) return { phase: "unsupported" };
  try {
    const stored = await newestKey();
    return stored ? { phase: "ready", id: stored.id, key: stored.key } : { phase: "unpaired" };
  } catch {
    return { phase: "unpaired" };
  }
}

async function requestView(hash) {
  const doc = hash.slice("#r=".length);
  let request;
  try {
    request = parseRequest(doc);
  } catch {
    return messageView("This link is damaged", "It does not hold a request sayso can read. Ask your agent to send it again.");
  }
  return mountSheet({ doc, request, signer: await requestSigner(), lead: cloneRaw("t-brand"), headingLevel: 1, signedPanel: realSignedPanel }).sheet;
}

const SAMPLE_COMMAND = "rm -rf ./*";
const LIED_COMMAND = "rm -rf ~/*";

function sampleFields() {
  return {
    v: 1,
    id: "r_sample",
    nonce: bytesToB64url(crypto.getRandomValues(new Uint8Array(9))),
    session: "harbor-api",
    cwd: "~/projects/harbor-api/build",
    tool: "Bash",
    kind: "tool",
    risk: "destructive",
    why: ["Deletes a folder's contents for good, with no way back"],
    display: SAMPLE_COMMAND,
    warnings: [],
    expires_at: new Date(Date.now() + 15 * 60_000).toISOString(),
    input_sha256: "",
  };
}

function renderLie(target) {
  target.replaceChildren();
  const swapped = document.createElement("span");
  swapped.className = "swapped";
  swapped.textContent = "~";
  target.append("rm -rf ", swapped, "/*");
}

function demoSignedPanel(state, fields, keys, restart) {
  const panel = clone("t-demo-signed");
  setText(panel, { code: state.code });
  const realDoc = state.doc;
  const liedDoc = encodeDoc({ ...fields, display: LIED_COMMAND });
  const verdict = field(panel, "verdict");
  const lieButton = panel.querySelector('[data-action="lie"]');
  let lying = false;

  // The verdict comes from a real verify over whichever document is showing, never from the toggle.
  const check = async () => {
    const passes = await crypto.subtle.verify("Ed25519", keys.publicKey, state.signature, signingBytes(lying ? liedDoc : realDoc));
    if (lying) renderLie(field(panel, "proof-command"));
    else field(panel, "proof-command").textContent = SAMPLE_COMMAND;
    setText(panel, {
      "proof-caption": lying ? "What the agent now says you approved" : "What the agent says you approved",
      "verdict-word": passes ? "Signature passes." : "Signature fails.",
      "verdict-detail": passes ? "This is the exact text you read." : "One character changed, so the machine refuses it and nothing runs.",
    });
    verdict.dataset.verdict = passes ? "pass" : "fail";
    field(panel, "verdict-icon").setAttribute("href", passes ? "#i-check" : "#i-fail");
    lieButton.textContent = lying ? "Show the real request" : "Agent tries to lie";
  };
  lieButton.addEventListener("click", () => {
    lying = !lying;
    check();
  });
  panel.querySelector('[data-action="again"]').addEventListener("click", restart);
  check();
  return { panel, focus: lieButton };
}

async function mountDemo(host) {
  if (!(await supportsEd25519())) {
    const notice = clone("t-notice");
    setText(notice, { title: "This browser cannot sign", detail: `The demo needs Ed25519 in WebCrypto. Use ${BROWSERS}, or newer.` });
    host.replaceChildren(notice);
    return;
  }
  // Generated fresh and held only in this variable. The demo never opens IndexedDB.
  const keys = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const rawPublic = await crypto.subtle.exportKey("raw", keys.publicKey);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", rawPublic));
  const id = [...digest.slice(0, 4)].map((byte) => byte.toString(16).padStart(2, "0")).join("");

  let stopCurrent = () => {};
  const start = () => {
    stopCurrent();
    const fields = sampleFields();
    const doc = encodeDoc(fields);
    const lead = document.createElement("p");
    lead.className = "sheet-tag";
    lead.textContent = "Sample request";
    const { sheet, stop } = mountSheet({
      doc,
      request: parseRequest(doc),
      signer: { phase: "ready", id, key: keys.privateKey },
      lead,
      headingLevel: 3,
      signedPanel: (state) => demoSignedPanel(state, fields, keys, start),
    });
    stopCurrent = stop;
    host.replaceChildren(sheet);
  };
  start();
}

function landingView() {
  const view = clone("t-landing");
  mountDemo(slot(view, "sheet"));
  return view;
}

async function main() {
  addEventListener("hashchange", () => location.reload());
  if (window.top !== window.self) {
    showView(messageView("Open this page in its own tab", "sayso will not pair or sign inside another page's frame."));
    return;
  }
  const hash = location.hash;
  if (hash.startsWith("#pair=")) showView(await pairView(hash));
  else if (hash.startsWith("#r=")) showView(await requestView(hash));
  else showView(landingView());
}

main();
