/* Card Vault — offline PWA card store.
   Security model:
     - A random 256-bit Data Encryption Key (DEK) encrypts the card list (AES-GCM).
     - The DEK is wrapped (encrypted) twice: once by a key derived from the master
       password (PBKDF2), once by a key derived from WebAuthn PRF output (Face ID).
     - Either unlock path recovers the same DEK. The DEK lives only in memory.
   Cleartext never leaves this device. Optional iCloud sync (see sync.js) copies
   only the ciphertext and the password-wrapped DEK, so Apple stores opaque bytes.
*/

const enc = new TextEncoder();
const dec = new TextDecoder();
const PBKDF2_ITERS = 310000;
const PRF_SALT = enc.encode("card-vault.prf.v1"); // fixed input salt for PRF eval

/* ---------- base64 helpers ---------- */
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/* ---------- IndexedDB (single meta record) ---------- */
const DB_NAME = "card-vault";
const STORE = "kv";
function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB_NAME, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function idbGet(key) {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction(STORE, "readonly").objectStore(STORE).get(key);
    t.onsuccess = () => res(t.result);
    t.onerror = () => rej(t.error);
  });
}
async function idbSet(key, val) {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction(STORE, "readwrite").objectStore(STORE).put(val, key);
    t.onsuccess = () => res();
    t.onerror = () => rej(t.error);
  });
}
async function idbClear() {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction(STORE, "readwrite").objectStore(STORE).clear();
    t.onsuccess = () => res();
    t.onerror = () => rej(t.error);
  });
}

/* ---------- crypto ---------- */
async function pwKek(password, salt) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
async function prfKek(prfBytes) {
  const base = await crypto.subtle.importKey("raw", prfBytes, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode("card-vault.kek") },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
async function genDek() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}
async function wrap(kek, dek) {
  const raw = await crypto.subtle.exportKey("raw", dek);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kek, raw);
  return { iv: b64(iv), ct: b64(ct) };
}
async function unwrap(kek, w) {
  const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(w.iv) }, kek, unb64(w.ct));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
}
async function encJSON(dek, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dek, enc.encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(ct) };
}
async function decJSON(dek, blob) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(blob.iv) }, dek, unb64(blob.ct));
  return JSON.parse(dec.decode(pt));
}

/* ---------- WebAuthn PRF (Face ID) ---------- */
function prfSupportedUA() {
  return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
}
async function registerPasskey() {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: "Card Vault" },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "vault", displayName: "Card Vault" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
      extensions: { prf: {} },
    },
  });
  const ext = cred.getClientExtensionResults();
  if (!ext.prf || ext.prf.enabled === false) throw new Error("This device/browser doesn't support Face ID encryption (WebAuthn PRF).");
  return b64(cred.rawId);
}
async function getPrfBytes(credId) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: "public-key", id: unb64(credId) }],
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  const ext = assertion.getClientExtensionResults();
  if (!ext.prf || !ext.prf.results || !ext.prf.results.first) throw new Error("Face ID unlock unavailable on this device.");
  return ext.prf.results.first;
}

/* ---------- vault state ---------- */
let META = null;      // { dekId, pw:{salt,wrapped}, prf:{credId,wrapped}|null, vault:{iv,ct}, updatedAt }
let DEK = null;       // in-memory only
let CARDS = [];       // decrypted card list (in memory only)
let DELETED = [];     // [{id, at}] tombstones, so deletions survive a merge

// Tombstones are kept long enough for any device to see them, then dropped.
const TOMBSTONE_TTL = 180 * 24 * 60 * 60 * 1000;

async function loadMeta() { META = (await idbGet("meta")) || null; }

/* The plaintext vault used to be a bare card array; it is now
   { v, cards, deleted } so deletions can be merged across devices. */
function normalizeVault(x) {
  if (Array.isArray(x)) return { v: 1, cards: x.map(migrateCard), deleted: [] };
  if (!x || typeof x !== "object") return { v: 1, cards: [], deleted: [] };
  return { v: 1, cards: (x.cards || []).map(migrateCard), deleted: x.deleted || [] };
}

/* Cards predating sync have no timestamps. uid() starts with a base-36
   millisecond stamp, so creation time is recoverable from the id itself. */
function migrateCard(c) {
  if (c.createdAt && c.updatedAt) return c;
  let born = 0;
  const stamp = parseInt(String(c.id || "").slice(0, -5), 36);
  if (Number.isFinite(stamp) && stamp > 0) born = stamp;
  return { ...c, createdAt: c.createdAt || born, updatedAt: c.updatedAt || c.createdAt || born };
}

function currentVault() { return { v: 1, cards: CARDS, deleted: DELETED }; }

// Fingerprint of the DEK. Lets sync tell "same vault, different edits" (mergeable)
// apart from "two unrelated vaults" (not mergeable) without exposing the key.
async function dekFingerprint(dek) {
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", dek));
  const tag = enc.encode("card-vault.dek-id.v1");
  const salted = new Uint8Array(tag.length + raw.length);
  salted.set(tag, 0);
  salted.set(raw, tag.length);
  return b64(await crypto.subtle.digest("SHA-256", salted)).slice(0, 22);
}

// Re-encrypt the in-memory vault and persist it. Requires an unlocked DEK.
async function persistLocal() {
  META.vault = await encJSON(DEK, currentVault());
  META.updatedAt = Date.now();
  if (!META.dekId) META.dekId = await dekFingerprint(DEK);
  await idbSet("meta", META);
}
async function saveVault() {
  await persistLocal();
  scheduleSync();
}
function lock() { DEK = null; CARDS = []; DELETED = []; render(); }

/* ---------- setup / unlock ---------- */
async function setupVault(password, enableFaceId) {
  DEK = await genDek();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  META = {
    dekId: await dekFingerprint(DEK),
    pw: { salt: b64(salt), wrapped: await wrap(await pwKek(password, salt), DEK) },
    prf: null, vault: null, updatedAt: 0,
  };
  if (enableFaceId) {
    const credId = await registerPasskey();
    const bytes = await getPrfBytes(credId);
    META.prf = { credId, wrapped: await wrap(await prfKek(bytes), DEK) };
  }
  CARDS = []; DELETED = [];
  await saveVault();
}
async function addFaceId() {
  const credId = await registerPasskey();
  const bytes = await getPrfBytes(credId);
  META.prf = { credId, wrapped: await wrap(await prfKek(bytes), DEK) };
  await idbSet("meta", META);
}
async function afterUnlock() {
  const v = normalizeVault(META.vault ? await decJSON(DEK, META.vault) : null);
  CARDS = v.cards; DELETED = v.deleted;
  if (!META.dekId) { META.dekId = await dekFingerprint(DEK); await idbSet("meta", META); }
  syncNow().catch(() => {}); // background pull/merge; never blocks unlock
}
async function unlockWithPassword(password) {
  const kek = await pwKek(password, unb64(META.pw.salt));
  DEK = await unwrap(kek, META.pw.wrapped); // throws if wrong password
  await afterUnlock();
}
async function unlockWithFaceId() {
  const bytes = await getPrfBytes(META.prf.credId);
  DEK = await unwrap(await prfKek(bytes), META.prf.wrapped);
  await afterUnlock();
}

/* ---------- merge ----------
   Both sides decrypt to plaintext under the same DEK, so merging happens on
   real card objects: newest edit per card id wins, and a tombstone removes a
   card unless that card was edited after the deletion (an edit resurrects it).
*/
function mergeVaults(a, b) {
  const tomb = new Map();
  for (const t of [...(a.deleted || []), ...(b.deleted || [])]) {
    const prev = tomb.get(t.id);
    if (!prev || t.at > prev.at) tomb.set(t.id, t);
  }
  const byId = new Map();
  for (const c of [...(a.cards || []), ...(b.cards || [])]) {
    const prev = byId.get(c.id);
    if (!prev || (c.updatedAt || 0) > (prev.updatedAt || 0)) byId.set(c.id, c);
  }
  const cards = [];
  for (const c of byId.values()) {
    const t = tomb.get(c.id);
    if (t && t.at >= (c.updatedAt || 0)) continue;
    cards.push(c);
  }
  // Stable, device-independent order so both sides converge on the same list.
  cards.sort((x, y) => (x.createdAt || 0) - (y.createdAt || 0) || (x.id < y.id ? -1 : 1));
  const cutoff = Date.now() - TOMBSTONE_TTL;
  const deleted = [...tomb.values()]
    .filter((t) => t.at >= cutoff && !cards.some((c) => c.id === t.id))
    .sort((x, y) => x.at - y.at);
  return { v: 1, cards, deleted };
}
const vaultKey = (v) => JSON.stringify([v.cards, v.deleted]);

/* ---------- iCloud sync ---------- */
let SYNC = { status: "off", msg: "", last: 0, fork: false };
let syncTimer = null, syncRunning = false, syncQueued = false;

function setSync(status, msg) {
  SYNC.status = status;
  SYNC.msg = msg || "";
  if (status === "ok") SYNC.last = Date.now();
  if (status !== "fork") SYNC.fork = false;
  renderSyncSheet();
  const btn = document.querySelector("[data-sync]");
  if (btn) btn.innerHTML = I.cloud(status);
}

function scheduleSync() {
  if (!CloudSync.isConfigured()) return;
  clearTimeout(syncTimer);
  syncTimer = setTimeout(() => syncNow().catch(() => {}), 1500);
}

function localPayload() {
  return {
    v: 1, dekId: META.dekId, pw: META.pw, prf: META.prf,
    vault: META.vault, updatedAt: META.updatedAt || 0,
  };
}

async function syncNow() {
  if (!CloudSync.isConfigured() || !META) return;
  if (syncRunning) { syncQueued = true; return; }
  syncRunning = true;
  setSync("syncing");
  try {
    await CloudSync.init();
    if (!CloudSync.signedIn()) { setSync("signedout"); return; }
    await syncOnce(0);
    if (SYNC.status === "syncing") setSync("ok");
  } catch (e) {
    if (e && e.fork) setSync("fork", e.message);
    else setSync("error", (e && e.message) || "Sync failed.");
  } finally {
    syncRunning = false;
    if (syncQueued) { syncQueued = false; scheduleSync(); }
  }
}

async function syncOnce(attempt) {
  const remote = await CloudSync.fetchRemote();

  if (!remote) { await CloudSync.saveRemote(localPayload()); return; }

  // Two independently created vaults have different DEKs; their ciphertexts are
  // not interchangeable, so refuse to merge and let the user choose a winner.
  if (remote.dekId && META.dekId && remote.dekId !== META.dekId) {
    const err = new Error("This device and iCloud hold different vaults.");
    err.fork = true;
    throw err;
  }

  // Locked: we can't decrypt to merge, so only push if we're strictly newer.
  if (!DEK) {
    if ((remote.updatedAt || 0) < (META.updatedAt || 0)) await CloudSync.saveRemote(localPayload());
    return;
  }

  let remoteVault;
  try {
    remoteVault = normalizeVault(remote.vault ? await decJSON(DEK, remote.vault) : null);
  } catch {
    const err = new Error("The iCloud copy can't be decrypted with this vault's key.");
    err.fork = true;
    throw err;
  }

  const local = currentVault();
  const merged = mergeVaults(local, remoteVault);

  if (vaultKey(merged) !== vaultKey(local)) {
    CARDS = merged.cards; DELETED = merged.deleted;
    await persistLocal();
    render();
  }
  // Adopt a Face ID enrolment from iCloud only if this device has none —
  // never clobber a passkey that already works here.
  if (!META.prf && remote.prf) { META.prf = remote.prf; await idbSet("meta", META); }

  if (vaultKey(merged) !== vaultKey(remoteVault) || !remote.pw) {
    try {
      await CloudSync.saveRemote(localPayload());
    } catch (e) {
      if (e && e.conflict && attempt < 3) return syncOnce(attempt + 1);
      throw e;
    }
  }
}

/* Pull the iCloud vault and adopt it wholesale (new device, or "cloud wins"). */
async function restoreFromCloud() {
  await CloudSync.init();
  if (!CloudSync.signedIn()) throw new Error("Sign in to iCloud first.");
  const remote = await CloudSync.fetchRemote();
  if (!remote || !remote.pw) throw new Error("No vault saved in iCloud yet.");
  META = {
    dekId: remote.dekId || null, pw: remote.pw, prf: remote.prf || null,
    vault: remote.vault || null, updatedAt: remote.updatedAt || Date.now(),
  };
  await idbSet("meta", META);
  DEK = null; CARDS = []; DELETED = [];
}

/* Overwrite the iCloud copy with this device's vault. */
async function overwriteCloud() {
  await CloudSync.init();
  if (!CloudSync.signedIn()) throw new Error("Sign in to iCloud first.");
  await CloudSync.fetchRemote().catch(() => null); // refresh the change tag
  await CloudSync.saveRemote(localPayload());
}

/* ---------- clipboard ---------- */
async function copy(text, label) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch {}
    ta.remove();
  }
  toast((label || "Copied") + " copied");
}

/* ---------- gradients by network ---------- */
const GRADIENTS = {
  "Diners Club": "linear-gradient(135deg,#1a1a1a 0%,#2b2b2b 45%,#0d0d0d 100%)",
  "Visa": "linear-gradient(135deg,#0f2027 0%,#203a43 50%,#2c5364 100%)",
  "Mastercard": "linear-gradient(135deg,#3a2b2b 0%,#5b3a3a 55%,#241717 100%)",
  "American Express": "linear-gradient(135deg,#3a3f4a 0%,#5b6472 55%,#2c313a 100%)",
  "RuPay": "linear-gradient(135deg,#14342b 0%,#1f5140 55%,#0d211b 100%)",
  "Other": "linear-gradient(135deg,#23262c 0%,#33373f 55%,#14171c 100%)",
};
const NETWORKS = Object.keys(GRADIENTS);
function gradientFor(network) { return GRADIENTS[network] || GRADIENTS.Other; }

/* ---------- helpers ---------- */
function maskNum(num) {
  const p = (num || "").trim().split(/\s+/);
  if (p.length < 2) return num;
  return p.map((x, i) => (i === p.length - 1 ? x : "••••")).join(" ");
}
function esc(s) { return (s || "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);

/* ---------- SVG icons ---------- */
const I = {
  lock: `<svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#D8B36A" stroke-width="1.6"><rect x="4" y="10" width="16" height="10" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>`,
  lockSm: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#8A8F98" stroke-width="1.7"><rect x="4" y="10" width="16" height="10" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>`,
  face: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#1a1400" stroke-width="1.8"><path d="M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2"/><path d="M9 10v1M15 10v1M9 15c1 1 5 1 6 0"/></svg>`,
  copy: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.85)" stroke-width="1.7"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>`,
  copyGold: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#D8B36A" stroke-width="1.6"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>`,
  eye: (on) => `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.85)" stroke-width="1.7"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/>${on ? '<circle cx="12" cy="12" r="3"/>' : '<line x1="3" y1="3" x2="21" y2="21"/>'}</svg>`,
  eyeD: (on) => `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#8A8F98" stroke-width="1.6"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/>${on ? '<circle cx="12" cy="12" r="3"/>' : '<line x1="3" y1="3" x2="21" y2="21"/>'}</svg>`,
  star: (on) => `<svg width="15" height="15" viewBox="0 0 24 24" fill="${on ? "#D8B36A" : "none"}" stroke="${on ? "#D8B36A" : "rgba(255,255,255,0.7)"}" stroke-width="1.6"><path d="M12 2l2.9 6.3 6.9.8-5.1 4.7 1.4 6.8L12 17.8 5.9 20.4l1.4-6.8L2.2 9.1l6.9-.8L12 2z"/></svg>`,
  back: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#8A8F98" stroke-width="2"><path d="M15 18l-6-6 6-6"/></svg>`,
  cloud: (status) => {
    const c = status === "ok" ? "#D8B36A" : status === "error" || status === "fork" ? "#E06B6B" : "#8A8F98";
    const arrows = status === "syncing"
      ? '<path d="M9.5 13.5l2.5-2.5 2.5 2.5"/>'
      : status === "ok" ? '<path d="M9.5 12.5l1.8 1.8 3.4-3.6"/>' : "";
    return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M7 18a4 4 0 0 1-.4-8A5.5 5.5 0 0 1 17.2 9.6 3.7 3.7 0 0 1 17 18H7z"/>${arrows}</svg>`;
  },
};

/* ---------- toast ---------- */
let toastT;
function toast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg; el.hidden = false;
  clearTimeout(toastT);
  toastT = setTimeout(() => (el.hidden = true), 1400);
}

/* ---------- rendering ---------- */
const app = () => document.getElementById("app");
let VIEW = { name: "boot", cardId: null };

function go(name, cardId = null) { VIEW = { name, cardId }; render(); }

/* ---------- sync sheet ----------
   Updated field-by-field rather than by innerHTML: the Apple sign-in button is
   injected into #apple-sign-in-button by CloudKit and must survive redraws. */
let SHEET_OPEN = false;

function syncStateText() {
  if (!CloudSync.isConfigured()) return "Not configured";
  switch (SYNC.status) {
    case "syncing": return "Syncing…";
    case "signedout": return "Not signed in to iCloud";
    case "fork": return "Conflict";
    case "error": return "Sync problem";
    case "ok": return `Synced to ${CloudSync.who()}`;
    default: return CloudSync.signedIn() ? `Signed in as ${CloudSync.who()}` : "Not signed in to iCloud";
  }
}

function renderSyncSheet() {
  const sheet = document.getElementById("sync-sheet");
  if (!sheet || !SHEET_OPEN) return;
  const configured = CloudSync.isConfigured();
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  const show = (id, on) => { const el = document.getElementById(id); if (el) el.hidden = !on; };

  set("sync-state", syncStateText());
  set("sync-err", SYNC.status === "error" || SYNC.status === "fork" ? SYNC.msg : "");
  show("sync-fork", SYNC.status === "fork");
  show("sync-auth-wrap", configured);
  show("sync-actions", configured);
  show("sync-wipe-cloud", configured); // nothing in iCloud to delete until it is

  const nowBtn = document.getElementById("sync-now");
  if (nowBtn) nowBtn.disabled = SYNC.status === "syncing" || !CloudSync.signedIn();

  const diagEl = document.getElementById("sync-diag");
  if (diagEl) {
    let text;
    try {
      const d = CloudSync.diag ? CloudSync.diag() : { error: "stale sync.js — hard-reload the page" };
      text = Object.keys(d).map((k) => `${k}: ${d[k]}`).join("\n") +
        `\nsyncStatus: ${SYNC.status}${SYNC.msg ? " — " + SYNC.msg : ""}`;
    } catch (e) {
      text = "diagnostics failed: " + ((e && e.message) || e);
    }
    diagEl.value = text; // textarea, so it stays selectable if clipboard is denied
  }

  set("sync-hint", configured
    ? (SYNC.last
        ? `Last synced ${new Date(SYNC.last).toLocaleTimeString()}. Only encrypted data is uploaded — your master password never leaves this device.`
        : "Only encrypted data is uploaded — your master password never leaves this device, and Apple can't read your cards.")
    : "Add your CloudKit container and API token to sync-config.js, then redeploy. Until then the vault stays on this device only.");
}

function openSync() {
  SHEET_OPEN = true;
  document.getElementById("sync-sheet").hidden = false;
  renderSyncSheet();
  if (CloudSync.isConfigured()) {
    CloudSync.init().then(renderSyncSheet, (e) => setSync("error", e.message));
  }
}
function closeSync() {
  SHEET_OPEN = false;
  document.getElementById("sync-sheet").hidden = true;
}

function cardFaceSmall(c) {
  return `
  <div class="card" style="background:${gradientFor(c.network)}" data-open="${c.id}">
    <div class="sheen"></div>
    <div class="top">
      <div><div class="label">${esc(c.label)}</div><div class="network">${esc(c.network)}</div></div>
      <button class="star-btn" data-fav="${c.id}">${I.star(c.favourite)}</button>
    </div>
    <div class="numrow">
      <span class="num" style="color:${c.accent || "#fff"}">${maskNum(c.number)}</span>
      <button class="oncard-btn" data-copy="number" data-id="${c.id}">${I.copy}</button>
    </div>
    <div class="metarow">
      <div class="field"><span class="k">EXP</span><span class="v">${esc(c.expiry)}</span>
        <button class="oncard-btn" data-copy="expiry" data-id="${c.id}">${I.copy}</button></div>
      <div class="field"><span class="k">CVV</span><span class="v" data-cvv="${c.id}">•••</span>
        <button class="oncard-btn" data-revealcvv="${c.id}">${I.eye(false)}</button>
        <button class="oncard-btn" data-copy="cvv" data-id="${c.id}">${I.copy}</button></div>
    </div>
  </div>`;
}

function section(title, list) {
  if (!list.length) return "";
  return `<div class="section"><div class="section-h">${title} <span>· ${list.length}</span></div>
    <div class="cards">${list.map(cardFaceSmall).join("")}</div></div>`;
}

function viewList() {
  const favs = CARDS.filter((c) => c.favourite);
  const prim = CARDS.filter((c) => !c.favourite && c.type !== "addon");
  const add = CARDS.filter((c) => !c.favourite && c.type === "addon");
  const body = CARDS.length
    ? section("Favourites", favs) + section("Your cards", prim) + section("Add-on cards", add)
    : `<div class="empty">No cards yet.<br/>Tap “Add card” to store your first one.</div>`;
  app().innerHTML = `
    <div class="header">
      <div><h1>Cards</h1><div class="meta">${CARDS.length} saved · offline ready</div></div>
      <div class="hgroup">
        <button class="icon-btn" data-sync>${I.cloud(SYNC.status)}</button>
        <button class="icon-btn" data-lock>${I.lockSm}</button>
      </div>
    </div>
    <div class="scroll">${body}</div>
    <button class="add-tile" data-add><span class="plus">+</span> Add card</button>`;
}

function viewDetail() {
  const c = CARDS.find((x) => x.id === VIEW.cardId);
  if (!c) return go("list");
  app().innerHTML = `
    <button class="back" data-back>${I.back} Cards</button>
    <div class="card big" style="background:${gradientFor(c.network)}">
      <div class="sheen"></div>
      <div class="top"><div><div class="label">${esc(c.label)}</div><div class="network">${esc(c.network)}</div></div><div class="chip"></div></div>
      <div class="num big" style="color:${c.accent || "#fff"}" data-num>${maskNum(c.number)}</div>
      <div class="bottom"><div class="v">${esc(c.name)}</div><div class="v">${esc(c.expiry)}</div></div>
    </div>
    <div class="rows">
      <div class="row"><div><div class="k">Card number</div><div class="v" data-fnum>${maskNum(c.number)}</div></div>
        <div class="acts"><button class="icon-btn" data-toggle="num">${I.eyeD(false)}</button><button class="icon-btn" data-copy="number" data-id="${c.id}">${I.copyGold}</button></div></div>
      <div class="row"><div><div class="k">Expiry</div><div class="v">${esc(c.expiry)}</div></div>
        <div class="acts"><button class="icon-btn" data-copy="expiry" data-id="${c.id}">${I.copyGold}</button></div></div>
      <div class="row"><div><div class="k">CVV</div><div class="v" data-fcvv>•••</div></div>
        <div class="acts"><button class="icon-btn" data-toggle="cvv">${I.eyeD(false)}</button><button class="icon-btn" data-copy="cvv" data-id="${c.id}">${I.copyGold}</button></div></div>
      <div class="row"><div><div class="k">Cardholder</div><div class="v">${esc(c.name)}</div></div></div>
      <div class="row" style="border:none"><button class="link" data-edit="${c.id}">Edit</button>
        <button class="link danger" data-del="${c.id}">Delete card</button></div>
    </div>`;
}

function viewForm(editId) {
  const c = editId ? CARDS.find((x) => x.id === editId) : null;
  const netOpts = NETWORKS.map((n) => `<option ${c && c.network === n ? "selected" : ""}>${n}</option>`).join("");
  app().innerHTML = `
    <button class="back" data-back>${I.back} Cancel</button>
    <div class="title-lg" style="text-align:left;margin-bottom:18px">${c ? "Edit card" : "New card"}</div>
    <div class="form">
      <label class="fld"><span>Card label</span><input id="f-label" value="${c ? esc(c.label) : ""}" placeholder="e.g. HDFC Infinia"/></label>
      <label class="fld"><span>Network</span>
        <select id="f-network" style="background:var(--ink2);border:1px solid var(--line);border-radius:12px;padding:13px 15px;color:var(--txt);font-family:var(--sans);font-size:16px;">${netOpts}</select></label>
      <label class="fld"><span>Card number</span><input id="f-number" class="mono" inputmode="numeric" value="${c ? esc(c.number) : ""}" placeholder="0000 0000 0000 0000"/></label>
      <div class="split">
        <label class="fld"><span>Expiry</span><input id="f-expiry" class="mono" value="${c ? esc(c.expiry) : ""}" placeholder="MM/YY"/></label>
        <label class="fld"><span>CVV</span><input id="f-cvv" class="mono" inputmode="numeric" value="${c ? esc(c.cvv) : ""}" placeholder="•••"/></label>
      </div>
      <label class="fld"><span>Cardholder</span><input id="f-name" value="${c ? esc(c.name) : ""}" placeholder="Name on card"/></label>
      <div class="split">
        <div class="toggle ${c && c.favourite ? "on" : ""}" data-t="fav"><span>Favourite</span><div class="sw"><div class="knob"></div></div></div>
        <div class="toggle ${c && c.type === "addon" ? "on" : ""}" data-t="addon"><span>Add-on card</span><div class="sw"><div class="knob"></div></div></div>
      </div>
      <div class="err" id="f-err"></div>
    </div>
    <button class="btn-primary" data-save="${editId || ""}" style="margin-top:14px">${c ? "Save changes" : "Save card"}</button>`;
}

function viewSetup() {
  app().innerHTML = `
    <div class="center">
      <div class="lock-badge">${I.lock}</div>
      <div><div class="title-lg">Create your vault</div><div class="sub">Set a master password to encrypt your cards</div></div>
      <div class="stack">
        <input id="s-pw" type="password" placeholder="Master password" />
        <input id="s-pw2" type="password" placeholder="Confirm password" />
        <div class="toggle on" data-t="face" id="s-face"><span>Enable Face ID unlock</span><div class="sw"><div class="knob"></div></div></div>
        <div class="err" id="s-err"></div>
        <button class="btn-primary" id="s-create">Create vault</button>
        <button class="link" data-sync>Already have a vault? Restore from iCloud</button>
        <div class="hint">Your password is the only way to recover the vault if Face ID is ever removed. There is no reset — keep it safe.</div>
      </div>
    </div>`;
}

function viewLock() {
  const hasFace = !!(META && META.prf);
  app().innerHTML = `
    <div class="center">
      <div class="lock-badge">${I.lock}</div>
      <div><div class="title-lg">Vault locked</div><div class="sub">Unlock to view your cards</div></div>
      <div class="stack">
        ${hasFace ? `<button class="btn-primary" id="u-face">${I.face}&nbsp; Unlock with Face ID</button>` : ""}
        <div id="pw-wrap" ${hasFace ? 'style="display:none"' : ""}>
          <input id="u-pw" type="password" placeholder="Master password" />
          <button class="btn-primary" id="u-pw-go" style="margin-top:12px">Unlock</button>
        </div>
        ${hasFace ? `<button class="link" id="u-usepw">Use master password</button>` : ""}
        <div class="err" id="u-err"></div>
      </div>
    </div>`;
}

function render() {
  if (VIEW.name === "boot") return;
  if (!META) return viewSetup();
  if (!DEK) return viewLock();
  if (VIEW.name === "detail") return viewDetail();
  if (VIEW.name === "add") return viewForm(null);
  if (VIEW.name === "edit") return viewForm(VIEW.cardId);
  return viewList();
}

/* ---------- event delegation ---------- */
document.addEventListener("click", async (e) => {
  const t = e.target.closest("[data-open],[data-fav],[data-copy],[data-revealcvv],[data-lock],[data-add],[data-back],[data-toggle],[data-edit],[data-del],[data-t],[data-save],[data-sync],#s-create,#u-face,#u-usepw,#u-pw-go,#sync-close,#sync-now,#sync-restore,#sync-take-cloud,#sync-take-local,#sync-wipe-cloud,#sync-wipe-local,#sync-diag-copy");
  if (!t) return;

  /* ----- sync sheet ----- */
  if (t.hasAttribute("data-sync")) return openSync();
  if (t.id === "sync-close") return closeSync();
  if (t.id === "sync-now") return void syncNow();
  if (t.id === "sync-restore" || t.id === "sync-take-cloud") {
    if (META && !confirm("Replace this device's vault with the iCloud copy? Anything saved only on this device will be lost.")) return;
    setSync("syncing");
    try {
      await restoreFromCloud();
      setSync("ok");
      closeSync();
      toast("Restored from iCloud");
      render(); // now shows the lock screen for the restored vault
    } catch (ex) { setSync("error", ex.message || "Restore failed."); }
    return;
  }
  if (t.id === "sync-diag-copy") {
    const box = document.getElementById("sync-diag");
    box.focus(); box.select();
    return copy(box.value, "Diagnostics");
  }
  if (t.id === "sync-wipe-cloud") {
    if (!confirm("Delete the vault stored in iCloud? This device keeps its own copy.")) return;
    setSync("syncing");
    try {
      await CloudSync.init();
      if (!CloudSync.signedIn()) throw new Error("Sign in to iCloud first.");
      await CloudSync.deleteRemote();
      setSync("idle");
      toast("iCloud copy deleted");
    } catch (ex) { setSync("error", ex.message || "Delete failed."); }
    return;
  }
  if (t.id === "sync-wipe-local") {
    if (!confirm("Erase this device's vault? Every card, the master password and Face ID unlock are removed permanently. This cannot be undone.")) return;
    if (!confirm("Last check — this is irreversible. Erase everything on this device?")) return;
    await idbClear();
    META = null; DEK = null; CARDS = []; DELETED = [];
    closeSync();
    toast("Vault erased");
    return go("list"); // no META now, so this lands on the setup screen
  }
  if (t.id === "sync-take-local") {
    if (!confirm("Replace the iCloud copy with this device's vault? The vault currently in iCloud will be lost.")) return;
    setSync("syncing");
    try { await overwriteCloud(); setSync("ok"); toast("iCloud updated"); }
    catch (ex) { setSync("error", ex.message || "Upload failed."); }
    return;
  }

  // list: open card
  if (t.dataset.open && !e.target.closest("[data-fav],[data-copy],[data-revealcvv]")) return go("detail", t.dataset.open);

  // favourite toggle
  if (t.dataset.fav) {
    const c = CARDS.find((x) => x.id === t.dataset.fav);
    c.favourite = !c.favourite; c.updatedAt = Date.now();
    await saveVault(); render(); return;
  }

  // copy fields
  if (t.dataset.copy) {
    const c = CARDS.find((x) => x.id === t.dataset.id);
    const map = { number: c.number, expiry: c.expiry, cvv: c.cvv };
    const labels = { number: "Number", expiry: "Expiry", cvv: "CVV" };
    return copy(map[t.dataset.copy], labels[t.dataset.copy]);
  }

  // reveal cvv on list card
  if (t.dataset.revealcvv) {
    const c = CARDS.find((x) => x.id === t.dataset.revealcvv);
    const span = document.querySelector(`[data-cvv="${c.id}"]`);
    const shown = span.textContent !== "•••";
    span.textContent = shown ? "•••" : c.cvv;
    t.innerHTML = I.eye(!shown);
    return;
  }

  if (t.hasAttribute("data-lock")) return lock();
  if (t.hasAttribute("data-add")) return go("add");
  if (t.hasAttribute("data-back")) return go(DEK && VIEW.name !== "list" ? "list" : "list");
  if (t.dataset.edit) return go("edit", t.dataset.edit);

  // detail reveal toggles
  if (t.dataset.toggle) {
    const c = CARDS.find((x) => x.id === VIEW.cardId);
    if (t.dataset.toggle === "num") {
      const el = document.querySelector("[data-fnum]");
      const shown = el.textContent === c.number;
      el.textContent = shown ? maskNum(c.number) : c.number;
      document.querySelector("[data-num]").textContent = shown ? maskNum(c.number) : c.number;
      t.innerHTML = I.eyeD(!shown);
    } else {
      const el = document.querySelector("[data-fcvv]");
      const shown = el.textContent === c.cvv;
      el.textContent = shown ? "•••" : c.cvv;
      t.innerHTML = I.eyeD(!shown);
    }
    return;
  }

  // delete
  if (t.dataset.del) {
    if (!confirm("Delete this card permanently?")) return;
    CARDS = CARDS.filter((x) => x.id !== t.dataset.del);
    // Tombstone, so the deletion propagates instead of the card coming back.
    DELETED = DELETED.filter((x) => x.id !== t.dataset.del).concat({ id: t.dataset.del, at: Date.now() });
    await saveVault(); return go("list");
  }

  // form toggles
  if (t.dataset.t) { t.classList.toggle("on"); return; }

  // save card
  if (t.hasAttribute("data-save")) {
    const g = (id) => document.getElementById(id).value.trim();
    const label = g("f-label"), number = g("f-number");
    if (!label || !number) { document.getElementById("f-err").textContent = "Label and card number are required."; return; }
    const prev = t.dataset.save ? CARDS.find((x) => x.id === t.dataset.save) : null;
    const now = Date.now();
    const rec = {
      id: t.dataset.save || uid(),
      label, network: document.getElementById("f-network").value,
      number, expiry: g("f-expiry"), cvv: g("f-cvv"), name: g("f-name"),
      favourite: document.querySelector('[data-t="fav"]').classList.contains("on"),
      type: document.querySelector('[data-t="addon"]').classList.contains("on") ? "addon" : "primary",
      accent: "#fff",
      createdAt: (prev && prev.createdAt) || now,
      updatedAt: now,
    };
    if (prev) {
      CARDS[CARDS.findIndex((x) => x.id === t.dataset.save)] = rec;
    } else CARDS.push(rec);
    await saveVault(); toast("Saved"); return go("list");
  }

  // setup: create vault
  if (t.id === "s-create") {
    const pw = document.getElementById("s-pw").value, pw2 = document.getElementById("s-pw2").value;
    const err = document.getElementById("s-err");
    if (pw.length < 6) return (err.textContent = "Password must be at least 6 characters.");
    if (pw !== pw2) return (err.textContent = "Passwords don't match.");
    const face = document.getElementById("s-face").classList.contains("on");
    t.textContent = "Creating…"; t.disabled = true;
    try {
      await setupVault(pw, face);
      go("list");
    } catch (ex) {
      // If Face ID enrolment failed, fall back to password-only vault.
      try { await setupVault(pw, false); toast("Created without Face ID"); go("list"); }
      catch (e2) { err.textContent = e2.message || "Could not create vault."; t.disabled = false; t.textContent = "Create vault"; }
    }
    return;
  }

  // unlock: face id
  if (t.id === "u-face") {
    const err = document.getElementById("u-err");
    try { await unlockWithFaceId(); go("list"); }
    catch (ex) { err.textContent = ex.message || "Face ID failed. Try your password."; }
    return;
  }
  if (t.id === "u-usepw") { document.getElementById("pw-wrap").style.display = "block"; t.style.display = "none"; return; }
  if (t.id === "u-pw-go") {
    const err = document.getElementById("u-err");
    try { await unlockWithPassword(document.getElementById("u-pw").value); go("list"); }
    catch (ex) { err.textContent = "Wrong password."; }
    return;
  }
});

// submit password on Enter
document.addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  const go = document.getElementById("u-pw-go");
  if (go && document.getElementById("pw-wrap").style.display !== "none") go.click();
});

/* Signing in to iCloud hands off to Apple and backgrounds the app, which would
   otherwise trip the auto-lock. Grant a short, user-initiated grace period. */
let AUTH_UNTIL = 0;
document.addEventListener("click", (e) => {
  if (e.target.closest("#sync-auth-wrap")) AUTH_UNTIL = Date.now() + 120000;
});

/* auto-lock when app is hidden/backgrounded */
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) { AUTH_UNTIL = 0; return; }
  if (DEK && Date.now() > AUTH_UNTIL) lock();
});

window.addEventListener("online", () => scheduleSync());

/* ---------- boot ---------- */
(async function boot() {
  // Browsers evict "script-writable" storage from idle sites, which for this
  // app means the vault itself. Ask to be exempt; ignored where unsupported.
  if (navigator.storage && navigator.storage.persist) {
    navigator.storage.persist().catch(() => {});
  }

  await loadMeta();
  VIEW = { name: "list", cardId: null };
  render();

  if (CloudSync.isConfigured()) {
    CloudSync.onChange(() => {
      renderSyncSheet();
      // A fresh sign-in is the moment to reconcile with iCloud.
      if (CloudSync.signedIn() && META) scheduleSync();
      else if (!CloudSync.signedIn()) setSync("signedout");
    });
    CloudSync.init().then(
      () => { if (META) syncNow().catch(() => {}); },
      () => setSync("error", "iCloud unavailable offline.")
    );
  }

  if ("serviceWorker" in navigator) {
    try { await navigator.serviceWorker.register("./service-worker.js"); } catch {}
  }
})();
