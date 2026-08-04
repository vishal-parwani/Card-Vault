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
      /* "platform" pins this to the device's own authenticator — Face ID. Left
         open, the credential could also live on a security key or a nearby
         phone, and Safari then has to ask which one you meant every time. */
      authenticatorSelection: { userVerification: "required", residentKey: "preferred", authenticatorAttachment: "platform" },
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
      /* Naming the transport is what removes the extra "use a passkey" tap.
         Without it Safari can't tell that the credential is on this device, so
         it offers the choice — security key, nearby device, this iPhone —
         before it will run Face ID. "internal" says there is only one answer.
         `hints` says the same thing to browsers that read it; both are ignored
         where unsupported, and neither needs the passkey to be re-enrolled. */
      allowCredentials: [{ type: "public-key", id: unb64(credId), transports: ["internal"] }],
      hints: ["client-device"],
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
function lock() { cancelAutoLock(); DEK = null; CARDS = []; DELETED = []; SEARCH = ""; render(); }

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
    META.prf = { credId, device: deviceId(), wrapped: await wrap(await prfKek(bytes), DEK) };
  }
  CARDS = []; DELETED = [];
  await saveVault();
}
/* A stable per-device id, held outside the vault so it never syncs. Lets us
   tell "this device's passkey" from one inherited via a restore — the latter
   belongs to another device and will always fail here. */
const DEVICE_KEY = "cardvault.deviceId";
function deviceId() {
  try {
    let id = localStorage.getItem(DEVICE_KEY);
    if (!id) { id = uid() + uid(); localStorage.setItem(DEVICE_KEY, id); }
    return id;
  } catch { return "no-storage"; }
}
function faceIdIsLocal() { return !!(META && META.prf && META.prf.device === deviceId()); }

/* Two ways to get Face ID working here:
     link  — the vault already carries a passkey and iCloud Keychain has synced
             it to this device, so it can be used as-is. No new credential.
     register — no usable passkey, so enrol a fresh one.
   Linking is tried first, which is what stops a reinstall from leaving a trail
   of orphaned passkeys for the same site. */
async function enableFaceId() {
  if (META && META.prf && META.prf.credId) {
    try {
      const bytes = await getPrfBytes(META.prf.credId);
      META.prf = {
        credId: META.prf.credId,
        device: deviceId(),
        wrapped: await wrap(await prfKek(bytes), DEK),
      };
      await idbSet("meta", META);
      return "linked";
    } catch (e) {
      // Passkey isn't available here (never synced, or removed) — enrol instead.
      console.warn("[CardVault] couldn't link existing passkey:", e);
    }
  }
  await addFaceId();
  return "registered";
}

async function addFaceId() {
  const credId = await registerPasskey();
  const bytes = await getPrfBytes(credId);
  META.prf = { credId, device: deviceId(), wrapped: await wrap(await prfKek(bytes), DEK) };
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

/* Restore driven from the first screen. Signs in if needed (which navigates
   away and comes back), pulls the vault, then tries the passkey that came with
   it — so a device whose iCloud Keychain has the passkey never sees a password
   prompt. Falls back to the password only when Face ID genuinely can't work. */
const RESTORE_INTENT = "cardvault.restoreIntent";

async function restoreFlow() {
  const err = document.getElementById("w-err");
  const say = (m) => { if (err) err.textContent = m; };
  try {
    say("");
    await CloudSync.init();
    if (!CloudSync.signedIn()) {
      try { localStorage.setItem(RESTORE_INTENT, "1"); } catch {}
      return CloudSync.signIn(); // leaves the page; boot picks it up on return
    }
    await restoreFromCloud();
    await finishRestore();
  } catch (ex) {
    say((ex && ex.message) || "Couldn't restore from iCloud.");
  }
}

/* After the vault lands, unlock with the inherited passkey if this device can.
   Success also marks it local, so the lock screen offers Face ID from then on. */
async function finishRestore() {
  try { localStorage.removeItem(RESTORE_INTENT); } catch {}
  if (META && META.prf && META.prf.credId) {
    try {
      await unlockWithFaceId();
      META.prf.device = deviceId();
      await idbSet("meta", META);
      toast("Unlocked with Face ID");
      return go("list");
    } catch (e) {
      console.warn("[CardVault] inherited passkey unusable here:", e);
    }
  }
  render(); // lock screen; password, then the Face ID prompt once unlocked
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
  /* Built from the Cards Tracker accents — indigo, terracotta, sage, amber —
     rather than the old near-blacks, so a card reads as a coloured object
     sitting on the cream page instead of a hole punched through it. Each keeps
     enough of its network's identity to stay recognisable at a glance. */
  "Diners Club":      "linear-gradient(135deg,#5c3d2e 0%,#7a5642 55%,#3d2b1f 100%)",
  "Visa":             "linear-gradient(135deg,#5b5070 0%,#7a6b8f 55%,#463d57 100%)",
  "Mastercard":       "linear-gradient(135deg,#4f6f55 0%,#6b8f71 55%,#3c5741 100%)",
  "American Express": "linear-gradient(135deg,#a86844 0%,#c4845a 55%,#8a5436 100%)",
  "RuPay":            "linear-gradient(135deg,#a5801f 0%,#c49a3c 55%,#856717 100%)",
  "Other":            "linear-gradient(135deg,#6b5647 0%,#8a7365 55%,#4f3f34 100%)",
};
const NETWORKS = Object.keys(GRADIENTS);
function gradientFor(network) { return GRADIENTS[network] || GRADIENTS.Other; }

/* Issuer network from the card number's leading digits. Only the network
   family is knowable offline — the product tier (Platinum, Infinite, …) lives
   in an issuer database, so it is never guessed here. Returns null rather than
   "Other" when unsure, so an uncertain guess never overwrites a real choice.
   Discover's ranges are read as RuPay: Discover isn't offered, and the overlap
   (60/65) is RuPay in practice for this vault. */
function detectNetwork(num) {
  const d = String(num || "").replace(/\D/g, "");
  if (d.length < 2) return null;
  if (/^4/.test(d)) return "Visa";
  if (/^3[47]/.test(d)) return "American Express";
  if (/^5[1-5]/.test(d)) return "Mastercard";
  if (d.length >= 4) {
    const four = parseInt(d.slice(0, 4), 10);
    if (four >= 2221 && four <= 2720) return "Mastercard"; // newer Mastercard range
  }
  if (/^(36|38|39|30[0-5])/.test(d)) return "Diners Club";
  if (/^(60|65|81|82|508)/.test(d)) return "RuPay";
  return null;
}

/* ---------- helpers ---------- */
const digitsOf = (s) => String(s || "").replace(/\D/g, "");

/* Group a number for display. Whatever spacing it was typed or imported with is
   ignored, so a hand-entered card and a LastPass one look identical. Grouping
   follows the number itself rather than the stored network label, which can be
   wrong: Amex is 4-6-5, 14-digit Diners is 4-6-4, everything else is fours.
   Purely visual — the spaces are never part of what gets copied. */
function groupNum(num) {
  const d = digitsOf(num);
  if (!d) return String(num || "").trim();
  const out = [];
  const sizes = d.length === 15 && /^3[47]/.test(d) ? [4, 6, 5]
              : d.length === 14 ? [4, 6, 4]
              : null;
  if (sizes) {
    let i = 0;
    for (const n of sizes) { out.push(d.slice(i, i + n)); i += n; }
    if (i < d.length) out.push(d.slice(i)); // anything unexpected still shows
  } else {
    for (let i = 0; i < d.length; i += 4) out.push(d.slice(i, i + 4));
  }
  return out.filter(Boolean).join(" ");
}

// Same grouping, with every group but the last replaced by dots of equal width.
function maskNum(num) {
  const g = groupNum(num);
  if (!g) return g;
  const parts = g.split(" ");
  if (parts.length < 2) return parts[0].length > 4 ? "•••• " + parts[0].slice(-4) : g;
  return parts.map((p, i) => (i === parts.length - 1 ? p : "•".repeat(p.length))).join(" ");
}
function esc(s) { return (s || "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);

/* ---------- LastPass import ----------
   LastPass exports payment cards as secure notes: one CSV row per item, with
   the card fields packed as "Key:value" lines inside the quoted `extra`
   column. Parsing happens entirely in this page — the CSV is never uploaded.
*/

// Full RFC4180-ish parse: fields may be quoted and contain commas, newlines
// and doubled quotes, all of which LastPass emits.
function parseCSV(text) {
  const rows = [];
  let row = [], field = "", inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else field += ch;
      continue;
    }
    if (ch === '"') { inQuotes = true; continue; }
    if (ch === ",") { row.push(field); field = ""; continue; }
    if (ch === "\n") { row.push(field); rows.push(row); row = []; field = ""; continue; }
    if (ch === "\r") continue;
    field += ch;
  }
  if (field !== "" || row.length) { row.push(field); rows.push(row); }
  return rows;
}

const LP_MONTHS = {
  january: 1, february: 2, march: 3, april: 4, may: 5, june: 6,
  july: 7, august: 8, september: 9, october: 10, november: 11, december: 12,
};

// LastPass writes "January,2029" (or "01,2029"); empty is ",".
function lpExpiry(raw) {
  const parts = String(raw || "").split(",").map((x) => x.trim());
  if (parts.length < 2) return "";
  const [m, y] = parts;
  if (!m || !y) return "";
  const mm = LP_MONTHS[m.toLowerCase()] || parseInt(m, 10);
  if (!mm || mm < 1 || mm > 12) return "";
  return String(mm).padStart(2, "0") + "/" + String(y).trim().slice(-2);
}

function lpNetwork(type, number) {
  const t = String(type || "").toLowerCase();
  if (t.includes("visa")) return "Visa";
  if (t.includes("master")) return "Mastercard";
  if (t.includes("amex") || t.includes("american")) return "American Express";
  if (t.includes("diner")) return "Diners Club";
  if (t.includes("rupay")) return "RuPay";
  return detectNetwork(number) || "Other"; // fall back to the number itself
}

/* "Notes:" is the last key and its value runs to the end of the block, over as
   many lines as the user wrote. Split there first, so a note containing
   something like "Type: personal" can't be misread as a card field. */
function lpSplit(extra) {
  const s = String(extra || "");
  const m = s.match(/(^|\n)Notes:/);
  if (!m) return { head: s, notes: "" };
  return { head: s.slice(0, m.index), notes: s.slice(m.index + m[0].length).trim() };
}

// Turn the "Key:value" block inside `extra` into a lookup.
function lpFields(extra) {
  const out = {};
  for (const line of String(extra || "").split("\n")) {
    const i = line.indexOf(":");
    if (i < 1) continue;
    out[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  return out;
}

/* LastPass files these under "Payment Cards" in its UI, but exports them as
   secure notes. The note type has been spelled a few ways across versions, so
   rather than rely on one label, also accept any entry carrying both a card
   number and a security code — a shape nothing else in the export has. */
function looksLikeCard(extra) {
  const s = String(extra || "");
  if (/notetype\s*:\s*(credit\s*card|payment\s*cards?|bank\s*card)/i.test(s)) return true;
  return /(^|\n)\s*Number\s*:\s*[0-9 -]{8,}/i.test(s) &&
         /(^|\n)\s*Security Code\s*:/i.test(s);
}

/* LastPass has no notion of an add-on/supplementary card, so it can only be
   guessed from what the user wrote. A guess is safe here: it only preselects a
   toggle that is one tap to correct. */
function lpIsAddon(text) {
  return /\b(add[- ]?on|addon|supplementary|supplementry|suppl)\b/i.test(text || "");
}

/* Returns { cards, skipped, total } — cards ready to merge, skipped counting
   entries that duplicate a number already in the vault. */
function parseLastPass(text, existing) {
  const rows = parseCSV(text);
  if (!rows.length) return { cards: [], skipped: 0, total: 0 };
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const col = (n) => header.indexOf(n);
  const iName = col("name"), iExtra = col("extra"), iFav = col("fav");
  if (iExtra < 0) return { cards: [], skipped: 0, total: 0 };

  const seen = new Set((existing || []).map((c) => String(c.number || "").replace(/\D/g, "")).filter(Boolean));
  const cards = [];
  let total = 0, skipped = 0;
  const now = Date.now();

  for (let r = 1; r < rows.length; r++) {
    const extra = rows[r][iExtra] || "";
    if (!looksLikeCard(extra)) continue;
    total++;
    const { head, notes } = lpSplit(extra);
    const f = lpFields(head);
    const number = (f["number"] || "").trim();
    const digits = number.replace(/\D/g, "");
    if (!digits) { skipped++; continue; }
    if (seen.has(digits)) { skipped++; continue; }
    seen.add(digits);
    cards.push({
      id: uid(),
      label: (iName >= 0 && rows[r][iName]) || f["name on card"] || "Imported card",
      network: lpNetwork(f["type"], number),
      number,
      expiry: lpExpiry(f["expiration date"]),
      cvv: (f["security code"] || "").trim(),
      name: (f["name on card"] || "").trim(),
      notes,
      favourite: iFav >= 0 && String(rows[r][iFav]).trim() === "1",
      type: lpIsAddon(`${(iName >= 0 && rows[r][iName]) || ""} ${notes}`) ? "addon" : "primary",
      accent: "#fff",
      createdAt: now,
      updatedAt: now,
    });
  }
  return { cards, skipped, total };
}

/* A card is valid through the end of its expiry month. Unparseable or missing
   expiry counts as active — better to offer it than to hide it. */
function cardExpired(expiry, now = new Date()) {
  const m = String(expiry || "").match(/^(\d{1,2})\s*\/\s*(\d{2}|\d{4})$/);
  if (!m) return false;
  const mm = parseInt(m[1], 10);
  if (mm < 1 || mm > 12) return false;
  const yy = m[2].length === 2 ? 2000 + parseInt(m[2], 10) : parseInt(m[2], 10);
  return now >= new Date(yy, mm, 1); // first day of the month after expiry
}

/* Why a card shouldn't be imported by default — "" means it's fine. LastPass
   has no active/closed flag, so this reads the expiry and any wording the user
   left behind. It only unticks a box, so a wrong call costs one tap. */
function importReason(c, now = new Date()) {
  if (cardExpired(c.expiry, now)) return "expired " + c.expiry;
  if (/\b(closed|cancell?ed|deactivated|inactive|blocked|surrendered|replaced)\b/i.test(`${c.label} ${c.notes || ""}`)) {
    return "looks closed";
  }
  return "";
}

let PENDING_IMPORT = [];

async function importLastPassFile(file) {
  return importLastPassText(await file.text());
}

async function importLastPassText(text) {
  const { cards, skipped, total } = parseLastPass(text, CARDS);
  if (!total) {
    alert("No payment cards found in that export.\n\nExport from the LastPass web vault on a computer (the phone app can't export): sidebar → Advanced Options → Export → LastPass CSV File.");
    return;
  }
  if (!cards.length) {
    toast(`Already have all ${skipped} card${skipped === 1 ? "" : "s"}`);
    return;
  }
  PENDING_IMPORT = cards.map((c) => ({ ...c, reason: importReason(c) }));
  showImportPicker(skipped);
}

// The summary line for one row, recomputed whenever its fields are edited.
function pickSummary(c) {
  return `${esc(c.network)} · ${esc(maskNum(c.number))}${c.expiry ? " · " + esc(c.expiry) : ""}` +
         `${c.type === "addon" ? " · add-on" : ""}` +
         `${c.reason ? ` · <span class="pick-warn">${esc(c.reason)}</span>` : ""}`;
}

function pickRowHTML(c, i) {
  const netOpts = NETWORKS.map((n) => `<option ${c.network === n ? "selected" : ""}>${n}</option>`).join("");
  return `
  <div class="pick-item" data-item="${i}">
    <div class="pick-row${c.reason ? " off" : ""}">
      <input type="checkbox" data-pick="${i}" ${c.reason ? "" : "checked"} aria-label="Import this card" />
      <span class="pick-body">
        <span class="pick-main" data-main="${i}">${esc(c.label)}</span>
        <span class="pick-sub" data-sub="${i}">${pickSummary(c)}</span>
      </span>
      <button class="pick-edit" data-editrow="${i}">Edit</button>
    </div>
    <div class="pick-form" data-form="${i}" hidden>
      <label>Label<input data-f="label" data-i="${i}" value="${esc(c.label)}" /></label>
      <label>Network<select data-f="network" data-i="${i}">${netOpts}</select></label>
      <label>Card number<input class="mono" data-f="number" data-i="${i}" inputmode="numeric" value="${esc(c.number)}" /></label>
      <div class="pick-split">
        <label>Expiry<input class="mono" data-f="expiry" data-i="${i}" value="${esc(c.expiry)}" placeholder="MM/YY" /></label>
        <label>CVV<input class="mono" data-f="cvv" data-i="${i}" inputmode="numeric" value="${esc(c.cvv)}" /></label>
      </div>
      <label>Cardholder<input data-f="name" data-i="${i}" value="${esc(c.name)}" /></label>
      <label>Notes<textarea rows="2" data-f="notes" data-i="${i}">${esc(c.notes || "")}</textarea></label>
      <label class="pick-check"><input type="checkbox" data-f="addon" data-i="${i}" ${c.type === "addon" ? "checked" : ""} /> Add-on card</label>
    </div>
  </div>`;
}

// Re-render just the summary of row i after an edit, including its reason.
function refreshPickRow(i) {
  const c = PENDING_IMPORT[i];
  c.reason = importReason(c);
  const main = document.querySelector(`[data-main="${i}"]`);
  const sub = document.querySelector(`[data-sub="${i}"]`);
  const row = document.querySelector(`[data-item="${i}"] .pick-row`);
  if (main) main.textContent = c.label;
  if (sub) sub.innerHTML = pickSummary(c);
  if (row) row.classList.toggle("off", !!c.reason);
}

function showImportPicker(skipped) {
  document.getElementById("import-list").innerHTML =
    PENDING_IMPORT.map((c, i) => pickRowHTML(c, i)).join("");

  const inactive = PENDING_IMPORT.filter((c) => c.reason).length;
  document.getElementById("import-summary").textContent =
    `Found ${PENDING_IMPORT.length} card${PENDING_IMPORT.length === 1 ? "" : "s"}` +
    (skipped ? `, ${skipped} already in your vault` : "") +
    (inactive ? `. ${inactive} look inactive and are unticked — tick any you still want.` : ".");

  document.getElementById("import-choose").hidden = true;
  document.getElementById("import-pick").hidden = false;
  updateImportCount();
}

function pickedIndexes() {
  return [...document.querySelectorAll("#import-list input[data-pick]")]
    .filter((el) => el.checked).map((el) => Number(el.dataset.pick));
}
function updateImportCount() {
  const n = pickedIndexes().length;
  const btn = document.getElementById("import-commit");
  btn.textContent = n ? `Import ${n} card${n === 1 ? "" : "s"}` : "Import";
  btn.disabled = !n;
}

async function commitImport() {
  const chosen = pickedIndexes().map((i) => {
    const { reason, ...card } = PENDING_IMPORT[i]; // reason is UI-only
    return card;
  });
  if (!chosen.length) return;
  CARDS = CARDS.concat(chosen);
  PENDING_IMPORT = [];
  await saveVault();
  closeImport();
  render();
  toast(`Imported ${chosen.length} card${chosen.length === 1 ? "" : "s"}`);
}

/* ---------- SVG icons ---------- */
const I = {
  lock: `<svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#c4845a" stroke-width="1.6"><rect x="4" y="10" width="16" height="10" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>`,
  lockSm: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9c8374" stroke-width="1.7"><rect x="4" y="10" width="16" height="10" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>`,
  faceGold: `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#c4845a" stroke-width="1.8"><path d="M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2"/><path d="M9 10v1M15 10v1M9 15c1 1 5 1 6 0"/></svg>`,
  face: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fff8f2" stroke-width="1.8"><path d="M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2"/><path d="M9 10v1M15 10v1M9 15c1 1 5 1 6 0"/></svg>`,
  copy: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.85)" stroke-width="1.7"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>`,
  copyGold: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#c4845a" stroke-width="1.6"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>`,
  eye: (on) => `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.85)" stroke-width="1.7"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/>${on ? '<circle cx="12" cy="12" r="3"/>' : '<line x1="3" y1="3" x2="21" y2="21"/>'}</svg>`,
  eyeD: (on) => `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9c8374" stroke-width="1.6"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/>${on ? '<circle cx="12" cy="12" r="3"/>' : '<line x1="3" y1="3" x2="21" y2="21"/>'}</svg>`,
  star: (on) => `<svg width="15" height="15" viewBox="0 0 24 24" fill="${on ? "#c4845a" : "none"}" stroke="${on ? "#c4845a" : "rgba(255,255,255,0.7)"}" stroke-width="1.6"><path d="M12 2l2.9 6.3 6.9.8-5.1 4.7 1.4 6.8L12 17.8 5.9 20.4l1.4-6.8L2.2 9.1l6.9-.8L12 2z"/></svg>`,
  back: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9c8374" stroke-width="2"><path d="M15 18l-6-6 6-6"/></svg>`,
  caret: `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M9 6l6 6-6 6"/></svg>`,
  search: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#9c8374" stroke-width="1.9"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>`,
  cloud: (status) => {
    const c = status === "ok" ? "#c4845a" : status === "error" || status === "fork" ? "#c0603a" : "#9c8374";
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

function go(name, cardId = null) { VIEW = { name, cardId }; render(); reassertUpdateBar(); }

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
  show("ck-signin", configured && !CloudSync.signedIn());
  show("ck-signout", configured && CloudSync.signedIn());
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

function openImport() {
  PENDING_IMPORT = [];
  document.getElementById("import-pick").hidden = true;
  document.getElementById("import-choose").hidden = false;
  document.getElementById("import-sheet").hidden = false;
}
function closeImport() {
  const sheet = document.getElementById("import-sheet");
  if (sheet) sheet.hidden = true;
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
      <span class="num" style="color:${c.accent || "#fff"}" data-listnum="${c.id}">${maskNum(c.number)}</span>
      <div class="numacts">
        <button class="oncard-btn" data-reveal="${c.id}" aria-label="Show number and CVV">${I.eye(false)}</button>
        <button class="oncard-btn" data-copy="number" data-id="${c.id}">${I.copy}</button>
      </div>
    </div>
    <div class="metarow">
      <div class="field"><span class="k">EXP</span><span class="v">${esc(c.expiry)}</span>
        <button class="oncard-btn" data-copy="expiry" data-id="${c.id}">${I.copy}</button></div>
      <div class="field"><span class="k">CVV</span><span class="v" data-cvv="${c.id}">•••</span>
        <button class="oncard-btn" data-copy="cvv" data-id="${c.id}">${I.copy}</button></div>
    </div>
  </div>`;
}

/* ---------- list: search, collapsing, manual order ---------- */
let SEARCH = "";

/* Which sections are folded away is a per-device view preference, not vault
   content, so it lives in localStorage and never syncs. */
const COLLAPSE_KEY = "cardvault.collapsed";
function collapsedSet() {
  try { return new Set(JSON.parse(localStorage.getItem(COLLAPSE_KEY) || "[]")); }
  catch { return new Set(); }
}
function toggleCollapsed(key) {
  const s = collapsedSet();
  if (s.has(key)) s.delete(key); else s.add(key);
  try { localStorage.setItem(COLLAPSE_KEY, JSON.stringify([...s])); } catch {}
}

/* Every field you can see on a card is searchable. The number is matched on
   digits alone as well, so "4111 1111" finds a card stored unspaced and an
   unspaced query finds a grouped one. */
function matchesSearch(c, q) {
  if (!q) return true;
  const qd = q.replace(/\D/g, "");
  if (qd.length >= 2 && String(c.number || "").replace(/\D/g, "").includes(qd)) return true;
  return [c.label, c.network, c.name, c.notes, c.expiry, c.number]
    .some((f) => String(f || "").toLowerCase().includes(q));
}

/* Dragged order wins where one has been set; the rest keep the creation order
   the vault already sorts by, so a card never jumps around on its own. */
function bySortOrder(a, b) {
  const ao = Number.isFinite(a.order) ? a.order : Infinity;
  const bo = Number.isFinite(b.order) ? b.order : Infinity;
  if (ao !== bo) return ao - bo;
  return (a.createdAt || 0) - (b.createdAt || 0) || (a.id < b.id ? -1 : 1);
}

function section(key, title, list) {
  if (!list.length) return "";
  // A filtered list is no place to hide matches, so collapsing is ignored then.
  const shut = !SEARCH.trim() && collapsedSet().has(key);
  return `<div class="section">
    <button class="section-h" data-collapse="${key}">
      <span class="caret ${shut ? "" : "open"}">${I.caret}</span>${title} <span class="count">· ${list.length}</span>
    </button>
    <div class="cards" data-cards="${key}" ${shut ? "hidden" : ""}>${list.map(cardFaceSmall).join("")}</div>
  </div>`;
}

function cardsHtml() {
  if (!CARDS.length) return `<div class="empty">No cards yet.<br/>Tap + above to store your first one.</div>`;
  const q = SEARCH.trim().toLowerCase();
  const hits = CARDS.filter((c) => matchesSearch(c, q));
  if (!hits.length) return `<div class="empty">Nothing matches “${esc(SEARCH.trim())}”.</div>`;
  return section("fav", "Favourites", hits.filter((c) => c.favourite).sort(bySortOrder))
    + section("prim", "Your cards", hits.filter((c) => !c.favourite && c.type !== "addon").sort(bySortOrder))
    + section("addon", "Add-on cards", hits.filter((c) => !c.favourite && c.type === "addon").sort(bySortOrder));
}

/* Repaints just the cards. Typing must not re-render the header, or the search
   field would be replaced under the cursor and lose focus on every keystroke. */
function renderCards() {
  const el = document.getElementById("card-scroll");
  if (el) el.innerHTML = cardsHtml();
  const meta = document.getElementById("list-meta");
  if (meta) meta.textContent = listMeta();
}

function listMeta() {
  const q = SEARCH.trim().toLowerCase();
  if (!q) return `${CARDS.length} saved · offline ready`;
  const n = CARDS.filter((c) => matchesSearch(c, q)).length;
  return `${n} of ${CARDS.length} shown`;
}

const FACE_DISMISS_KEY = "cardvault.faceBannerDismissed";
function showFaceBanner() {
  if (!DEK || faceIdIsLocal() || !prfSupportedUA()) return false;
  try { return localStorage.getItem(FACE_DISMISS_KEY) !== "1"; } catch { return true; }
}

function viewList() {
  app().innerHTML = `
    <div class="header">
      <div><h1>Cards</h1><div class="meta" id="list-meta">${listMeta()}</div></div>
      <div class="hgroup">
        <button class="icon-btn" data-add aria-label="Add card"><span class="plus">+</span></button>
        <button class="icon-btn" data-sync>${I.cloud(SYNC.status)}</button>
        <button class="icon-btn" data-lock>${I.lockSm}</button>
      </div>
    </div>
    ${showFaceBanner() ? `
      <div class="banner">
        <div class="banner-txt">
          <div class="banner-t">${I.faceGold} ${META.prf ? "Use Face ID here" : "Turn on Face ID"}</div>
          <div class="banner-s">${META.prf
            ? "This vault came from another device. Link its Face ID to unlock here without your master password."
            : "Unlock without typing your master password."}</div>
        </div>
        <div class="banner-acts">
          <button class="btn-primary" data-facesetup>${META.prf ? "Link Face ID" : "Enable Face ID"}</button>
          <button class="link" data-facedismiss>Not now</button>
        </div>
      </div>` : ""}
    ${CARDS.length ? `
      <div class="search-wrap">
        <span class="search-i">${I.search}</span>
        <input id="card-search" type="search" placeholder="Search cards" value="${esc(SEARCH)}"
               autocomplete="off" autocorrect="off" autocapitalize="none" spellcheck="false" enterkeyhint="search" />
        <button class="search-x" id="search-clear" aria-label="Clear search" ${SEARCH ? "" : "hidden"}>&times;</button>
      </div>` : ""}
    <div class="scroll" id="card-scroll">${cardsHtml()}</div>
    <div class="list-links">
      <button class="link" data-import>Import from LastPass</button>
      ${prfSupportedUA() && !showFaceBanner() ? `<button class="link" data-facesetup>${faceIdIsLocal() ? "Re-enrol" : "Set up"} Face ID here</button>` : ""}
    </div>`;
}

function viewDetail() {
  const c = CARDS.find((x) => x.id === VIEW.cardId);
  if (!c) return go("list");
  app().innerHTML = `
    <button class="back" data-back>${I.back} Cards</button>
    <div class="card big" style="background:${gradientFor(c.network)}">
      <div class="sheen"></div>
      <div class="top"><div><div class="label">${esc(c.label)}</div><div class="network">${esc(c.network)}</div></div><div class="chip"></div></div>
      <div class="num big" style="color:${c.accent || "#fff"}" data-num>${esc(groupNum(c.number))}</div>
      <div class="bottom"><div class="v">${esc(c.name)}</div><div class="v">${esc(c.expiry)}</div></div>
    </div>
    <div class="rows">
      <div class="row"><div><div class="k">Card number</div><div class="v" data-fnum>${esc(groupNum(c.number))}</div></div>
        <div class="acts"><button class="icon-btn" data-toggle="num">${I.eyeD(true)}</button><button class="icon-btn" data-copy="number" data-id="${c.id}">${I.copyGold}</button></div></div>
      <div class="row"><div><div class="k">Expiry</div><div class="v">${esc(c.expiry)}</div></div>
        <div class="acts"><button class="icon-btn" data-copy="expiry" data-id="${c.id}">${I.copyGold}</button></div></div>
      <div class="row"><div><div class="k">CVV</div><div class="v" data-fcvv>${esc(c.cvv)}</div></div>
        <div class="acts"><button class="icon-btn" data-toggle="cvv">${I.eyeD(true)}</button><button class="icon-btn" data-copy="cvv" data-id="${c.id}">${I.copyGold}</button></div></div>
      <div class="row"><div><div class="k">Cardholder</div><div class="v">${esc(c.name)}</div></div></div>
      ${c.notes ? `<div class="row"><div><div class="k">Notes</div><div class="v notes">${esc(c.notes)}</div></div></div>` : ""}
      <div class="row" style="border:none"><button class="link" data-edit="${c.id}">Edit</button>
        <button class="link danger" data-del="${c.id}">Delete card</button></div>
    </div>`;
}

function viewForm(editId) {
  const c = editId ? CARDS.find((x) => x.id === editId) : null;
  numberDigits = c ? String(c.number || "").replace(/\D/g, "").length : 0;
  const netOpts = NETWORKS.map((n) => `<option ${c && c.network === n ? "selected" : ""}>${n}</option>`).join("");
  app().innerHTML = `
    <button class="back" data-back>${I.back} Cancel</button>
    <div class="title-lg" style="text-align:left;margin-bottom:18px">${c ? "Edit card" : "New card"}</div>
    <form class="form" id="card-form" onsubmit="return false" autocomplete="on">
      <label class="fld"><span>Card label</span><input id="f-label" autocomplete="off" value="${c ? esc(c.label) : ""}" placeholder="e.g. HDFC Infinia"/></label>
      <label class="fld"><span>Network</span>
        <select id="f-network" ${c ? 'data-touched="1"' : ""} style="background:var(--ink2);border:1px solid var(--line);border-radius:12px;padding:13px 15px;color:var(--txt);font-family:var(--sans);font-size:16px;">${netOpts}</select></label>
      <label class="fld"><span>Card number</span><input id="f-number" class="mono" inputmode="numeric" autocomplete="cc-number" value="${c ? esc(c.number) : ""}" placeholder="0000 0000 0000 0000"/></label>
      <div class="split">
        <label class="fld"><span>Expiry</span><input id="f-expiry" class="mono" autocomplete="cc-exp" value="${c ? esc(c.expiry) : ""}" placeholder="MM/YY"/></label>
        <label class="fld"><span>CVV</span><input id="f-cvv" class="mono" inputmode="numeric" autocomplete="cc-csc" value="${c ? esc(c.cvv) : ""}" placeholder="•••"/></label>
      </div>
      <label class="fld"><span>Cardholder</span><input id="f-name" autocomplete="cc-name" value="${c ? esc(c.name) : ""}" placeholder="Name on card"/></label>
      <label class="fld"><span>Notes</span><textarea id="f-notes" rows="3" placeholder="Anything else worth remembering">${c ? esc(c.notes) : ""}</textarea></label>
      <div class="split">
        <div class="toggle ${c && c.favourite ? "on" : ""}" data-t="fav"><span>Favourite</span><div class="sw"><div class="knob"></div></div></div>
        <div class="toggle ${c && c.type === "addon" ? "on" : ""}" data-t="addon"><span>Add-on card</span><div class="sw"><div class="knob"></div></div></div>
      </div>
      <div class="err" id="f-err"></div>
    </form>
    <button class="btn-primary" data-save="${editId || ""}" style="margin-top:14px">${c ? "Save changes" : "Save card"}</button>`;
}

function viewWelcome() {
  app().innerHTML = `
    <div class="center">
      <div class="lock-badge">${I.lock}</div>
      <div><div class="title-lg">Card Vault</div><div class="sub">Your cards, encrypted on your device</div></div>
      <div class="stack">
        <button class="btn-primary" data-new>Create a new vault</button>
        <button class="btn-ghost" data-restore>Restore from iCloud</button>
        <div class="err" id="w-err"></div>
        <div class="hint">Restoring brings your cards from another device and unlocks with Face ID if it is available here.</div>
      </div>
    </div>`;
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
        <button class="link" data-welcome>Back</button>
        <div class="hint">Your password is the only way to recover the vault if Face ID is ever removed. There is no reset — keep it safe.</div>
      </div>
    </div>`;
}

function viewLock() {
  const hasFace = faceIdIsLocal();          // never offer another device's passkey
  const inherited = !!(META && META.prf) && !hasFace;
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
        ${inherited ? `<div class="hint">Face ID was set up on another device. Unlock with your master password and you can turn it on here in one tap.</div>` : ""}
        <div class="err" id="u-err"></div>
      </div>
    </div>`;
}

function render() {
  if (VIEW.name === "boot") return;
  if (!META) return VIEW.name === "create" ? viewSetup() : viewWelcome();
  if (!DEK) return viewLock();
  if (VIEW.name === "detail") return viewDetail();
  if (VIEW.name === "add") return viewForm(null);
  if (VIEW.name === "edit") return viewForm(VIEW.cardId);
  return viewList();
}

/* ---------- event delegation ---------- */
document.addEventListener("click", async (e) => {
  const t = e.target.closest("[data-open],[data-fav],[data-copy],[data-reveal],[data-lock],[data-add],[data-back],[data-toggle],[data-edit],[data-del],[data-t],[data-save],[data-sync],[data-new],[data-welcome],[data-restore],[data-import],[data-facesetup],[data-facedismiss],[data-editrow],#s-create,#import-close,#import-file-btn,#import-paste-go,#import-commit,#import-back,#import-all,#import-none,#u-face,#u-usepw,#u-pw-go,#sync-close,#sync-now,#sync-restore,#sync-take-cloud,#sync-take-local,#sync-wipe-cloud,#sync-wipe-local,#sync-diag-copy,#sync-selftest,#ck-signin,#ck-signout,#update-reload,#update-dismiss,[data-collapse],#search-clear");
  if (!t) return;

  if (t.id === "update-reload") { t.disabled = true; t.textContent = "Reloading…"; return applyUpdate(); }
  if (t.id === "update-dismiss") return showUpdateBar(false);

  if (t.dataset.collapse) { toggleCollapsed(t.dataset.collapse); return renderCards(); }
  if (t.id === "search-clear") {
    SEARCH = "";
    const box = document.getElementById("card-search");
    if (box) { box.value = ""; box.focus(); }
    t.hidden = true;
    return renderCards();
  }

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
  if (t.id === "ck-signin") {
    setSync("syncing");
    try { await CloudSync.signIn(); }           // navigates away to Apple
    catch (ex) { setSync("error", ex.message || "Couldn't start sign-in."); }
    return;
  }
  if (t.id === "ck-signout") {
    CloudSync.signOut();
    setSync("signedout");
    toast("Signed out of iCloud");
    return;
  }
  if (t.id === "sync-selftest") {
    const box = document.getElementById("sync-diag");
    t.disabled = true; box.value = "Running self-test…";
    try {
      const r = await CloudSync.selfTest();
      box.value = "== CloudKit REST self-test ==\n" +
        Object.keys(r).map((k) => `${k}: ${r[k]}`).join("\n");
    } catch (ex) {
      box.value = "self-test failed: " + ((ex && ex.message) || ex);
    }
    t.disabled = false;
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
  if (t.dataset.open && !e.target.closest("[data-fav],[data-copy],[data-reveal]")) return go("detail", t.dataset.open);

  // favourite toggle
  if (t.dataset.fav) {
    const c = CARDS.find((x) => x.id === t.dataset.fav);
    c.favourite = !c.favourite; c.updatedAt = Date.now();
    await saveVault(); render(); return;
  }

  // copy fields
  if (t.dataset.copy) {
    const c = CARDS.find((x) => x.id === t.dataset.id);
    const map = { number: digitsOf(c.number), expiry: c.expiry, cvv: c.cvv };
    const labels = { number: "Number", expiry: "Expiry", cvv: "CVV" };
    return copy(map[t.dataset.copy], labels[t.dataset.copy]);
  }

  /* One eye per tile shows the number and the CVV together — they are wanted at
     the same moment, and two toggles meant two taps for one intent. State lives
     on the number span rather than in its text: a number short enough that
     maskNum leaves it alone would otherwise read as "already revealed". */
  if (t.dataset.reveal) {
    const c = CARDS.find((x) => x.id === t.dataset.reveal);
    const num = document.querySelector(`[data-listnum="${c.id}"]`);
    const cvv = document.querySelector(`[data-cvv="${c.id}"]`);
    const shown = num.dataset.shown === "1";
    num.dataset.shown = shown ? "" : "1";
    num.textContent = shown ? maskNum(c.number) : groupNum(c.number);
    if (cvv) cvv.textContent = shown ? "•••" : (c.cvv || "—");
    t.innerHTML = I.eye(!shown);
    return;
  }

  if (t.hasAttribute("data-lock")) return lock();
  if (t.hasAttribute("data-new")) return go("create");
  if (t.hasAttribute("data-welcome")) return go("welcome");
  if (t.hasAttribute("data-restore")) {
    t.disabled = true; t.textContent = "Restoring…";
    await restoreFlow();
    if (document.body.contains(t)) { t.disabled = false; t.textContent = "Restore from iCloud"; }
    return;
  }
  if (t.hasAttribute("data-add")) return go("add");
  if (t.hasAttribute("data-import")) return openImport();
  if (t.hasAttribute("data-facedismiss")) {
    try { localStorage.setItem(FACE_DISMISS_KEY, "1"); } catch {}
    return render();
  }
  if (t.hasAttribute("data-facesetup")) {
    try {
      const how = await enableFaceId();
      try { localStorage.removeItem(FACE_DISMISS_KEY); } catch {}
      scheduleSync();
      toast(how === "linked" ? "Face ID linked" : "Face ID enabled");
      render();
    } catch (ex) {
      alert("Couldn't set up Face ID on this device.\n\n" + ((ex && ex.message) || ex));
    }
    return;
  }
  if (t.id === "import-close") return closeImport();
  if (t.id === "import-file-btn") return document.getElementById("lp-file").click();
  if (t.dataset.editrow !== undefined) {
    const form = document.querySelector(`[data-form="${t.dataset.editrow}"]`);
    form.hidden = !form.hidden;
    t.textContent = form.hidden ? "Edit" : "Done";
    return;
  }
  if (t.id === "import-commit") return commitImport();
  if (t.id === "import-back") {
    PENDING_IMPORT = [];
    document.getElementById("import-pick").hidden = true;
    document.getElementById("import-choose").hidden = false;
    return;
  }
  if (t.id === "import-all" || t.id === "import-none") {
    const on = t.id === "import-all";
    document.querySelectorAll("#import-list input[data-pick]").forEach((el) => { el.checked = on; });
    return updateImportCount();
  }
  if (t.id === "import-paste-go") {
    const box = document.getElementById("import-text");
    const text = box.value.trim();
    if (!text) { toast("Paste the export text first"); return; }
    try { await importLastPassText(text); box.value = ""; }
    catch (ex) { alert("Couldn't read that text: " + ((ex && ex.message) || ex)); }
    return;
  }
  if (t.hasAttribute("data-back")) return go(DEK && VIEW.name !== "list" ? "list" : "list");
  if (t.dataset.edit) return go("edit", t.dataset.edit);

  // detail reveal toggles
  if (t.dataset.toggle) {
    const c = CARDS.find((x) => x.id === VIEW.cardId);
    if (t.dataset.toggle === "num") {
      const el = document.querySelector("[data-fnum]");
      const shown = el.dataset.shown === "1";   // a flag, not a string compare
      el.dataset.shown = shown ? "" : "1";
      el.textContent = shown ? maskNum(c.number) : groupNum(c.number);
      document.querySelector("[data-num]").textContent = shown ? maskNum(c.number) : groupNum(c.number);
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
      number, expiry: g("f-expiry"), cvv: g("f-cvv"), name: g("f-name"), notes: g("f-notes"),
      favourite: document.querySelector('[data-t="fav"]').classList.contains("on"),
      type: document.querySelector('[data-t="addon"]').classList.contains("on") ? "addon" : "primary",
      accent: "#fff",
      order: prev ? prev.order : undefined, // rebuilt wholesale; keep its place
      createdAt: (prev && prev.createdAt) || now,
      updatedAt: now,
    };
    if (prev) {
      CARDS[CARDS.findIndex((x) => x.id === t.dataset.save)] = rec;
    } else CARDS.push(rec);
    SEARCH = ""; // else the card you just saved may not match, and looks lost
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
    if (FACE_BUSY) return; // an automatic prompt is already up
    const err = document.getElementById("u-err");
    FACE_BUSY = true;
    try { await unlockWithFaceId(); go("list"); }
    catch (ex) {
      // Browsers report this as an opaque DOMException. The actionable cause is
      // almost always that the passkey belongs to a different device.
      console.error("[CardVault] Face ID unlock failed:", ex);
      err.textContent = "Face ID isn't set up on this device. Unlock with your master password, then tap “Enable Face ID here”.";
      document.getElementById("pw-wrap").style.display = "block";
      const use = document.getElementById("u-usepw");
      if (use) use.style.display = "none";
    } finally { FACE_BUSY = false; }
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

/* Fill the network as the number is typed, or when iOS's card scanner drops a
   number in. A manual pick wins: existing cards start marked as touched, so
   re-scanning never silently rewrites a network the user chose. */
let numberDigits = 0; // reset in viewForm; used to spot a scan vs. typing
document.addEventListener("input", (e) => {
  if (!e.target || e.target.id !== "f-number") return;

  const sel = document.getElementById("f-network");
  if (sel && !sel.dataset.touched) {
    const n = detectNetwork(e.target.value);
    if (n && sel.value !== n) sel.value = n;
  }

  /* A scan or autofill lands many digits at once, where typing adds one at a
     time. On that jump, move to CVV — the one field no scanner can fill — so
     the keyboard is already waiting on it. Delayed slightly so iOS can finish
     populating expiry and cardholder first. */
  const digits = e.target.value.replace(/\D/g, "").length;
  const scanned = digits - numberDigits >= 6;
  numberDigits = digits;
  if (!scanned) return;
  const cvv = document.getElementById("f-cvv");
  if (cvv && !cvv.value) setTimeout(() => { if (!cvv.value) cvv.focus(); }, 300);
});
function applyPickEdit(el) {
  const i = Number(el.dataset.i);
  const c = PENDING_IMPORT[i];
  if (!c) return;
  const f = el.dataset.f;
  if (f === "addon") c.type = el.checked ? "addon" : "primary";
  else c[f] = el.value;
  c.updatedAt = Date.now();
  refreshPickRow(i);
}

document.addEventListener("change", (e) => {
  if (!e.target) return;
  if (e.target.id === "f-network") e.target.dataset.touched = "1";
  if (e.target.matches("#import-list input[data-pick]")) updateImportCount();
  if (e.target.matches("[data-f][data-i]")) applyPickEdit(e.target);
});
document.addEventListener("input", (e) => {
  if (e.target && e.target.matches("[data-f][data-i]")) applyPickEdit(e.target);
});

/* Filters as you type. Only the card area is repainted — see renderCards. */
document.addEventListener("input", (e) => {
  if (!e.target || e.target.id !== "card-search") return;
  SEARCH = e.target.value;
  const x = document.getElementById("search-clear");
  if (x) x.hidden = !SEARCH;
  renderCards();
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

/* ---------- drag to reorder ----------
   Hold a card for a moment, then drag it. The hold is the point: the list
   scrolls, and grabbing on contact would turn every scroll into a reorder, so
   movement before the timer fires is read as a scroll and cancels the hold.

   While dragging, a fixed clone follows the finger and the real tile stays in
   the flow, hidden, as the placeholder — so the gap you are about to drop into
   is the actual layout rather than something drawn to imitate it. */
const HOLD_MS = 400, HOLD_SLOP = 10;
let DRAG = null, hold = null, holdTimer = null, dragEndedAt = 0;

function cancelHold() {
  clearTimeout(holdTimer);
  holdTimer = null; hold = null;
}

function startDrag(x, y) {
  const tile = hold.tile;
  const r = tile.getBoundingClientRect();
  const ghost = tile.cloneNode(true);
  /* The clone carries the same data-* hooks as the original; strip them so a
     stray lookup can never land on a node that is about to be thrown away. */
  ghost.removeAttribute("data-open");
  ghost.querySelectorAll("[data-listnum],[data-cvv],[data-fav],[data-copy],[data-reveal]")
    .forEach((el) => ["data-listnum", "data-cvv", "data-fav", "data-copy", "data-reveal"]
      .forEach((a) => el.removeAttribute(a)));
  ghost.className = tile.className + " drag-ghost";
  ghost.style.cssText += `;left:${r.left}px;top:${r.top}px;width:${r.width}px;height:${r.height}px;`;
  document.body.appendChild(ghost);

  DRAG = { tile, ghost, list: tile.parentElement, x, y };
  tile.classList.add("drag-src");
  document.body.classList.add("dragging");
  dragMove(x, y);
}

function dragMove(x, y) {
  const d = DRAG;
  d.ghost.style.transform = `translate(${x - d.x}px, ${y - d.y}px) scale(1.04)`;
  /* Drop before the first tile whose midpoint is below the finger, else last.
     Moving the real tile is what makes the gap open up. */
  const target = [...d.list.children].find((s) => {
    if (s === d.tile) return false;
    const r = s.getBoundingClientRect();
    return y < r.top + r.height / 2;
  });
  if (target !== d.tile.nextElementSibling) d.list.insertBefore(d.tile, target || null);
}

async function endDrag() {
  const d = DRAG;
  DRAG = null;
  d.ghost.remove();
  d.tile.classList.remove("drag-src");
  document.body.classList.remove("dragging");
  dragEndedAt = Date.now(); // the pointerup becomes a click on the tile; swallow it

  // Renumber the section from what the DOM now shows.
  let changed = false;
  [...d.list.children].forEach((el, i) => {
    const c = CARDS.find((x) => x.id === el.dataset.open);
    if (!c || c.order === i) return;
    c.order = i;
    c.updatedAt = Date.now(); // so the new position merges across devices
    changed = true;
  });
  if (changed) await saveVault();
  render();
}

document.addEventListener("pointerdown", (e) => {
  if (DRAG || !DEK) return;
  if (SEARCH.trim()) return;                 // order is ambiguous in a filtered list
  if (e.target.closest("button")) return;    // star, copy and eye stay tappable
  const tile = e.target.closest(".card[data-open]");
  if (!tile || !tile.parentElement.dataset.cards) return;
  hold = { tile, x: e.clientX, y: e.clientY, id: e.pointerId };
  holdTimer = setTimeout(() => { holdTimer = null; startDrag(hold.x, hold.y); }, HOLD_MS);
});

document.addEventListener("pointermove", (e) => {
  if (DRAG) return dragMove(e.clientX, e.clientY);
  if (!hold || e.pointerId !== hold.id) return;
  if (Math.hypot(e.clientX - hold.x, e.clientY - hold.y) > HOLD_SLOP) cancelHold();
});

document.addEventListener("pointerup", () => { if (DRAG) endDrag(); else cancelHold(); });
document.addEventListener("pointercancel", () => { if (DRAG) endDrag(); else cancelHold(); });

/* iOS scrolls the page on touchmove unless the default is refused, and it will
   not honour a touch-action set only once the drag has already begun. */
document.addEventListener("touchmove", (e) => { if (DRAG) e.preventDefault(); }, { passive: false });

/* A drag ends with a click on the tile it started from, which would open the
   card. Swallow anything landing in the moment after a drop — a window rather
   than a one-shot flag, because the re-render can replace the tile before the
   click arrives, and a flag left armed would then eat the next real tap. */
const CLICK_DEAD_MS = 300;
document.addEventListener("click", (e) => {
  if (Date.now() - dragEndedAt > CLICK_DEAD_MS) return;
  e.stopPropagation();
  e.preventDefault();
}, true);

/* ---------- app updates ----------
   The service worker installs a new build and waits rather than taking over, so
   the page decides when to swap. Without that the app kept serving whatever it
   had already loaded and looked unchanged until it was quit and relaunched
   twice — the reason a deploy never seemed to arrive. */
/* The version this build was shipped as. version.json on the server holds the
   version that is deployed. Comparing the two is the whole update check — it
   does not depend on the browser noticing that service-worker.js changed, which
   is exactly the step iOS was failing to do. */
const APP_VERSION = "33";

let SW_REG = null, lastUpdateCheck = 0, SW_RELOADING = false;

/* Fetched with no-store and a cache-busting query, so neither the HTTP cache
   nor the service worker can answer with a stale number. */
async function deployedVersion() {
  const res = await fetch(`./version.json?t=${Date.now()}`, { cache: "no-store" });
  if (!res.ok) throw new Error("version check failed");
  return String((await res.json()).version || "");
}

async function checkVersion() {
  if (!navigator.onLine) return;
  try {
    const latest = await deployedVersion();
    if (latest && latest !== APP_VERSION) showUpdateBar(true);
  } catch { /* offline or blocked — nothing to announce */ }
}

/* Belt and braces: drop every cache, unregister the worker, then reload on a
   URL the browser has never seen. Anything short of this can still be answered
   from something stale. */
async function forceUpdate() {
  if (SW_RELOADING) return;
  SW_RELOADING = true;
  try {
    const regs = await navigator.serviceWorker.getRegistrations();
    await Promise.all(regs.map((r) => r.unregister()));
  } catch {}
  try {
    const keys = await caches.keys();
    await Promise.all(keys.map((k) => caches.delete(k)));
  } catch {}
  const u = new URL(location.href);
  u.searchParams.set("v", Date.now().toString(36));
  location.replace(u.toString());
}

/* Remembered separately from the DOM: the bar must survive re-renders, the
   privacy shield, and an unlock, and be re-asserted afterwards. */
let UPDATE_PENDING = false;

function showUpdateBar(on) {
  UPDATE_PENDING = !!on;
  const el = document.getElementById("update-bar");
  if (!el) return;
  // Reloading drops the in-memory DEK, but only say so when there is one.
  const sub = el.querySelector(".update-s");
  if (sub) sub.textContent = DEK ? "Reloading locks the vault." : "Reload to install it.";
  el.hidden = !on;
}

/* The worker now activates as soon as it installs, so a page can find itself
   controlled by a newer build than the scripts it is running. Reload once when
   that happens, so the running code and the cache never disagree. */
function watchForController() {
  if (!navigator.serviceWorker.controller) return; // first install, nothing stale
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (SW_RELOADING) return;
    SW_RELOADING = true;
    location.reload();
  });
}

function watchForUpdate(reg) {
  SW_REG = reg;
  // A build may already be waiting from an earlier launch.
  if (reg.waiting && navigator.serviceWorker.controller) showUpdateBar(true);
  reg.addEventListener("updatefound", () => {
    const sw = reg.installing;
    if (!sw) return;
    sw.addEventListener("statechange", () => {
      // No controller means this is a first install, not an update to announce.
      if (sw.state === "installed" && navigator.serviceWorker.controller) showUpdateBar(true);
    });
  });
}

/* Checked on launch and on each return to the foreground, so a deploy is picked
   up without quitting the app. Throttled: app switching is frequent. */
function checkForUpdate() {
  if (Date.now() - lastUpdateCheck < 30000) return;
  lastUpdateCheck = Date.now();
  checkVersion();
  if (SW_REG) SW_REG.update().catch(() => {});
}

function applyUpdate() { return forceUpdate(); }

/* ---------- auto-lock ----------
   Locking the instant the app is backgrounded made every app switch — and every
   share sheet, notification tap or file picker — cost a full unlock. The DEK now
   survives a short absence instead, and is dropped once that runs out. */
const LOCK_GRACE_MS = 15000;
let hiddenAt = 0, lockTimer = null;

function cancelAutoLock() {
  if (lockTimer) { clearTimeout(lockTimer); lockTimer = null; }
  hiddenAt = 0;
}

function startAutoLock() {
  cancelAutoLock();
  hiddenAt = Date.now();
  /* Backgrounded timers are throttled, and suspended outright once iOS freezes
     the tab, so this only fires in the lucky case. The elapsed-time check on
     the way back is what actually guarantees the grace period is honoured. */
  lockTimer = setTimeout(() => {
    lockTimer = null;
    if (DEK && document.hidden) lock();
  }, LOCK_GRACE_MS);
}

/* Card details are still in the DOM during the grace period, and iOS snapshots
   the screen for the app switcher on the way out. Cover it. */
// The shield sits above everything; re-show the bar once it lifts.
function reassertUpdateBar() {
  if (!UPDATE_PENDING) return;
  const el = document.getElementById("update-bar");
  if (el) el.hidden = false;
}

function privacyShield(on) {
  let el = document.getElementById("privacy-shield");
  if (!on) { if (el) el.hidden = true; return; }
  if (!DEK) return; // nothing on screen worth hiding
  if (!el) {
    el = document.createElement("div");
    el.id = "privacy-shield";
    el.innerHTML = `<div class="lock-badge">${I.lock}</div>`;
    document.body.appendChild(el);
  }
  el.hidden = false;
}

/* Coming back to a locked vault should present Face ID on its own, rather than
   asking for a tap first. Safari may refuse WebAuthn without a user gesture, so
   this is best-effort: on refusal the lock screen's button is still there. */
let FACE_BUSY = false;
/* The version check is a network round trip, and the automatic Face ID sheet
   used to open long before it answered — so UPDATE_PENDING was still false and
   the guard never fired. Wait for the check, but only briefly: a slow or dead
   network must not leave the user staring at a lock screen. */
const VERSION_GATE_MS = 1500;
async function gateAutoFaceId() {
  try {
    await Promise.race([
      checkVersion(),
      new Promise((r) => setTimeout(r, VERSION_GATE_MS)),
    ]);
  } catch {}
  maybeAutoFaceId();
}

async function maybeAutoFaceId() {
  // An update announcement outranks the automatic unlock: the Face ID sheet
  // covers the screen, so prompting first meant the bar was never seen. The
  // lock screen's own button still works, and dismissing the bar resumes this.
  if (UPDATE_PENDING) return;
  if (FACE_BUSY || DEK || !META || document.hidden || SHEET_OPEN) return;
  if (!faceIdIsLocal()) return;
  FACE_BUSY = true;
  try { await unlockWithFaceId(); go("list"); }
  catch (ex) { console.warn("[CardVault] automatic Face ID prompt unavailable:", ex); }
  finally { FACE_BUSY = false; }
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    privacyShield(true);
    // A sign-in hand-off holds its own grace; don't start a second clock.
    if (DEK && Date.now() > AUTH_UNTIL) startAutoLock();
    return;
  }
  privacyShield(false);
  reassertUpdateBar();
  const away = hiddenAt ? Date.now() - hiddenAt : 0;
  cancelAutoLock();
  AUTH_UNTIL = 0;
  if (DEK && away >= LOCK_GRACE_MS) lock();
  gateAutoFaceId();
  checkForUpdate();
});

document.addEventListener("change", async (e) => {
  if (!e.target || e.target.id !== "lp-file" || !e.target.files.length) return;
  const file = e.target.files[0];
  e.target.value = ""; // let the same file be picked again after a failed run
  try { await importLastPassFile(file); }
  catch (ex) { alert("Couldn't read that file: " + ((ex && ex.message) || ex)); }
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
  gateAutoFaceId();  // announce a new build first, then offer Face ID

  if (CloudSync.isConfigured()) {
    CloudSync.onChange(() => {
      renderSyncSheet();
      // A fresh sign-in is the moment to reconcile with iCloud.
      if (CloudSync.signedIn() && META) scheduleSync();
      else if (!CloudSync.signedIn()) setSync("signedout");
    });
    CloudSync.init().then(
      async () => {
        // Signing in navigates away and back. If this device has no vault yet,
        // finish the restore rather than leaving the user at the setup screen.
        let wanted = false;
        try { wanted = localStorage.getItem(RESTORE_INTENT) === "1"; } catch {}
        if (!META && wanted && CloudSync.signedIn()) {
          try {
            await restoreFromCloud(); // nothing local to lose
            await finishRestore();
            return;
          } catch { try { localStorage.removeItem(RESTORE_INTENT); } catch {} }
        }
        if (META) syncNow().catch(() => {});
      },
      () => setSync("error", "iCloud unavailable offline.")
    );
  }

  // Drop the cache-buster forceUpdate() added, so it doesn't linger.
  try {
    const u = new URL(location.href);
    if (u.searchParams.has("v")) {
      u.searchParams.delete("v");
      history.replaceState(null, "", u.pathname + (u.search || "") + u.hash);
    }
  } catch {}

  if ("serviceWorker" in navigator) {
    try {
      // register() checks for a new worker itself, so don't immediately re-ask.
      lastUpdateCheck = Date.now();
      watchForController();
      watchForUpdate(await navigator.serviceWorker.register("./service-worker.js"));
    } catch {}
  }
})();
