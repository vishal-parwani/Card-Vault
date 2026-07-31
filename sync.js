/* Card Vault — CloudKit JS adapter.

   Talks to the signed-in user's *private* CloudKit database and keeps one
   record there. The record holds the same encrypted blob that sits in
   IndexedDB: AES-GCM ciphertext plus the password-wrapped DEK. Apple stores
   opaque bytes — the vault is unreadable without the master password.

   Everything here is best-effort. If the CDN is unreachable, the container
   isn't configured, or the user never signs in, the app keeps working offline;
   these calls just reject and the caller reports the reason.
*/
(function () {
  const CK_SRC = "https://cdn.apple-cloudkit.com/ck/2/cloudkit.js";
  const RECORD_TYPE = "Vault";
  const RECORD_NAME = "vault-v1";
  const LOAD_TIMEOUT = 15000;

  let scriptP = null;      // in-flight CDN load
  let initP = null;        // in-flight configure+auth
  let container = null, db = null;
  let identity = null;     // CloudKit userIdentity, or null when signed out
  let changeTag = null;    // last seen recordChangeTag, for conflict detection
  const watchers = new Set();

  function cfg() { return window.CARD_VAULT_SYNC || {}; }

  function isConfigured() {
    const c = cfg();
    const both = String(c.containerIdentifier || "") + String(c.apiToken || "");
    return !!(c.containerIdentifier && c.apiToken && !/PASTE_|YOUR_/.test(both));
  }

  function notify() { watchers.forEach((fn) => { try { fn(); } catch {} }); }
  function onChange(fn) { watchers.add(fn); }

  /* ---------- loading ---------- */
  function loadScript() {
    if (window.CloudKit) return Promise.resolve();
    if (scriptP) return scriptP;
    scriptP = new Promise((res, rej) => {
      const fail = (msg) => { scriptP = null; rej(new Error(msg)); };
      const timer = setTimeout(() => fail("Couldn't reach iCloud — check your connection."), LOAD_TIMEOUT);
      // Listener goes on before the script does, so we can't miss the event.
      window.addEventListener("cloudkitloaded", () => { clearTimeout(timer); res(); }, { once: true });
      const s = document.createElement("script");
      s.src = CK_SRC;
      s.async = true;
      s.onerror = () => { clearTimeout(timer); fail("Couldn't load iCloud — you may be offline."); };
      document.head.appendChild(s);
    });
    return scriptP;
  }

  function setIdentity(who) {
    identity = who || null;
    if (!identity) changeTag = null; // tags are per-account; drop on sign-out
    notify();
  }

  // whenUserSignsIn/Out resolve once, so re-arm after each to keep tracking.
  function watchAuth() {
    if (!container) return;
    container.whenUserSignsIn().then((who) => { setIdentity(who); watchAuth(); }, () => {});
    container.whenUserSignsOut().then(() => { setIdentity(null); watchAuth(); }, () => {});
  }

  function init() {
    if (!isConfigured()) return Promise.reject(new Error("iCloud sync isn't configured yet."));
    if (initP) return initP;
    initP = (async () => {
      await loadScript();
      const c = cfg();
      CloudKit.configure({
        containers: [{
          containerIdentifier: c.containerIdentifier,
          apiTokenAuth: {
            apiToken: c.apiToken,
            persist: true, // remember the Apple ID between launches
            signInButton: { id: "apple-sign-in-button", theme: "black" },
            signOutButton: { id: "apple-sign-out-button", theme: "black" },
          },
          environment: c.environment === "production" ? "production" : "development",
        }],
      });
      container = CloudKit.getDefaultContainer();
      db = container.privateCloudDatabase;
      // Renders Apple's sign-in button into #apple-sign-in-button and resolves
      // with the identity if a session is already persisted.
      setIdentity(await container.setUpAuth());
      watchAuth();
      return identity;
    })().catch((e) => { initP = null; throw e; });
    return initP;
  }

  /* ---------- errors ---------- */
  function codeOf(e) { return (e && (e.ckErrorCode || e.serverErrorCode || e.reason)) || ""; }
  function isNotFound(e) { return /NOT_FOUND/i.test(codeOf(e)); }
  function isConflict(e) { return /CONFLICT|SERVER_RECORD_CHANGED/i.test(codeOf(e)); }
  function ckError(e) {
    const msg = (e && (e.reason || e.ckErrorCode || e.serverErrorCode)) || "iCloud request failed.";
    const err = new Error(msg);
    err.ckErrorCode = e && (e.ckErrorCode || e.serverErrorCode);
    return err;
  }

  /* ---------- record I/O ---------- */
  // Resolves with the stored payload object, or null when nothing is saved yet.
  async function fetchRemote() {
    const res = await db.fetchRecords([RECORD_NAME]);
    if (res.hasErrors) {
      const e = res.errors[0];
      if (isNotFound(e)) { changeTag = null; return null; }
      throw ckError(e);
    }
    const rec = res.records && res.records[0];
    if (!rec || !rec.fields || !rec.fields.payload) { changeTag = null; return null; }
    changeTag = rec.recordChangeTag || null;
    try {
      return JSON.parse(rec.fields.payload.value);
    } catch {
      throw new Error("The iCloud copy is unreadable.");
    }
  }

  // Throws err.conflict === true when someone else wrote since our last fetch.
  async function saveRemote(payload) {
    const rec = {
      recordType: RECORD_TYPE,
      recordName: RECORD_NAME,
      fields: { payload: { value: JSON.stringify(payload) } },
    };
    if (changeTag) rec.recordChangeTag = changeTag;
    const res = await db.saveRecords([rec]);
    if (res.hasErrors) {
      const e = res.errors[0];
      if (isConflict(e)) {
        changeTag = null; // force a re-fetch before the retry
        const err = new Error("The iCloud copy changed — merging.");
        err.conflict = true;
        throw err;
      }
      throw ckError(e);
    }
    const saved = res.records && res.records[0];
    changeTag = (saved && saved.recordChangeTag) || null;
  }

  window.CloudSync = {
    isConfigured,
    init,
    onChange,
    fetchRemote,
    saveRemote,
    ready: () => !!db,
    signedIn: () => !!identity,
    who: () => {
      if (!identity) return "";
      const n = identity.nameComponents || {};
      return [n.givenName, n.familyName].filter(Boolean).join(" ") || identity.emailAddress || "your Apple ID";
    },
  };
})();
