/* Card Vault — CloudKit Web Services client.

   Talks to the signed-in user's *private* CloudKit database over the REST API
   and keeps one record there. The record holds the same encrypted blob that
   sits in IndexedDB: AES-GCM ciphertext plus the password-wrapped DEK. Apple
   stores opaque bytes — the vault is unreadable without the master password.

   This deliberately does NOT use CloudKit JS. That library was observed to
   hold a valid ckWebAuthToken and still issue unauthenticated requests, which
   Apple answers with 421 AUTHENTICATION_REQUIRED. The REST API accepts the
   very same token and returns 200, so we drive auth ourselves:

     1. GET users/current with ckAPIToken.
     2. On 421, the body carries a redirectURL — send the browser there.
     3. Apple redirects back with ?ckWebAuthToken=…; capture and store it.
     4. Every later call passes ckAPIToken + ckWebAuthToken.

   Dropping the library also removes the CDN dependency, so nothing external
   has to load for the app to start.
*/
(function () {
  const RECORD_TYPE = "Vault";
  const RECORD_NAME = "vault-v1";
  const WEB_AUTH_KEY = "cardvault.ckWebAuthToken";

  let webAuth = "";        // session credential from Apple, persisted locally
  let userRecordName = ""; // set once authenticated
  let redirectURL = "";    // Apple's sign-in URL, handed to us on a 421
  let changeTag = null;    // last seen recordChangeTag, for conflict detection
  let started = false;
  const watchers = new Set();

  function cfg() { return window.CARD_VAULT_SYNC || {}; }
  function isConfigured() {
    const c = cfg();
    const both = String(c.containerIdentifier || "") + String(c.apiToken || "");
    return !!(c.containerIdentifier && c.apiToken && !/PASTE_|YOUR_/.test(both));
  }
  function environment() { return cfg().environment === "production" ? "production" : "development"; }
  function apiBase() {
    return `https://api.apple-cloudkit.com/database/1/${encodeURIComponent(cfg().containerIdentifier)}/${environment()}/private`;
  }

  function notify() { watchers.forEach((fn) => { try { fn(); } catch {} }); }
  function onChange(fn) { watchers.add(fn); }

  /* ---------- diagnostics ---------- */
  const DIAG = { origin: location.origin, lastCall: "(none)", lastStatus: "", lastError: "" };
  const redact = (s) => (s ? `${s.slice(0, 6)}…(${s.length} chars)` : "(none)");
  function diag() {
    return {
      ...DIAG,
      env: environment(),
      container: cfg().containerIdentifier,
      tokenLen: String(cfg().apiToken || "").length,
      webAuthToken: redact(webAuth),
      userRecordName: userRecordName || "(not signed in)",
      haveRedirectURL: redirectURL ? "yes" : "no",
      changeTag: changeTag || "(none)",
    };
  }

  /* ---------- auth ---------- */
  // Apple appends ?ckWebAuthToken=… on return. Store it and strip it from the
  // URL so a session credential isn't left sitting in browser history.
  function captureWebAuthToken() {
    try {
      const u = new URL(location.href);
      const t = u.searchParams.get("ckWebAuthToken");
      if (t) {
        localStorage.setItem(WEB_AUTH_KEY, t);
        u.searchParams.delete("ckWebAuthToken");
        history.replaceState(null, "", u.pathname + (u.search || "") + u.hash);
      }
      return localStorage.getItem(WEB_AUTH_KEY) || "";
    } catch { return ""; }
  }
  /* Listeners must only fire when the signed-in state actually changes.
     init() runs on every sync, so notifying unconditionally here would make
     each sync schedule the next one and spin forever. */
  function setUser(name) {
    const next = name || "";
    const changed = userRecordName !== next;
    userRecordName = next;
    if (changed) notify();
  }
  function clearAuth() {
    webAuth = "";
    try { localStorage.removeItem(WEB_AUTH_KEY); } catch {}
    setUser("");
  }

  /* ---------- transport ---------- */
  async function call(path, body) {
    const p = new URLSearchParams({ ckAPIToken: cfg().apiToken });
    if (webAuth) p.set("ckWebAuthToken", webAuth);
    const url = `${apiBase()}/${path}?${p}`;
    DIAG.lastCall = path;

    let res, text;
    try {
      res = await fetch(url, body
        ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
        : { method: "GET" });
      text = await res.text();
    } catch (e) {
      DIAG.lastStatus = "network/CORS failure";
      DIAG.lastError = (e && e.message) || String(e);
      throw new Error("Couldn't reach iCloud — you may be offline.");
    }

    DIAG.lastStatus = String(res.status);
    let json = null;
    try { json = JSON.parse(text); } catch {}

    if (res.ok) return json;

    // 421/401 mean "no valid credential". The body carries the sign-in URL.
    if (res.status === 421 || res.status === 401) {
      if (json && json.redirectURL) redirectURL = json.redirectURL;
      clearAuth();
      const e = new Error("Sign in to iCloud to sync.");
      e.needsAuth = true;
      throw e;
    }
    const msg = (json && (json.reason || json.serverErrorCode)) || `iCloud error ${res.status}`;
    DIAG.lastError = msg;
    const e = new Error(msg);
    e.serverErrorCode = json && json.serverErrorCode;
    throw e;
  }

  // Resolves with the user record name, or null when sign-in is still needed.
  async function init() {
    if (!isConfigured()) throw new Error("iCloud sync isn't configured yet.");
    webAuth = captureWebAuthToken();
    started = true;
    try {
      const r = await call("users/current");
      setUser((r && r.userRecordName) || "");
      return userRecordName;
    } catch (e) {
      if (e.needsAuth) return null; // expected when signed out; button appears
      DIAG.lastError = e.message;
      throw e;
    }
  }

  async function signIn() {
    if (!redirectURL) {
      // Provokes a 421 whose body carries a fresh redirectURL.
      try { await call("users/current"); } catch {}
    }
    if (!redirectURL) throw new Error("Couldn't start iCloud sign-in. Try again.");
    location.href = redirectURL;
  }

  function signOut() { changeTag = null; clearAuth(); }

  /* ---------- record I/O ---------- */
  function firstRecord(r) { return (r && r.records && r.records[0]) || null; }

  /* Before the first save the Vault record type does not exist at all, and
     CloudKit answers a lookup with "can't find record type" rather than
     NOT_FOUND. That is still just "nothing stored yet" — saving creates the
     type automatically in the development environment. */
  function isMissingSchema(x) {
    const s = [x && x.message, x && x.reason, x && x.serverErrorCode].join(" ").toLowerCase();
    // Apple's wording is "could not find record_type with name 'Vault'".
    // Match the underscore and spaced spellings both, so this survives rewording.
    return /record[_ ]type/.test(s) || s.includes("unknown_item");
  }

  // Resolves with the stored payload object, or null when nothing is saved yet.
  async function fetchRemote() {
    let r;
    try {
      r = await call("records/lookup", { records: [{ recordName: RECORD_NAME }] });
    } catch (e) {
      if (isMissingSchema(e)) { changeTag = null; return null; }
      throw e;
    }
    const rec = firstRecord(r);
    if (!rec || rec.serverErrorCode) {
      if (!rec || /NOT_FOUND/i.test(rec.serverErrorCode || "") || isMissingSchema(rec)) {
        changeTag = null; return null;
      }
      throw new Error(rec.reason || rec.serverErrorCode);
    }
    changeTag = rec.recordChangeTag || null;
    if (!rec.fields || !rec.fields.payload) return null;
    try {
      return JSON.parse(rec.fields.payload.value);
    } catch {
      throw new Error("The iCloud copy is unreadable.");
    }
  }

  // Throws err.conflict === true when someone else wrote since our last fetch.
  async function saveRemote(payload) {
    const record = {
      recordType: RECORD_TYPE,
      recordName: RECORD_NAME,
      fields: { payload: { value: JSON.stringify(payload) } },
    };
    if (changeTag) record.recordChangeTag = changeTag;
    const r = await call("records/modify", {
      operations: [{ operationType: changeTag ? "update" : "create", record }],
    });
    const rec = firstRecord(r);
    if (!rec || rec.serverErrorCode) {
      const code = (rec && rec.serverErrorCode) || "";
      // EXISTS means a record is already there and our "create" lost the race.
      if (/CONFLICT|EXISTS|SERVER_RECORD_CHANGED/i.test(code)) {
        changeTag = null; // force a re-fetch before the retry
        const e = new Error("The iCloud copy changed — merging.");
        e.conflict = true;
        throw e;
      }
      if (isMissingSchema(rec)) {
        throw new Error("CloudKit has no \"Vault\" record type in " + environment() +
          ". In production you must deploy the schema from the CloudKit Console first.");
      }
      throw new Error((rec && (rec.reason || code)) || "Couldn't save to iCloud.");
    }
    changeTag = rec.recordChangeTag || null;
  }

  // Remove the vault record entirely. A missing record counts as success.
  async function deleteRemote() {
    const r = await call("records/modify", {
      operations: [{ operationType: "forceDelete", record: { recordName: RECORD_NAME } }],
    });
    changeTag = null;
    const rec = firstRecord(r);
    if (rec && rec.serverErrorCode && !/NOT_FOUND/i.test(rec.serverErrorCode)) {
      throw new Error(rec.reason || rec.serverErrorCode);
    }
  }

  /* Raw probe used by the diagnostics panel. */
  async function selfTest() {
    const p = new URLSearchParams({ ckAPIToken: cfg().apiToken });
    const tok = captureWebAuthToken();
    if (tok) p.set("ckWebAuthToken", tok);
    const out = {
      env: environment(),
      webAuthToken: redact(tok),
      url: `${apiBase()}/users/current?ckAPIToken=…${tok ? "&ckWebAuthToken=…" : ""}`,
    };
    try {
      const res = await fetch(`${apiBase()}/users/current?${p}`);
      out.httpStatus = res.status;
      out.body = (await res.text()).slice(0, 600);
    } catch (e) {
      out.httpStatus = "fetch threw";
      out.body = (e && e.message) || String(e);
    }
    return out;
  }

  window.CloudSync = {
    isConfigured, init, onChange, diag, selfTest,
    signIn, signOut, captureWebAuthToken,
    fetchRemote, saveRemote, deleteRemote,
    ready: () => started,
    signedIn: () => !!userRecordName,
    who: () => (userRecordName ? "iCloud" : ""),
  };
})();
