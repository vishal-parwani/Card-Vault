# Card Vault

A tiny offline, encrypted store for your card details — a self-hosted stand-in for the LastPass "Payment Cards" feature. No passwords, notes, or other LastPass features. Works fully offline; optional end-to-end encrypted iCloud sync across your devices.

## Security model
- A random 256-bit **Data Encryption Key (DEK)** encrypts your card list with AES-GCM.
- The DEK is wrapped twice so either method can unlock the same vault:
  - **Master password** → PBKDF2 (310k iterations, SHA-256) → AES-GCM key.
  - **Face ID** → WebAuthn **PRF** output → HKDF → AES-GCM key.
- The DEK exists **only in memory** after unlock and is dropped when the app is backgrounded or locked.
- Storage is your browser's IndexedDB. There is **no server** — iCloud sync, if you turn it on, goes straight from your device to your own private CloudKit database.

> There is no password reset. If the passkey is removed *and* the password is lost, the vault is unrecoverable — by design.

## iCloud sync (optional)

Off until you configure it. Fill in `sync-config.js` (it documents each step) with an iCloud container identifier and a CloudKit **Web Services API token**, add your domain to the container's Allowed Origins, and redeploy. Without that, the app behaves exactly as before: local, offline, no network calls.

**Why not CloudKit JS.** Apple's `cloudkit.js` opens sign-in in a popup. Apple then delivers `ckWebAuthToken` to the *popup's* URL, the parent window never receives it, and every subsequent request goes out unauthenticated — which Apple answers with `421 AUTHENTICATION_REQUIRED`. `sync.js` therefore talks to CloudKit Web Services (REST) directly and drives auth itself: a 421 response carries a `redirectURL`, we navigate the top-level window there, and Apple returns to the app with the token in the address bar. That token is stored locally, stripped from the URL, and attached to every later call. Dropping the library also removes the CDN dependency.

**What actually gets uploaded.** One record in *your* private CloudKit database, holding the AES-GCM ciphertext and the password-wrapped DEK. Apple stores opaque bytes. Your master password is never uploaded, never derived server-side, and the DEK is never uploaded unwrapped — so nobody without your password can read the vault, Apple included.

**How devices reconcile.** Each card carries `createdAt`/`updatedAt`, and deletions leave a tombstone, so merging is per-card rather than last-writer-wins on the whole vault: edit on your phone and add on your iPad, and you keep both. A deleted card stays deleted instead of being resurrected by the other device (unless that device edited it *after* the deletion). Saves are guarded by CloudKit's `recordChangeTag`, so a concurrent write re-fetches, re-merges, and retries.

**Setting up a second device.** Open the app, tap *Already have a vault? Restore from iCloud*, sign in, then unlock with your master password. Face ID enrolment carries over on Apple devices, since iCloud Keychain syncs the passkey and its PRF output.

**Two unrelated vaults.** If a device created its own vault with a different master password, its ciphertext isn't interchangeable with the one in iCloud. The app detects this (by comparing a salted hash of the DEK, never the key itself), refuses to merge, and asks which copy should win rather than silently destroying either.

**Caveats.**
- Signing in hands off to Apple's page, which backgrounds the app. Auto-lock is suspended for two minutes after you tap sign-in so returning doesn't drop you at the lock screen; it resumes immediately afterwards.
- CloudKit's `development` and `production` environments hold **separate data**. Test in development, then CloudKit Dashboard → *Deploy Schema to Production* and flip `environment` in `sync-config.js`.
- The `Vault` record type is created automatically on the first save in development. Production needs that schema deployed before sync will work there.
- Sync needs network. Offline, the app runs from cache as usual and syncs when you're back.

## Requirements
- **Face ID unlock** needs WebAuthn PRF: iOS/iPadOS 18+ (Safari) or a recent Chrome. If unavailable, the app silently falls back to password-only and still works.
- Must be served over **HTTPS** (GitHub Pages qualifies). WebAuthn won't run over plain HTTP.

## Deploy on GitHub Pages
1. Put these files in the repo root.
2. Settings → Pages → Source: `main` / root.
3. Open the published `https://<user>.github.io/card-vault/` URL in Safari on the iPhone.

## Install on iPhone
Safari → Share → **Add to Home Screen**. Launch from the home-screen icon for full-screen, offline use.

## Files
- `index.html` — shell
- `app.js` — crypto, IndexedDB, WebAuthn PRF, merge logic, UI
- `sync.js` — CloudKit JS adapter (auth, fetch/save, conflict detection)
- `sync-config.js` — your CloudKit container + API token; edit this to enable sync
- `styles.css` — styling
- `manifest.webmanifest`, `service-worker.js`, `icons/` — PWA/offline
