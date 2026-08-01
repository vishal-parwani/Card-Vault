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
- **You must create the `Vault` record type by hand before the first sync.** Unlike the native SDK, CloudKit Web Services does not auto-create schema, even in development — the first save fails with `could not find record_type with name 'Vault'`. In the CloudKit Console: Schema → Record Types → **+** → name it `Vault`, add one **String** field called `payload`. No index is needed; the record is fetched by name, not by query. Repeat once per environment, or use *Deploy Schema to Production*.
- Sync needs network. Offline, the app runs from cache as usual and syncs when you're back.

## Adding a card

On iPhone/iPad, tapping the **Card number** field offers **Scan Credit Card** in the keyboard bar — iOS's own scanner, entirely on-device. It fills the number, expiry and cardholder name.

The network is then detected from the card's leading digits and selected for you; picking one yourself always wins, and editing an existing card never rewrites its stored network.

After a scan the CVV field is focused automatically, since that is the one value you always have to supply. Typing a number by hand never steals focus, and a CVV you have already entered is left alone.

What scanning can't give you, and why:
- **CVV** is never returned by Apple's scanner, regardless of where it is printed on the card — the scanner emits only number, expiry and cardholder name, and Safari's own card autofill likewise never stores a CVV. Newer cards that print the CVV beside the number make no difference. Type it.
- **Bank and product tier** (say "HDFC Infinia" or "Visa Infinite") aren't derivable offline. Only the network *family* is in the leading digits — Visa Platinum and Visa Infinite both begin with `4`. Resolving the tier needs an issuer (BIN) database: an online lookup would send part of your card number to a third party, and a bundled table would be stale and confidently wrong on exactly the cards that matter. So the label stays a field you type once.

## Importing from LastPass

In LastPass: **Account Options → Advanced → Export → LastPass CSV File**. Then in Card Vault, tap **Import from LastPass** under the Add card button and pick the downloaded `.csv`.

Only payment cards are imported — logins and secure notes in the same export are ignored. Number, cardholder, CVV, expiry, per-card notes and the favourite flag all come across; the item name becomes the card label, and the network is taken from LastPass or inferred from the number when LastPass left it blank. Cards whose number is already in the vault are skipped, so re-running an import is safe.

**Add-on cards** are guessed, because LastPass has no field for them. A card whose name or notes mention "add-on", "supplementary" or similar is filed under Add-on cards; everything else lands under Your cards. It's a guess, so check the sections after importing — the toggle on the edit screen fixes any that landed wrong.

The file is parsed in the page and never uploaded — importing works with no network at all. It does mean the export sitting in your Downloads folder is **plaintext card data**: delete it once the import looks right.

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
- `sync.js` — CloudKit Web Services client (auth flow, fetch/save, conflict detection)
- `sync-config.js` — your CloudKit container + API token; edit this to enable sync
- `styles.css` — styling
- `manifest.webmanifest`, `service-worker.js`, `icons/` — PWA/offline
