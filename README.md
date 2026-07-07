# Card Vault

A tiny offline, encrypted store for your card details — a self-hosted stand-in for the LastPass "Payment Cards" feature. No passwords, notes, or other LastPass features. Nothing leaves your device.

## Security model
- A random 256-bit **Data Encryption Key (DEK)** encrypts your card list with AES-GCM.
- The DEK is wrapped twice so either method can unlock the same vault:
  - **Master password** → PBKDF2 (310k iterations, SHA-256) → AES-GCM key.
  - **Face ID** → WebAuthn **PRF** output → HKDF → AES-GCM key.
- The DEK exists **only in memory** after unlock and is dropped when the app is backgrounded or locked.
- Storage is your browser's IndexedDB on that device only. There is **no sync and no server**.

> There is no password reset. If the passkey is removed *and* the password is lost, the vault is unrecoverable — by design.

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
- `app.js` — crypto, IndexedDB, WebAuthn PRF, UI
- `styles.css` — styling
- `manifest.webmanifest`, `service-worker.js`, `icons/` — PWA/offline
