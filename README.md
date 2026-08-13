# Card Vault

A tiny offline, encrypted store for your card details — a self-hosted stand-in for the LastPass "Payment Cards" feature. No passwords, notes, or other LastPass features. Works fully offline; optional end-to-end encrypted iCloud sync across your devices.

## Security model
- A random 256-bit **Data Encryption Key (DEK)** encrypts your card list with AES-GCM.
- The DEK is wrapped twice so either method can unlock the same vault:
  - **Master password** → PBKDF2 (310k iterations, SHA-256) → AES-GCM key.
  - **Face ID** → WebAuthn **PRF** output → HKDF → AES-GCM key.
- The DEK exists **only in memory** after unlock, and is dropped on lock or after the app has been backgrounded for 15 seconds (see *Unlocking and auto-lock*).
- Storage is your browser's IndexedDB. There is **no server** — iCloud sync, if you turn it on, goes straight from your device to your own private CloudKit database.

> There is no password reset. If the passkey is removed *and* the password is lost, the vault is unrecoverable — by design.

## Unlocking and auto-lock

**Auto-lock waits 30 seconds.** Locking the moment the app lost focus meant every app switch — and every share sheet, notification tap or file picker — cost a full unlock. The vault now survives 30 seconds of being backgrounded and locks after that. Because iOS freezes a backgrounded tab's timers, the countdown can't be trusted to fire on its own; the elapsed time is re-checked when you come back, so the grace period holds regardless of whether the timer ran.

**Not every unexpected lock is that timer**, and raising it won't fix the ones that aren't. The DEK lives in memory only, so anything that reloads or discards the page locks the vault whatever the clock says:

- A **service worker taking over**. This was the real cause of "it asked for Face ID after five seconds": the update check runs every time the app returns to the foreground, so shortly after a deploy the new worker would claim the page, the old code reloaded itself to match, and the DEK went with it. A takeover under an unlocked vault now raises the update bar instead and leaves the reload to you; locked, there is nothing to lose and it still reloads at once.
- **iOS reclaiming the page's memory** while the app is backgrounded, which relaunches it cold. No grace period can prevent this, and keeping the key anywhere it would survive would defeat the point of the key.

**The screen is covered while you're away.** The DEK now outlives being backgrounded, so card details are still on screen when iOS takes its app-switcher snapshot. A shield is drawn over the app on the way out and removed on the way back, keeping the snapshot blank.

**Face ID fires on its own.** Returning to a locked vault triggers the Face ID prompt without waiting for a tap, and so does launching the app. This is best-effort: Safari can refuse WebAuthn to a page that hasn't been touched yet, and when it does the app falls back silently to the lock screen's *Unlock with Face ID* button. Nothing is retried in a loop — one attempt per return to the foreground.

**And without the passkey chooser.** That prompt used to arrive behind a second tap asking whether to use a passkey. The credential is registered with `authenticatorAttachment: "platform"` and requested with `transports: ["internal"]` (plus `hints: ["client-device"]`), which tells Safari the key is on *this* device — so it stops offering the choice between a security key, a nearby phone and this iPhone, and goes straight to the face scan. The transport hint is supplied at request time, so passkeys enrolled before this change benefit without being re-enrolled.

## Updates

The app is cache-first, so a deploy doesn't appear just because you reopened the app. It used to take two full quit-and-relaunch cycles to land: the service worker called `skipWaiting()` and took over immediately, but the page on screen had already loaded the previous build's scripts, so the first relaunch swapped the cache and the second one finally showed the new code.

Now a new build installs and **waits** instead. The page notices it, shows a *New version available* bar, and only promotes it when you tap **Reload** — which messages the waiting worker to `skipWaiting()`, then reloads once it has taken control, so the fresh files are the ones that load. Dismissing the bar leaves the build waiting; it activates on its own the next time the app is fully closed and reopened.

The check runs at launch and on each return to the foreground (throttled to once a minute), so a deploy is normally picked up without quitting the app at all.

Reloading drops the in-memory DEK, so the vault locks — the bar says so when there is something to lose.

> Bumping `CACHE` in `service-worker.js` is what marks a build as new. Change it whenever you ship, or devices will keep serving the cached copy.

## Viewing card details

The card number is masked on the main list, with an eye button beside the copy button to reveal it on that card alone; it re-masks when the list next re-renders.

Opening a card shows **everything unmasked** — number and CVV included — since that screen is the point of tapping through. The eye buttons still work, in reverse: they hide a value you don't want on screen.

## Finding and arranging cards

**Search** lives behind the magnifier in the header — tap it and the field appears, tap it again and it folds away along with whatever you'd typed. It also folds away on its own once focus leaves it — including when you simply start scrolling the list, which on iOS doesn't blur an input by itself, so the keyboard used to sit there over the cards with an empty field above them. Scrolling drops focus, which dismisses the keyboard and takes an unused field with it. So opening it and changing your mind doesn't leave it parked there; a field with a query in it stays, since closing clears the query and losing a live filter because you tapped a card would be worse than the clutter. Escape closes it and restores the full list. The row is removed a beat after focus leaves rather than immediately — taking it away between finger-down and tap would shift the list up and land the tap on the wrong card. It filters as you type, across every field you can see: label, network, cardholder, notes, expiry and number. The number is matched on digits alone as well, so `4111 1111` finds a card stored unspaced and `41111111` finds a grouped one. Only the card area repaints on each keystroke — re-rendering the header would replace the field under the cursor and lose focus on every letter.

**Sections collapse.** Tap *Favourites*, *Your cards* or *Add-on cards* to fold one away; the count stays visible in the header. Which ones are folded is a per-device view preference, so it lives in `localStorage` and never syncs. Searching ignores collapsing — a filtered list is no place to hide matches — and the folds come back when the search is cleared.

**Drag to reorder.** Hold a card for a moment, then drag it. The hold is what separates a reorder from a scroll: grabbing on contact would turn every flick of the list into a drag, so movement before the timer fires is read as scrolling and cancels the hold. While dragging, a clone follows your finger and the real tile stays in the list, hidden, as the placeholder — the gap you're about to drop into is the actual layout rather than an imitation of it.

Cards reorder within their own section only, since the sections are what decides where a card lives. The position is stored per card and carries a fresh `updatedAt`, so it merges across devices like any other edit. Cards you've never dragged keep their existing creation order and don't shuffle themselves.

Dragging is off while a search is active — the order of a filtered list doesn't mean anything to write back.

## iCloud sync (optional)

Off until you configure it. Fill in `sync-config.js` (it documents each step) with an iCloud container identifier and a CloudKit **Web Services API token**, add your domain to the container's Allowed Origins, and redeploy. Without that, the app behaves exactly as before: local, offline, no network calls.

**Why not CloudKit JS.** Apple's `cloudkit.js` opens sign-in in a popup. Apple then delivers `ckWebAuthToken` to the *popup's* URL, the parent window never receives it, and every subsequent request goes out unauthenticated — which Apple answers with `421 AUTHENTICATION_REQUIRED`. `sync.js` therefore talks to CloudKit Web Services (REST) directly and drives auth itself: a 421 response carries a `redirectURL`, we navigate the top-level window there, and Apple returns to the app with the token in the address bar. That token is stored locally, stripped from the URL, and attached to every later call. Dropping the library also removes the CDN dependency.

**What actually gets uploaded.** One record in *your* private CloudKit database, holding the AES-GCM ciphertext and the password-wrapped DEK. Apple stores opaque bytes. Your master password is never uploaded, never derived server-side, and the DEK is never uploaded unwrapped — so nobody without your password can read the vault, Apple included.

**How devices reconcile.** Each card carries `createdAt`/`updatedAt`, and deletions leave a tombstone, so merging is per-card rather than last-writer-wins on the whole vault: edit on your phone and add on your iPad, and you keep both. A deleted card stays deleted instead of being resurrected by the other device (unless that device edited it *after* the deletion). Saves are guarded by CloudKit's `recordChangeTag`, so a concurrent write re-fetches, re-merges, and retries.

**The sign-in expires, and that's Apple's clock.** A CloudKit web auth token lasts **30 minutes** by default, or **two weeks** if *Keep me signed in* is ticked on Apple's own sign-in page — there is no way for the app to extend it. So being asked to sign in again is routine rather than a fault, and the sheet says *iCloud sign-in expired* rather than *Not signed in* once you have signed in at least once, with the checkbox called out beneath. Signing out deliberately resets that, so the next *Not signed in* is the truth. Nothing is lost while the session is gone: the vault is on the device, and only syncing pauses.

**Setting up a second device.** Open the app, tap *Already have a vault? Restore from iCloud*, sign in, then unlock with your master password. Face ID enrolment carries over on Apple devices, since iCloud Keychain syncs the passkey and its PRF output.

**Two unrelated vaults.** If a device created its own vault with a different master password, its ciphertext isn't interchangeable with the one in iCloud. The app detects this (by comparing a salted hash of the DEK, never the key itself), refuses to merge, and asks which copy should win rather than silently destroying either.

**Caveats.**
- Signing in hands off to Apple's page, which backgrounds the app. Auto-lock is suspended for two minutes after you tap sign-in so returning doesn't drop you at the lock screen; it resumes immediately afterwards.
- CloudKit's `development` and `production` environments hold **separate data**. Test in development, then CloudKit Dashboard → *Deploy Schema to Production* and flip `environment` in `sync-config.js`.
- **You must create the `Vault` record type by hand before the first sync.** Unlike the native SDK, CloudKit Web Services does not auto-create schema, even in development — the first save fails with `could not find record_type with name 'Vault'`. In the CloudKit Console: Schema → Record Types → **+** → name it `Vault`, add one **String** field called `payload`. No index is needed; the record is fetched by name, not by query. Repeat once per environment, or use *Deploy Schema to Production*.
- Sync needs network. Offline, the app runs from cache as usual and syncs when you're back.

## Adding a card

The form is sized to fit an iPhone screen without scrolling, down to an SE, with the iOS safe areas accounted for — Network and Sub-type share a row, and the padding is trimmed rather than the type, since anything under 16px makes Safari zoom the page in on focus.

**Scanning is Apple's, and it lives in the keyboard bar.** Because the number field is marked `autocomplete="cc-number"`, focusing it puts **Scan Credit Card** in the QuickType strip directly above the keyboard; the camera then runs entirely on-device and fills the number, expiry and cardholder name. A web page cannot open that scanner itself — there is no API for it — so the **Scan** button beside the *Card number* label does the only thing available: it focuses the field and says where to look. It appears on iOS and iPadOS only, since no other platform makes the offer.

**Getting Safari to make the offer** took two changes, because Apple documents none of the heuristics:

- **No `inputmode="numeric"` on iOS.** It forces the numeric keypad, whose accessory bar carries only prev/next/done — there is nowhere for an AutoFill offer to appear, so the scanner is silently unreachable. The attribute is therefore dropped on iOS and kept everywhere else, trading a slightly less convenient keyboard for a scanner that exists. The CVV keeps its keypad; nothing scans into it anyway.
- **Conventional `name` attributes.** Safari's card detection reads `name`/`id`/label text, and ids like `f-number` match nothing it looks for. The fields now also carry `cardnumber`, `cc-exp`, `cvc` and `ccname`.

If the offer still doesn't appear, card AutoFill is switched off — *Settings › Safari › AutoFill › Credit Cards*. The hint under the field says so on its own after a few seconds of nothing arriving.

The network is then detected from the card's leading digits and selected for you; picking one yourself always wins, and editing an existing card never rewrites its stored network.

After a scan the CVV field is focused automatically, since that is the one value you always have to supply. Typing a number by hand never steals focus, and a CVV you have already entered is left alone.

What scanning can't give you, and why:
- **CVV** is never returned by Apple's scanner, regardless of where it is printed on the card — the scanner emits only number, expiry and cardholder name, and Safari's own card autofill likewise never stores a CVV. Newer cards that print the CVV beside the number make no difference. Type it.
- **Bank and product tier** (say "HDFC Infinia" or "Visa Infinite") aren't derivable offline. Only the network *family* is in the leading digits — Visa Platinum and Visa Infinite both begin with `4`. Resolving the tier needs an issuer (BIN) database: an online lookup would send part of your card number to a third party, and a bundled table would be stale and confidently wrong on exactly the cards that matter. So the label stays a field you type once.

## Archiving a card

A card you've cancelled, or one that has expired, doesn't need deleting — open it and tap **Archive card**, then pick a reason: expired, cancelled by me, closed by issuer, lost or stolen, replaced, or other. The card keeps every detail it had and moves into its own **Archived** section at the bottom of the list, drawn desaturated with the reason beside the network. The count under the header separates the two, so *8 saved · 3 archived* tells you what's actually live.

Archiving is reversible from the same screen (**Restore to my cards**), and the archive state carries `updatedAt` like any other edit, so it merges across devices rather than being a per-device view setting.

## Settings

The gear in the header holds the things you touch rarely: **iCloud Sync**, and **Face ID** enrolment. Enrolment only appears when this device has no passkey of its own — otherwise it says so and offers nothing to press, since re-enrolling a device that is already set up does nothing but re-run the prompt. On a device restored from iCloud where the vault already carries a passkey from elsewhere, the button reads *Link Face ID from your other device*. The build number sits at the bottom of the sheet.

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
