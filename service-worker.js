const CACHE = "card-vault-v25";
const ASSETS = [
  "./",
  "./index.html",
  "./app.js",
  "./sync.js",
  "./sync-config.js",
  "./styles.css",
  "./manifest.webmanifest",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/apple-touch-icon.png",
];

/* skipWaiting is required, not optional. Without it a new build parks in
   "waiting" until every client using the old worker goes away — and an older
   build has no reload prompt to promote it, while iOS keeps the page alive as a
   client across app switches. That combination strands a device on a stale
   build permanently. Activating immediately means the worst case is seeing the
   new version one launch later; the update bar below just makes that instant. */
self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener("message", (e) => {
  if (e.data && e.data.type === "SKIP_WAITING") self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())
  );
});

// Cache-first for app shell; network passthrough for anything else (e.g. fonts,
// CloudKit JS). sync-config.js is network-first so editing your CloudKit
// credentials takes effect without also bumping the cache version.
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.origin === location.origin && url.pathname.endsWith("/sync-config.js")) {
    e.respondWith(
      fetch(e.request).then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(e.request, copy)).catch(() => {});
        return res;
      }).catch(() => caches.match(e.request))
    );
    return;
  }
  if (url.origin === location.origin) {
    e.respondWith(
      caches.match(e.request).then((hit) => hit || fetch(e.request).then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(e.request, copy)).catch(() => {});
        return res;
      }).catch(() => caches.match("./index.html")))
    );
  }
});
