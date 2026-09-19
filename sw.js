// Toggle Password Manager - Service Worker
const CACHE_NAME = 'toggle-vault-v2';

self.addEventListener('install', (event) => {
  // Activate immediately
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          // Delete all older caches
          return caches.delete(key);
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  // Network-first strategy so updates in CSS/JS are seen instantly
  event.respondWith(
    fetch(event.request)
      .then((networkResponse) => {
        return networkResponse;
      })
      .catch(() => {
        // Fallback to cache only when truly offline
        return caches.match(event.request);
      })
  );
});
