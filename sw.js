// Toggle Password Manager - Service Worker (v3.0)
// High-resilience offline-first cache with network-first runtime updates
const CACHE_NAME = 'toggle-vault-v3';

const CORE_ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './styles/theme.css',
  './styles/components.css',
  './styles/main.css',
  './js/app.js',
  './js/crypto.js',
  './js/storage.js',
  './js/generator.js',
  './js/security.js',
  './js/importer.js',
  './js/ui.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        // Cache core assets for offline launch
        return cache.addAll(CORE_ASSETS).catch((err) => {
          console.warn('[SW] Core asset pre-caching partial warning:', err);
        });
      })
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  event.respondWith(
    fetch(event.request)
      .then((networkResponse) => {
        // Clone and store valid responses into cache
        if (networkResponse && networkResponse.status === 200) {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
        }
        return networkResponse;
      })
      .catch(async () => {
        // Fallback to cache when offline
        const cachedResponse = await caches.match(event.request);
        if (cachedResponse) return cachedResponse;

        // Fallback to index.html for navigation requests
        if (event.request.mode === 'navigate') {
          return caches.match('./index.html') || caches.match('index.html');
        }

        return new Response('Offline: Resource not available', {
          status: 503,
          statusText: 'Service Unavailable',
          headers: { 'Content-Type': 'text/plain' }
        });
      })
  );
});
