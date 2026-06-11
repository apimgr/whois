package server

import (
	"fmt"
	"net/http"
)

// handleManifest serves /manifest.json for PWA support (AI.md PART 16).
func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	name := s.config.BrandingTitle
	if name == "" {
		name = "caswhois"
	}
	desc := s.config.BrandingDescription
	if desc == "" {
		desc = "WHOIS lookup service"
	}
	themeColor := s.config.BrandingAccentColor
	if themeColor == "" {
		themeColor = "#007bff"
	}

	manifest := fmt.Sprintf(`{
  "name": %q,
  "short_name": %q,
  "description": %q,
  "start_url": "/?source=pwa",
  "scope": "/",
  "display": "standalone",
  "orientation": "any",
  "background_color": "#0d1117",
  "theme_color": %q,
  "categories": ["utilities"],
  "icons": [
    {"src": "/static/icons/icon-72.png",  "sizes": "72x72",   "type": "image/png"},
    {"src": "/static/icons/icon-96.png",  "sizes": "96x96",   "type": "image/png"},
    {"src": "/static/icons/icon-128.png", "sizes": "128x128", "type": "image/png"},
    {"src": "/static/icons/icon-144.png", "sizes": "144x144", "type": "image/png"},
    {"src": "/static/icons/icon-152.png", "sizes": "152x152", "type": "image/png"},
    {"src": "/static/icons/icon-192.png", "sizes": "192x192", "type": "image/png"},
    {"src": "/static/icons/icon-384.png", "sizes": "384x384", "type": "image/png"},
    {"src": "/static/icons/icon-512.png", "sizes": "512x512", "type": "image/png"},
    {"src": "/static/icons/icon-maskable-192.png", "sizes": "192x192", "type": "image/png", "purpose": "maskable"},
    {"src": "/static/icons/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"}
  ]
}`, name, name, desc, themeColor)

	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, manifest)
}

// handleServiceWorker serves /sw.js for PWA offline support (AI.md PART 16).
func (s *Server) handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	appName := s.config.BrandingTitle
	if appName == "" {
		appName = "caswhois"
	}

	sw := fmt.Sprintf(`// Service Worker for %s (AI.md PART 16 PWA support)
const CACHE_VERSION = 'v1';
const CACHE_NAME = '%s-cache-' + CACHE_VERSION;

const PRECACHE_ASSETS = [
  '/',
  '/static/css/main.css',
  '/static/js/main.js',
  '/offline.html'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(PRECACHE_ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  if (event.request.url.includes('/api/')) return;

  event.respondWith(
    caches.match(event.request)
      .then(cached => cached || fetch(event.request)
        .then(response => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match('/offline.html'))
      )
  );
});

self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
`, appName, appName)

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Service-Worker-Allowed", "/")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, sw)
}

// handleOfflinePage serves /offline.html shown by the service worker when offline (AI.md PART 16).
func (s *Server) handleOfflinePage(w http.ResponseWriter, r *http.Request) {
	name := s.config.BrandingTitle
	if name == "" {
		name = "caswhois"
	}

	page := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Offline — %s</title>
<link rel="stylesheet" href="/static/css/main.css">
</head>
<body class="offline-page">
<main id="main-content" style="text-align:center;padding:4rem 1rem;">
  <h1>You are offline</h1>
  <p>%s requires a network connection. Please check your connection and try again.</p>
  <button onclick="window.location.reload()">Retry</button>
</main>
</body>
</html>`, name, name)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, page)
}
