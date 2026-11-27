package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/common/i18n"
)

// handleManifest serves the install metadata for the progressive web app.
func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	name := s.config.Branding.Title
	if name == "" {
		name = constants.InternalName
	}
	desc := s.config.Branding.Description
	if desc == "" {
		desc = "WHOIS lookup service"
	}
	themeColor := s.config.Branding.AccentColor
	if themeColor == "" {
		themeColor = "#007bff"
	}
	base := s.GetBaseURL(r)
	assetURL := func(assetPath string) string {
		return base + assetPath + "?v=" + url.QueryEscape(Version+"-"+CommitID)
	}
	manifest := map[string]any{
		"name": name, "short_name": name, "description": desc,
		"start_url": s.withBaseURL(r, "/?source=pwa"), "scope": s.withBaseURL(r, "/"),
		"display": "standalone", "orientation": "any", "background_color": "#0d1117",
		"theme_color": themeColor, "categories": []string{"utilities"},
		"icons": []map[string]string{
			{"src": assetURL("/static/icons/icon-72.png"), "sizes": "72x72", "type": "image/png"},
			{"src": assetURL("/static/icons/icon-96.png"), "sizes": "96x96", "type": "image/png"},
			{"src": assetURL("/static/icons/icon-128.png"), "sizes": "128x128", "type": "image/png"},
			{"src": assetURL("/static/icons/icon-144.png"), "sizes": "144x144", "type": "image/png"},
			{"src": assetURL("/static/icons/icon-152.png"), "sizes": "152x152", "type": "image/png"},
			{"src": assetURL("/static/icons/icon-192.png"), "sizes": "192x192", "type": "image/png"},
			{"src": assetURL("/static/icons/icon-384.png"), "sizes": "384x384", "type": "image/png"},
			{"src": assetURL("/static/icons/icon-512.png"), "sizes": "512x512", "type": "image/png"},
			{"src": assetURL("/static/icons/icon-maskable-192.png"), "sizes": "192x192", "type": "image/png", "purpose": "maskable"},
			{"src": assetURL("/static/icons/icon-maskable-512.png"), "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
		},
	}
	writeVersionedJSON(w, r, manifest)
}

// handleServiceWorker serves a build-stamped worker with a guaranteed offline
// response. Only pages marked X-Offline-Cache: public are retained for use offline.
func (s *Server) handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	base := s.GetBaseURL(r)
	stamp := Version + "-" + CommitID
	configHash := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", s.config.Web.UI.Accent, s.config.Notifications.WebUI.Duration, s.config.Notifications.WebUI.WarningDuration)))
	cacheName := constants.InternalName + "-cache-" + stamp + "-" + hex.EncodeToString(configHash[:6])
	script := `const CACHE_NAME = @@CACHE@@;
const CACHE_PREFIX = @@PREFIX@@;
const BASE_PATH = @@BASE@@;
const STAMP = @@STAMP@@;
const STRINGS_CACHE = @@STRINGS@@;
const NAV_TIMEOUT_MS = 8000;
const PRECACHE_ASSETS = [
  BASE_PATH + '/static/css/common.css?v=' + STAMP,
  BASE_PATH + '/static/css/components.css?v=' + STAMP,
  BASE_PATH + '/static/css/public.css?v=' + STAMP,
  BASE_PATH + '/static/js/app.js?v=' + STAMP,
  BASE_PATH + '/static/icons/icon-192.png?v=' + STAMP,
  BASE_PATH + '/static/icons/icon-512.png?v=' + STAMP
];
const DEFAULT_STRINGS = {lang:'en',dir:'ltr',title:'Offline',heading:'You are offline',message:'This page could not be loaded. Check your connection and try again.'};

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(PRECACHE_ASSETS)));
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(
    keys.filter(key => key.startsWith(CACHE_PREFIX) && key !== CACHE_NAME).map(key => caches.delete(key))
  )).then(() => self.clients.claim()));
});

function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('network timeout')), ms);
    promise.then(value => { clearTimeout(timer); resolve(value); }, error => { clearTimeout(timer); reject(error); });
  });
}

function escapeHTML(value) {
  return String(value).replace(/[&<>\"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]));
}

async function offlineResponse() {
  let strings = DEFAULT_STRINGS;
  try {
    const stored = await (await caches.open(STRINGS_CACHE)).match(BASE_PATH + '/offline-strings.json');
    if (stored) strings = Object.assign({}, DEFAULT_STRINGS, await stored.json());
  } catch (_) {}
  return new Response('<!doctype html><html lang="' + escapeHTML(strings.lang) + '" dir="' + escapeHTML(strings.dir) + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + escapeHTML(strings.title) + '</title></head><body><main><h1>' + escapeHTML(strings.heading) + '</h1><p>' + escapeHTML(strings.message) + '</p></main></body></html>', {status:503,statusText:'Service Unavailable',headers:{'Content-Type':'text/html; charset=utf-8'}});
}

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith(BASE_PATH + '/api/')) return;

  if (request.mode === 'navigate') {
    event.respondWith(withTimeout(fetch(request), NAV_TIMEOUT_MS).then(async response => {
      const cache = await caches.open(CACHE_NAME);
      if (response.redirected) {
        await cache.delete(request);
        throw new Error('navigation redirected');
      }
      if (response.ok && !response.redirected && response.headers.get('X-Offline-Cache') === 'public') {
        await cache.put(request, response.clone());
      } else {
        await cache.delete(request);
      }
      return response;
    }).catch(async () => (await caches.match(request)) || offlineResponse()).catch(() => offlineResponse()));
    return;
  }

  if (url.pathname.startsWith(BASE_PATH + '/static/')) {
    event.respondWith(caches.match(request).then(cached => cached || fetch(request).then(async response => {
      if (response.ok && !response.redirected) await (await caches.open(CACHE_NAME)).put(request, response.clone());
      return response;
    })).catch(() => new Response('', {status:504,statusText:'Gateway Timeout'})));
  }
});

self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});
`
	script = strings.NewReplacer(
		"@@CACHE@@", jsString(cacheName),
		"@@PREFIX@@", jsString(constants.InternalName+"-cache-"),
		"@@BASE@@", jsString(base),
		"@@STAMP@@", jsString(stamp),
		"@@STRINGS@@", jsString(constants.InternalName+"-offline-strings"),
	).Replace(script)
	w.Header().Set("Service-Worker-Allowed", s.withBaseURL(r, "/"))
	writeVersionedScript(w, r, []byte(script), stamp)
}

// handleOfflineStrings returns language-specific, non-sensitive copy for the
// service worker's synthesized fallback page.
func (s *Server) handleOfflineStrings(w http.ResponseWriter, r *http.Request) {
	lang := LangFromContext(r.Context())
	strings := map[string]string{
		"lang": lang, "dir": i18n.Dir(lang),
		"title":   translateKey(lang, "pwa.offline_title"),
		"heading": translateKey(lang, "pwa.offline_title"),
		"message": translateKey(lang, "pwa.offline_message"),
	}
	body, err := json.Marshal(strings)
	if err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
		return
	}
	writeVersioned(w, r, "application/json; charset=utf-8", body)
}

func jsString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func writeVersionedJSON(w http.ResponseWriter, r *http.Request, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
		return
	}
	writeVersioned(w, r, "application/manifest+json; charset=utf-8", body)
}

func writeVersionedScript(w http.ResponseWriter, r *http.Request, body []byte, stamp string) {
	writeVersioned(w, r, "application/javascript; charset=utf-8", body, stamp)
}

func writeVersioned(w http.ResponseWriter, r *http.Request, contentType string, body []byte, stamps ...string) {
	stamp := Version + "-" + CommitID
	if len(stamps) > 0 {
		stamp = stamps[0]
	}
	etag := fmt.Sprintf("\"%s\"", strings.ReplaceAll(stamp, "\"", ""))
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) setHTMLCacheHeaders(header http.Header, r *http.Request) {
	if !strings.HasPrefix(strings.ToLower(header.Get("Content-Type")), "text/html") {
		return
	}
	stamp := Version + "-" + CommitID
	cacheControl := "no-store"
	if strings.Contains(strings.ToLower(header.Get("Cache-Control")), "private") {
		cacheControl = "private, no-store"
	}
	header.Set("Cache-Control", cacheControl)
	header.Set("ETag", `"`+stamp+`"`)
	if cookie, err := r.Cookie(constants.InternalName + "_build"); err == nil && cookie.Value != stamp {
		header.Set("Clear-Site-Data", `"cache", "storage"`)
	}
	cookie := (&http.Cookie{
		Name: constants.InternalName + "_build", Value: stamp, Path: "/",
		MaxAge: 31536000, Secure: true, SameSite: http.SameSiteLaxMode,
	}).String()
	cookiePrefix := constants.InternalName + "_build="
	setCookies := header.Values("Set-Cookie")
	header.Del("Set-Cookie")
	for _, existing := range setCookies {
		if !strings.HasPrefix(existing, cookiePrefix) {
			header.Add("Set-Cookie", existing)
		}
	}
	header.Add("Set-Cookie", cookie)
}
