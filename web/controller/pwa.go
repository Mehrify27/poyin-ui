package controller

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mhsanaei/3x-ui/v2/config"

	"github.com/gin-gonic/gin"
)

// PWAController serves a dynamic, webBasePath-aware Web App Manifest and
// Service Worker script scoped strictly to the SPA shell.
type PWAController struct{}

// NewPWAController registers dynamic PWA routes under the panel's basePath group.
func NewPWAController(g *gin.RouterGroup) *PWAController {
	p := &PWAController{}
	g.GET("/manifest.webmanifest", p.Manifest)
	g.GET("/sw.js", p.ServiceWorker)
	return p
}

// Manifest serves <basePath>manifest.webmanifest with dynamic start_url, scope,
// id, icons, and adaptive theme colors matching the active webBasePath.
func (p *PWAController) Manifest(c *gin.Context) {
	basePath := normalizeBasePath(c.GetString("base_path"))
	appBase := basePath + "app/"

	manifest := gin.H{
		"id":               appBase,
		"name":             "VPN-UI Control Panel",
		"short_name":       "VPN-UI",
		"description":      "Multi-protocol VPN & Xray management console",
		"start_url":        appBase,
		"scope":            appBase,
		"display":          "standalone",
		"orientation":      "any",
		"background_color": "#0a1222",
		"theme_color":      "#008771",
		"icons": []gin.H{
			{
				"src":     appBase + "icons/icon-192.png",
				"sizes":   "192x192",
				"type":    "image/png",
				"purpose": "any",
			},
			{
				"src":     appBase + "icons/icon-512.png",
				"sizes":   "512x512",
				"type":    "image/png",
				"purpose": "any",
			},
			{
				"src":     appBase + "icons/icon-512-maskable.png",
				"sizes":   "512x512",
				"type":    "image/png",
				"purpose": "maskable",
			},
			{
				"src":     appBase + "icons/logo.svg",
				"sizes":   "any",
				"type":    "image/svg+xml",
				"purpose": "any",
			},
		},
	}

	c.Header("Content-Type", "application/manifest+json; charset=utf-8")
	c.Header("Cache-Control", "no-cache")
	c.JSON(http.StatusOK, manifest)
}

// ServiceWorker serves <basePath>sw.js with strict static-only caching rules:
// only hashed SPA UI shell assets under appBase are cached; API calls, auth,
// WebSockets, panel forms, and subscription endpoints are always network-only.
func (p *PWAController) ServiceWorker(c *gin.Context) {
	basePath := normalizeBasePath(c.GetString("base_path"))
	appBase := basePath + "app/"
	cacheVersion := fmt.Sprintf("vpn-ui-shell-%s", config.GetAssetVersion())

	baseJSON, _ := json.Marshal(basePath)
	appJSON, _ := json.Marshal(appBase)
	cacheJSON, _ := json.Marshal(cacheVersion)

	script := fmt.Sprintf(`/* VPN-UI Service Worker (webBasePath-scoped, static UI shell only) */
const BASE_PATH = %s;
const APP_BASE = %s;
const CACHE_NAME = %s;
const OFFLINE_URL = APP_BASE + "offline.html";
const SHELL_PRECACHE = [OFFLINE_URL, APP_BASE + "icons/logo.svg"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_PRECACHE)).catch(() => undefined)
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key.startsWith("vpn-ui-shell-") && key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

function isExcludedPath(pathname) {
  if (!pathname.startsWith(BASE_PATH)) return true;
  const rel = pathname.slice(BASE_PATH.length);
  if (
    rel.startsWith("api/") ||
    rel.startsWith("panel/") ||
    rel.startsWith("sub/") ||
    rel === "ws" ||
    rel.startsWith("ws/") ||
    rel === "login" ||
    rel.startsWith("login/") ||
    rel === "logout" ||
    rel.startsWith("logout/") ||
    rel === "getTwoFactorEnable" ||
    rel === "manifest.webmanifest" ||
    rel === "sw.js"
  ) {
    return true;
  }
  return false;
}

function isStaticAsset(pathname) {
  if (!pathname.startsWith(APP_BASE)) return false;
  return (
    pathname.startsWith(APP_BASE + "assets/") ||
    pathname.startsWith(APP_BASE + "icons/") ||
    /\.(?:js|mjs|css|woff2?|ttf|svg|png|ico|webp)$/i.test(pathname)
  );
}

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (isExcludedPath(url.pathname)) return;
  if (!url.pathname.startsWith(APP_BASE)) return;

  // Navigation requests under APP_BASE: always try network first (fresh base_path &
  // cookies); fall back cleanly to offline shell when disconnected.
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req, { cache: "no-store" }).catch(async () => {
        const cache = await caches.open(CACHE_NAME);
        const offline = await cache.match(OFFLINE_URL);
        if (offline) return offline;
        return new Response("Offline", {
          status: 503,
          headers: { "Content-Type": "text/plain; charset=utf-8" },
        });
      })
    );
    return;
  }

  // Static bundled assets (hashed JS/CSS/fonts/icons): stale/cache-first for fast offline shell.
  if (isStaticAsset(url.pathname)) {
    event.respondWith(
      caches.open(CACHE_NAME).then(async (cache) => {
        const cached = await cache.match(req);
        if (cached) return cached;
        const resp = await fetch(req);
        if (resp && resp.ok && resp.type === "basic") {
          cache.put(req, resp.clone()).catch(() => undefined);
        }
        return resp;
      })
    );
  }
});
`, string(baseJSON), string(appJSON), string(cacheJSON))

	c.Header("Content-Type", "application/javascript; charset=utf-8")
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Service-Worker-Allowed", basePath)
	c.String(http.StatusOK, script)
}
