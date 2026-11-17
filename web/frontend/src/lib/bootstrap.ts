import type { RuntimeConfig } from "@/types/api";

declare global {
  interface Window {
    __VPN_UI_RUNTIME__?: Partial<RuntimeConfig>;
  }
}

export function normalizeBasePath(raw?: string): string {
  const trimmed = (raw ?? "/").trim();
  if (!trimmed || trimmed === "/") return "/";
  const withLeading = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withLeading.endsWith("/") ? withLeading : `${withLeading}/`;
}

export function deriveBasePathFromLocation(): string {
  if (typeof window === "undefined") return "/";
  const pathname = window.location.pathname || "/";
  const appMarker = pathname.indexOf("/app");
  if (appMarker === 0) return "/";
  if (appMarker > 0) return normalizeBasePath(pathname.slice(0, appMarker + 1));
  return "/";
}

let cachedRuntime: RuntimeConfig | null = null;

export function getRuntimeConfig(): RuntimeConfig {
  if (cachedRuntime) return cachedRuntime;
  const injected = typeof window !== "undefined" ? window.__VPN_UI_RUNTIME__ : undefined;
  const basePath = normalizeBasePath(injected?.basePath || deriveBasePathFromLocation());
  const appBasePath = normalizeBasePath(injected?.appBasePath || `${basePath}app/`);

  cachedRuntime = {
    basePath,
    appBasePath,
    apiBasePath: normalizeBasePath(injected?.apiBasePath || `${basePath}panel/api/`),
    wsPath: injected?.wsPath || `${basePath}ws`,
    manifestUrl: injected?.manifestUrl || `${basePath}manifest.webmanifest`,
    swUrl: injected?.swUrl || `${basePath}sw.js`,
    version: injected?.version || "2.0.2",
    assetVersion: injected?.assetVersion || "",
  };
  return cachedRuntime;
}

export function setRuntimeBasePaths(basePath: string, appBasePath?: string): void {
  const normalizedBase = normalizeBasePath(basePath);
  const normalizedApp = normalizeBasePath(appBasePath || `${normalizedBase}app/`);
  cachedRuntime = {
    ...getRuntimeConfig(),
    basePath: normalizedBase,
    appBasePath: normalizedApp,
    apiBasePath: `${normalizedBase}panel/api/`,
    wsPath: `${normalizedBase}ws`,
    manifestUrl: `${normalizedBase}manifest.webmanifest`,
    swUrl: `${normalizedBase}sw.js`,
  };
}

export interface BeforeInstallPromptEvent extends Event {
  prompt(): Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed"; platform: string }>;
}

export function registerPanelServiceWorker(onUpdateFound?: () => void): void {
  if (typeof window === "undefined" || !("serviceWorker" in navigator)) return;
  // Never register stale SW in Vite hot-reload dev mode unless built bundle is active.
  if (import.meta.env.DEV) return;

  const runtime = getRuntimeConfig();
  const swUrl = runtime.swUrl || `${runtime.basePath}sw.js`;
  const scope = runtime.appBasePath;

  window.addEventListener("load", () => {
    navigator.serviceWorker
      .register(swUrl, { scope })
      .then((reg) => {
        reg.addEventListener("updatefound", () => {
          const installing = reg.installing;
          if (!installing) return;
          installing.addEventListener("statechange", () => {
            if (installing.state === "installed" && navigator.serviceWorker.controller) {
              onUpdateFound?.();
            }
          });
        });
      })
      .catch(() => {
        // Non-fatal on insecure non-localhost origins or restricted environments.
      });
  });
}
