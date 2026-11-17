import { computed, ref } from "vue";
import { defineStore } from "pinia";
import { panelApi, setUnauthorizedHandler } from "@/api/client";
import {
  getRuntimeConfig,
  registerPanelServiceWorker,
  setRuntimeBasePaths,
  type BeforeInstallPromptEvent,
} from "@/lib/bootstrap";
import {
  detectInitialLocale,
  RTL_LOCALES,
  setActiveLocale,
  type LocaleCode,
} from "@/i18n";
import type { BootstrapPayload } from "@/types/api";

export type ThemeMode = "light" | "dark" | "ultra-dark";

function readInitialTheme(): ThemeMode {
  if (typeof localStorage === "undefined") return "dark";
  const darkPref = localStorage.getItem("dark-mode");
  if (darkPref === "false") return "light";
  if (localStorage.getItem("isUltraDarkThemeEnabled") === "true") return "ultra-dark";
  return "dark";
}

function applyThemeToDom(mode: ThemeMode): void {
  if (typeof document === "undefined") return;
  const html = document.documentElement;
  const body = document.body;

  if (mode === "light") {
    body.setAttribute("class", "light");
    html.removeAttribute("data-theme");
    html.style.colorScheme = "light";
  } else if (mode === "ultra-dark") {
    body.setAttribute("class", "dark");
    html.setAttribute("data-theme", "ultra-dark");
    html.style.colorScheme = "dark";
  } else {
    body.setAttribute("class", "dark");
    html.removeAttribute("data-theme");
    html.style.colorScheme = "dark";
  }

  const metaTheme = document.querySelector('meta[name="theme-color"]');
  if (metaTheme) {
    metaTheme.setAttribute("content", mode === "light" ? "#008771" : "#0a1222");
  }
}

export const useAppStore = defineStore("app", () => {
  const initialized = ref(false);
  const loadingBootstrap = ref(false);
  const bootstrap = ref<BootstrapPayload | null>(null);
  const theme = ref<ThemeMode>(readInitialTheme());
  const locale = ref<LocaleCode>(detectInitialLocale());
  const online = ref(typeof navigator !== "undefined" ? navigator.onLine : true);
  const installPrompt = ref<BeforeInstallPromptEvent | null>(null);
  const swUpdateAvailable = ref(false);

  const authenticated = computed(() => Boolean(bootstrap.value?.authenticated && bootstrap.value?.user));
  const user = computed(() => bootstrap.value?.user ?? null);
  const perms = computed(() => bootstrap.value?.perms ?? {});
  const reseller = computed(() => bootstrap.value?.reseller ?? { isReseller: false });
  const capabilities = computed(() => bootstrap.value?.capabilities ?? null);
  const ui = computed(() => bootstrap.value?.ui ?? null);
  const donate = computed(() => bootstrap.value?.donate ?? []);
  const isRtl = computed(() => RTL_LOCALES.has(locale.value));
  const runtime = computed(() => getRuntimeConfig());
  const canInstallPwa = computed(() => installPrompt.value !== null);

  function setTheme(next: ThemeMode): void {
    theme.value = next;
    applyThemeToDom(next);
    if (typeof localStorage !== "undefined") {
      if (next === "light") {
        localStorage.setItem("dark-mode", "false");
        localStorage.setItem("isUltraDarkThemeEnabled", "false");
      } else if (next === "ultra-dark") {
        localStorage.setItem("dark-mode", "true");
        localStorage.setItem("isUltraDarkThemeEnabled", "true");
      } else {
        localStorage.setItem("dark-mode", "true");
        localStorage.setItem("isUltraDarkThemeEnabled", "false");
      }
    }
  }

  function cycleTheme(): void {
    const order: ThemeMode[] = ["dark", "ultra-dark", "light"];
    const next = order[(order.indexOf(theme.value) + 1) % order.length];
    setTheme(next);
  }

  async function changeLocale(code: string): Promise<void> {
    const active = await setActiveLocale(code, true);
    locale.value = active;
  }

  async function initBootstrap(): Promise<BootstrapPayload | null> {
    loadingBootstrap.value = true;
    try {
      const data = await panelApi.fetchBootstrap();
      bootstrap.value = data;
      if (data.basePath) {
        setRuntimeBasePaths(data.basePath, data.appBasePath);
      }
      const targetLocale = detectInitialLocale(data.defaultLocale || "en-US");
      locale.value = await setActiveLocale(targetLocale, false);
      return data;
    } finally {
      loadingBootstrap.value = false;
      initialized.value = true;
    }
  }

  function clearSession(): void {
    if (bootstrap.value) {
      bootstrap.value = {
        ...bootstrap.value,
        authenticated: false,
        user: undefined,
        perms: undefined,
        reseller: undefined,
        ui: undefined,
        capabilities: undefined,
        donate: undefined,
      };
    }
  }

  async function logout(): Promise<void> {
    try {
      await panelApi.logout();
    } finally {
      clearSession();
    }
  }

  async function triggerPwaInstall(): Promise<void> {
    if (!installPrompt.value) return;
    await installPrompt.value.prompt();
    await installPrompt.value.userChoice.catch(() => undefined);
    installPrompt.value = null;
  }

  function initEnvironmentListeners(): void {
    applyThemeToDom(theme.value);
    if (typeof window === "undefined") return;

    window.addEventListener("online", () => {
      online.value = true;
    });
    window.addEventListener("offline", () => {
      online.value = false;
    });
    window.addEventListener("beforeinstallprompt", (ev) => {
      ev.preventDefault();
      installPrompt.value = ev as BeforeInstallPromptEvent;
    });
    window.addEventListener("appinstalled", () => {
      installPrompt.value = null;
    });

    registerPanelServiceWorker(() => {
      swUpdateAvailable.value = true;
    });
  }

  setUnauthorizedHandler(() => {
    clearSession();
  });

  return {
    initialized,
    loadingBootstrap,
    bootstrap,
    theme,
    locale,
    online,
    canInstallPwa,
    swUpdateAvailable,
    authenticated,
    user,
    perms,
    reseller,
    capabilities,
    ui,
    donate,
    isRtl,
    runtime,
    setTheme,
    cycleTheme,
    changeLocale,
    initBootstrap,
    clearSession,
    logout,
    triggerPwaInstall,
    initEnvironmentListeners,
  };
});
