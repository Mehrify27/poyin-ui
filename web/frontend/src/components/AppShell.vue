<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { useRoute, useRouter } from "vue-router";
import AppLogo from "@/components/AppLogo.vue";
import M3Icon from "@/components/M3Icon.vue";
import { useAppStore } from "@/stores/app";

const { t } = useI18n();
const route = useRoute();
const router = useRouter();
const appStore = useAppStore();

const navItems = computed(() => {
  const items = [
    {
      to: "/",
      name: "overview",
      label: t("spa.navHome"),
      icon: "dashboard",
      visible: true,
    },
    {
      to: "/cores",
      name: "cores",
      label: t("spa.navCore"),
      icon: "memory",
      visible: Boolean(appStore.perms.coreSettings || appStore.user?.isSuperAdmin),
    },
  ];
  return items.filter((item) => item.visible);
});

const legacyPanelHref = computed(() => `${appStore.runtime.basePath}panel/`);

const themeIcon = computed(() => {
  if (appStore.theme === "light") return "light_mode";
  if (appStore.theme === "ultra-dark") return "contrast";
  return "dark_mode";
});

const themeLabel = computed(() => {
  if (appStore.theme === "light") return t("spa.themeLight");
  if (appStore.theme === "ultra-dark") return t("spa.themeUltraDark");
  return t("spa.themeDark");
});

const locales = computed(
  () =>
    appStore.bootstrap?.supportedLocales ?? [
      { code: "en-US", name: "English", icon: "🇺🇸", rtl: false },
      { code: "fa-IR", name: "فارسی", icon: "🇮🇷", rtl: true },
    ],
);

async function onLocaleChange(event: Event): Promise<void> {
  const select = event.target as HTMLSelectElement;
  await appStore.changeLocale(select.value);
}

async function handleLogout(): Promise<void> {
  await appStore.logout();
  await router.replace("/login");
}

function reloadForUpdate(): void {
  window.location.reload();
}
</script>

<template>
  <div class="shell-layout">
    <aside class="shell-rail">
      <div class="shell-rail-top">
        <RouterLink to="/" class="shell-brand-link" aria-label="VPN-UI Home">
          <AppLogo />
        </RouterLink>
      </div>

      <nav class="shell-nav" :aria-label="t('menu.navigation')">
        <RouterLink
          v-for="item in navItems"
          :key="item.name"
          :to="item.to"
          class="shell-nav-item"
          :class="{ 'is-active': route.name === item.name }"
        >
          <M3Icon :name="item.icon" :filled="route.name === item.name" :size="20" />
          <span>{{ item.label }}</span>
        </RouterLink>

        <a :href="legacyPanelHref" class="shell-nav-item shell-nav-item--external">
          <M3Icon name="open_in_new" :size="20" />
          <span>{{ t("spa.openLegacy") }}</span>
        </a>
      </nav>

      <div class="shell-rail-foot">
        <button
          v-if="appStore.canInstallPwa"
          type="button"
          class="m3-btn m3-btn--tonal shell-foot-btn"
          :title="t('pwa.installHint')"
          @click="appStore.triggerPwaInstall()"
        >
          <M3Icon name="install_desktop" :size="18" />
          <span>{{ t("pwa.installApp") }}</span>
        </button>

        <div class="shell-controls-row">
          <button
            type="button"
            class="shell-icon-btn"
            :title="themeLabel"
            @click="appStore.cycleTheme()"
          >
            <M3Icon :name="themeIcon" :size="18" />
          </button>

          <select
            class="shell-lang-select"
            :aria-label="t('spa.language')"
            :value="appStore.locale"
            @change="onLocaleChange"
          >
            <option v-for="loc in locales" :key="loc.code" :value="loc.code">
              {{ loc.name }}
            </option>
          </select>
        </div>

        <button type="button" class="shell-nav-item shell-logout-btn" @click="handleLogout">
          <M3Icon name="logout" :size="18" />
          <span>{{ t("menu.logout") }}</span>
        </button>
      </div>
    </aside>

    <div class="shell-main-wrap">
      <header class="shell-topbar">
        <div class="shell-topbar-left">
          <RouterLink to="/" class="shell-mobile-brand">
            <AppLogo compact :size="30" />
          </RouterLink>
          <div class="shell-title-group">
            <span class="shell-server-name">
              {{ appStore.ui?.serverName || appStore.bootstrap?.host || "VPN-UI" }}
            </span>
            <span class="shell-version-badge">v{{ appStore.bootstrap?.version || "2.0.3" }}</span>
          </div>
        </div>

        <div class="shell-topbar-right">
          <span
            class="m3-pill"
            :class="appStore.online ? 'm3-pill--ok' : 'm3-pill--error'"
          >
            <M3Icon :name="appStore.online ? 'cloud_done' : 'cloud_off'" :size="14" />
            <span>{{ appStore.online ? t("spa.backendConnected") : t("offline") }}</span>
          </span>
          <span v-if="appStore.user" class="shell-user-chip">
            <M3Icon name="person" :size="16" />
            <span>{{ appStore.user.username }}</span>
          </span>
        </div>
      </header>

      <div v-if="!appStore.online" class="shell-banner shell-banner--offline" role="status">
        <M3Icon name="wifi_off" :size="20" />
        <div class="shell-banner-text">
          <strong>{{ t("pwa.offlineTitle") }}</strong>
          <span>{{ t("pwa.offlineDesc") }}</span>
        </div>
        <button type="button" class="m3-btn m3-btn--outlined" @click="appStore.initBootstrap()">
          {{ t("pwa.retry") }}
        </button>
      </div>

      <div v-if="appStore.swUpdateAvailable" class="shell-banner shell-banner--info" role="status">
        <M3Icon name="system_update" :size="20" />
        <div class="shell-banner-text">
          <span>{{ t("pwa.updateAvailable") }}</span>
        </div>
        <button type="button" class="m3-btn m3-btn--tonal" @click="reloadForUpdate">
          {{ t("pages.core.refresh") }}
        </button>
      </div>

      <main class="shell-content">
        <slot />
      </main>

      <nav class="shell-mobile-bar" :aria-label="t('menu.navigation')">
        <RouterLink
          v-for="item in navItems"
          :key="item.name"
          :to="item.to"
          class="shell-mobile-item"
          :class="{ 'is-active': route.name === item.name }"
        >
          <M3Icon :name="item.icon" :filled="route.name === item.name" :size="22" />
          <span>{{ item.label }}</span>
        </RouterLink>
        <a :href="legacyPanelHref" class="shell-mobile-item">
          <M3Icon name="open_in_new" :size="20" />
          <span>{{ t("spa.legacyPanel") }}</span>
        </a>
      </nav>
    </div>
  </div>
</template>

<style scoped>
.shell-layout {
  display: flex;
  min-height: 100vh;
}

.shell-rail {
  width: 244px;
  flex: 0 0 244px;
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 18px 14px;
  background: var(--md-sys-color-surface);
  border-inline-end: 1px solid var(--md-sys-color-outline-variant);
}

.shell-rail-top {
  padding: 4px 6px;
}

.shell-brand-link {
  text-decoration: none;
}

.shell-nav {
  display: flex;
  flex-direction: column;
  gap: 6px;
  flex: 1 1 auto;
}

.shell-nav-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 14px;
  border-radius: 999px;
  color: var(--md-sys-color-on-surface-variant);
  font-weight: 500;
  text-decoration: none;
  border: none;
  background: transparent;
  cursor: pointer;
  text-align: start;
  transition: background-color 0.15s ease, color 0.15s ease;
}

.shell-nav-item:hover {
  background: var(--md-sys-color-surface-container);
  color: var(--md-sys-color-on-surface);
  text-decoration: none;
}

.shell-nav-item.is-active {
  background: var(--md-sys-color-primary-container);
  color: var(--md-sys-color-primary);
  font-weight: 600;
}

.shell-rail-foot {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-top: 12px;
  border-top: 1px solid var(--md-sys-color-outline-variant);
}

.shell-foot-btn {
  width: 100%;
}

.shell-controls-row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.shell-icon-btn {
  width: 38px;
  height: 38px;
  flex: 0 0 38px;
  border-radius: 50%;
  border: 1px solid var(--md-sys-color-outline-variant);
  background: var(--md-sys-color-surface-container-low);
  color: var(--md-sys-color-on-surface);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
}

.shell-lang-select {
  flex: 1 1 auto;
  min-width: 0;
  height: 38px;
  border-radius: 999px;
  border: 1px solid var(--md-sys-color-outline-variant);
  background: var(--md-sys-color-surface-container-low);
  color: var(--md-sys-color-on-surface);
  padding: 0 12px;
}

.shell-logout-btn {
  color: var(--md-sys-color-error);
}

.shell-main-wrap {
  flex: 1 1 auto;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.shell-topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 14px 24px;
  background: var(--md-sys-color-surface);
  border-bottom: 1px solid var(--md-sys-color-outline-variant);
}

.shell-topbar-left,
.shell-topbar-right {
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 0;
}

.shell-mobile-brand {
  display: none;
}

.shell-title-group {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.shell-server-name {
  font-size: 16px;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.shell-version-badge {
  font-size: 12px;
  font-family: var(--font-mono);
  padding: 2px 8px;
  border-radius: 999px;
  background: var(--md-sys-color-surface-container);
  color: var(--md-sys-color-on-surface-variant);
}

.shell-user-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  border-radius: 999px;
  background: var(--md-sys-color-surface-container);
  font-size: 13px;
  font-weight: 500;
}

.shell-banner {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 16px 24px 0;
  padding: 12px 16px;
  border-radius: var(--md-shape-md);
  border: 1px solid var(--md-sys-color-outline-variant);
}

.shell-banner--offline {
  background: var(--md-sys-color-error-container);
  color: var(--md-sys-color-error);
}

.shell-banner--info {
  background: var(--status-info-bg);
  color: var(--status-info);
}

.shell-banner-text {
  display: flex;
  flex-direction: column;
  gap: 2px;
  flex: 1 1 auto;
}

.shell-content {
  padding: 24px;
  flex: 1 1 auto;
}

.shell-mobile-bar {
  display: none;
}

@media (max-width: 860px) {
  .shell-rail {
    display: none;
  }

  .shell-mobile-brand {
    display: inline-flex;
  }

  .shell-topbar {
    padding: 12px 16px;
  }

  .shell-content {
    padding: 16px 16px 84px;
  }

  .shell-mobile-bar {
    position: fixed;
    inset-inline: 0;
    bottom: 0;
    display: flex;
    justify-content: space-around;
    background: var(--md-sys-color-surface);
    border-top: 1px solid var(--md-sys-color-outline-variant);
    padding: 8px 6px calc(8px + env(safe-area-inset-bottom, 0px));
    z-index: 40;
  }

  .shell-mobile-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 2px;
    font-size: 11px;
    color: var(--md-sys-color-on-surface-variant);
    padding: 4px 12px;
    border-radius: 999px;
    text-decoration: none;
  }

  .shell-mobile-item.is-active {
    color: var(--md-sys-color-primary);
    font-weight: 600;
  }
}
</style>
