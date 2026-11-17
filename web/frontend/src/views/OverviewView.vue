<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { ApiError, buildWebSocketUrl, panelApi } from "@/api/client";
import AppShell from "@/components/AppShell.vue";
import M3Icon from "@/components/M3Icon.vue";
import { useAppStore } from "@/stores/app";
import type { ServerStatusSnapshot } from "@/types/api";

const { t } = useI18n();
const appStore = useAppStore();

const status = ref<ServerStatusSnapshot | null>(null);
const loadingStatus = ref(false);
const statusError = ref("");
let ws: WebSocket | null = null;
let stopped = false;

const canViewOverview = computed(
  () =>
    Boolean(
      appStore.perms.accessOverview ||
        appStore.user?.isSuperAdmin ||
        appStore.reseller?.allowOverview,
    ),
);

const canViewCores = computed(() =>
  Boolean(appStore.perms.coreSettings || appStore.user?.isSuperAdmin),
);

function formatBytes(bytes?: number): string {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let idx = 0;
  let val = bytes;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx += 1;
  }
  return `${val.toFixed(val >= 100 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

async function refresh(): Promise<void> {
  loadingStatus.value = true;
  statusError.value = "";
  try {
    await appStore.initBootstrap();
    if (canViewOverview.value) {
      status.value = await panelApi.fetchServerStatus();
    }
  } catch (err) {
    if (err instanceof ApiError && err.status !== 401) {
      statusError.value = err.message;
    }
  } finally {
    loadingStatus.value = false;
  }
}

function connectSocket(): void {
  if (typeof WebSocket === "undefined" || !canViewOverview.value) return;
  try {
    ws = new WebSocket(buildWebSocketUrl());
    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(String(event.data)) as { type?: string; payload?: unknown };
        if (msg?.type === "status" && msg.payload && typeof msg.payload === "object") {
          status.value = msg.payload as ServerStatusSnapshot;
        }
      } catch {
        // Ignore non-JSON or unrecognized WebSocket frames.
      }
    };
    ws.onclose = () => {
      if (!stopped) {
        window.setTimeout(() => {
          if (!stopped && appStore.authenticated) connectSocket();
        }, 5000);
      }
    };
  } catch {
    // Graceful degradation to manual/periodic refresh when WS cannot open.
  }
}

onMounted(async () => {
  await refresh();
  connectSocket();
});

onBeforeUnmount(() => {
  stopped = true;
  if (ws) {
    ws.close();
    ws = null;
  }
});
</script>

<template>
  <AppShell>
    <div class="overview-grid">
      <section class="m3-card overview-hero">
        <div class="hero-row">
          <div>
            <h1 class="section-title">{{ t("pages.index.title") }}</h1>
            <p class="section-sub">
              {{ appStore.ui?.serverName || appStore.bootstrap?.host }}
              <span class="mono-tag">{{ appStore.runtime.basePath }}</span>
            </p>
          </div>
          <div class="hero-actions">
            <button type="button" class="m3-btn m3-btn--outlined" :disabled="loadingStatus" @click="refresh">
              <M3Icon name="refresh" :size="18" />
              <span>{{ t("pages.core.refresh") }}</span>
            </button>
            <RouterLink v-if="canViewCores" to="/cores" class="m3-btn m3-btn--primary">
              <M3Icon name="memory" :size="18" />
              <span>{{ t("spa.navCore") }}</span>
            </RouterLink>
          </div>
        </div>

        <div v-if="statusError" class="m3-pill m3-pill--error">{{ statusError }}</div>

        <div v-if="status" class="telemetry-row">
          <div class="telemetry-tile">
            <span class="tile-label">CPU</span>
            <strong class="tile-value">{{ status.cpu.toFixed(1) }}%</strong>
            <span class="tile-sub">{{ status.cpuCores }} cores</span>
          </div>
          <div class="telemetry-tile">
            <span class="tile-label">Memory</span>
            <strong class="tile-value">{{ formatBytes(status.mem?.current) }}</strong>
            <span class="tile-sub">/ {{ formatBytes(status.mem?.total) }}</span>
          </div>
          <div class="telemetry-tile">
            <span class="tile-label">Disk</span>
            <strong class="tile-value">{{ formatBytes(status.disk?.current) }}</strong>
            <span class="tile-sub">/ {{ formatBytes(status.disk?.total) }}</span>
          </div>
          <div class="telemetry-tile">
            <span class="tile-label">Xray</span>
            <strong class="tile-value">{{ status.xray?.state || "-" }}</strong>
            <span class="tile-sub">{{ status.xray?.version || "" }}</span>
          </div>
        </div>
      </section>

      <section v-if="appStore.capabilities" class="m3-card">
        <div class="cap-head">
          <h2>{{ t("spa.capabilities") }}</h2>
          <span
            class="m3-pill"
            :class="appStore.capabilities.provisioned ? 'm3-pill--ok' : 'm3-pill--warn'"
          >
            {{
              appStore.capabilities.provisioned
                ? t("spa.provisioned")
                : t("spa.notProvisioned")
            }}
          </span>
        </div>

        <div class="cap-meta">
          <span class="meta-chip">{{ appStore.capabilities.os }} / {{ appStore.capabilities.arch }}</span>
          <span class="meta-chip">
            AWG: {{ appStore.capabilities.protocols.awgMode }}
          </span>
          <span class="meta-chip">
            Xray: {{ appStore.capabilities.protocols.xrayVersion || "-" }}
            <template v-if="appStore.capabilities.protocols.xrayPatched">(patched)</template>
          </span>
          <span class="meta-chip">
            Hysteria 2: {{ appStore.capabilities.protocols.hysteria2Available ? t("enabled") : t("disabled") }}
          </span>
        </div>

        <div class="engines-list">
          <div
            v-for="eng in appStore.capabilities.engines"
            :key="eng.id"
            class="engine-row"
          >
            <div class="engine-info">
              <strong>{{ eng.title }}</strong>
              <span>{{ eng.protocols }}</span>
            </div>
            <div class="engine-badges">
              <span v-if="eng.version" class="mono-tag">{{ eng.version }}</span>
              <span
                class="m3-pill"
                :class="eng.available ? 'm3-pill--ok' : 'm3-pill--warn'"
              >
                {{ eng.available ? t("pages.core.installedTag") : t("pages.core.missing") }}
              </span>
            </div>
          </div>
        </div>
      </section>
    </div>
  </AppShell>
</template>

<style scoped>
.overview-grid {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.overview-hero {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.hero-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
}

.section-title {
  margin: 0 0 4px;
  font-size: 22px;
}

.section-sub {
  margin: 0;
  color: var(--md-sys-color-on-surface-variant);
  display: flex;
  align-items: center;
  gap: 8px;
}

.hero-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.telemetry-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 12px;
}

.telemetry-tile {
  background: var(--md-sys-color-surface-container-low);
  border: 1px solid var(--md-sys-color-outline-variant);
  border-radius: var(--md-shape-md);
  padding: 14px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.tile-label {
  font-size: 12px;
  color: var(--md-sys-color-on-surface-variant);
}

.tile-value {
  font-size: 20px;
}

.tile-sub {
  font-size: 12px;
  color: var(--md-sys-color-on-surface-variant);
}

.cap-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.cap-head h2 {
  margin: 0;
  font-size: 17px;
}

.cap-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 16px;
}

.meta-chip {
  padding: 4px 10px;
  border-radius: 999px;
  background: var(--md-sys-color-surface-container);
  font-size: 12px;
}

.mono-tag {
  font-family: var(--font-mono);
  font-size: 12px;
  padding: 2px 8px;
  border-radius: 6px;
  background: var(--md-sys-color-surface-container);
}

.engines-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 10px;
}

.engine-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px;
  border-radius: var(--md-shape-md);
  background: var(--md-sys-color-surface-container-low);
  border: 1px solid var(--md-sys-color-outline-variant);
}

.engine-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.engine-info span {
  font-size: 12px;
  color: var(--md-sys-color-on-surface-variant);
}

.engine-badges {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}
</style>
