<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { ApiError, panelApi } from "@/api/client";
import AppShell from "@/components/AppShell.vue";
import M3Icon from "@/components/M3Icon.vue";
import { useAppStore } from "@/stores/app";
import type {
  CoreBinaryInventory,
  NetworkTuningStatus,
  XrayBinaryCapabilities,
} from "@/types/api";

const { t } = useI18n();
const appStore = useAppStore();

const loading = ref(false);
const actingProfile = ref(false);
const savingForkEngine = ref(false);
const errorMessage = ref("");
const binaries = ref<CoreBinaryInventory[]>([]);
const xrayCaps = ref<XrayBinaryCapabilities | null>(null);
const forkProtocolEngine = ref("auto");
const speedLimitEngine = ref("in-core-xray");
const netTuning = ref<NetworkTuningStatus | null>(null);
const selectedProfile = ref("vpn-performance");

const isSuperAdmin = computed(() => Boolean(appStore.user?.isSuperAdmin));

function binaryModeLabel(mode?: string): string {
  switch (mode) {
    case "bundled-patched":
      return "Bundled Patched (XTLS)";
    case "custom-patched":
      return "Custom Patched";
    case "official-xtls-unpatched":
      return "Official XTLS";
    default:
      return mode || "-";
  }
}

async function loadData(): Promise<void> {
  loading.value = true;
  errorMessage.value = "";
  try {
    const [versionsRes, tuningRes] = await Promise.all([
      panelApi.fetchCoreVersions(),
      panelApi.fetchNetworkTuning(),
    ]);
    binaries.value = versionsRes.binaries ?? [];
    xrayCaps.value = versionsRes.xrayCapabilities ?? null;
    if (versionsRes.forkProtocolEngine) {
      forkProtocolEngine.value = versionsRes.forkProtocolEngine;
    }
    if (versionsRes.speedLimitEngine) {
      speedLimitEngine.value = versionsRes.speedLimitEngine;
    }
    netTuning.value = tuningRes;
    if (tuningRes.activeProfile) {
      selectedProfile.value = tuningRes.activeProfile;
    }
  } catch (err) {
    errorMessage.value = err instanceof ApiError ? err.message : t("somethingWentWrong");
  } finally {
    loading.value = false;
  }
}

async function applyForkProtocolEngine(): Promise<void> {
  savingForkEngine.value = true;
  errorMessage.value = "";
  try {
    const res = await panelApi.setForkProtocolEngine(forkProtocolEngine.value);
    if (res.binaries) binaries.value = res.binaries;
    if (res.xrayCapabilities) xrayCaps.value = res.xrayCapabilities;
    if (res.forkProtocolEngine) forkProtocolEngine.value = res.forkProtocolEngine;
    if (res.speedLimitEngine) speedLimitEngine.value = res.speedLimitEngine;
  } catch (err) {
    errorMessage.value = err instanceof ApiError ? err.message : t("somethingWentWrong");
  } finally {
    savingForkEngine.value = false;
  }
}

async function applyBbrProfile(): Promise<void> {
  actingProfile.value = true;
  errorMessage.value = "";
  try {
    netTuning.value = await panelApi.applyNetworkTuning(selectedProfile.value);
  } catch (err) {
    errorMessage.value = err instanceof ApiError ? err.message : t("somethingWentWrong");
  } finally {
    actingProfile.value = false;
  }
}

async function revertBbrProfile(): Promise<void> {
  actingProfile.value = true;
  errorMessage.value = "";
  try {
    netTuning.value = await panelApi.revertNetworkTuning();
  } catch (err) {
    errorMessage.value = err instanceof ApiError ? err.message : t("somethingWentWrong");
  } finally {
    actingProfile.value = false;
  }
}

onMounted(loadData);
</script>

<template>
  <AppShell>
    <div class="cores-stack">
      <div class="cores-header">
        <div>
          <h1>{{ t("pages.core.title") }}</h1>
          <p>{{ t("spa.core.sidecarUpdaterDesc") }}</p>
        </div>
        <button type="button" class="m3-btn m3-btn--outlined" :disabled="loading" @click="loadData">
          <M3Icon name="refresh" :size="18" />
          <span>{{ t("pages.core.refresh") }}</span>
        </button>
      </div>

      <div v-if="errorMessage" class="m3-pill m3-pill--error">{{ errorMessage }}</div>

      <section v-if="netTuning" class="m3-card tuning-card">
        <div class="card-head">
          <h2>{{ t("spa.core.networkTuningTitle") }}</h2>
          <span
            class="m3-pill"
            :class="netTuning.bbrActive ? 'm3-pill--ok' : 'm3-pill--warn'"
          >
            {{ netTuning.bbrActive ? t("spa.core.bbrActive") : t("spa.core.bbrInactive") }}
          </span>
        </div>

        <div class="tuning-metrics">
          <span class="metric-chip">Kernel: {{ netTuning.kernelRelease || "-" }}</span>
          <span class="metric-chip">CC: {{ netTuning.congestionControl || "-" }}</span>
          <span class="metric-chip">Qdisc: {{ netTuning.defaultQdisc || "-" }}</span>
          <span v-if="netTuning.bestBBRVariant" class="metric-chip">
            Best: {{ netTuning.bestBBRVariant }}
          </span>
        </div>

        <p v-if="netTuning.message" class="tuning-note">{{ netTuning.message }}</p>

        <div v-if="isSuperAdmin" class="tuning-controls">
          <select v-model="selectedProfile" class="profile-select">
            <option value="bbr">bbr</option>
            <option value="vpn-performance">vpn-performance</option>
          </select>
          <button
            type="button"
            class="m3-btn m3-btn--primary"
            :disabled="actingProfile || netTuning.readOnlySysctl"
            @click="applyBbrProfile"
          >
            <M3Icon name="speed" :size="18" />
            <span>{{ t("spa.core.applyTuning") }}</span>
          </button>
          <button
            v-if="netTuning.canRevert"
            type="button"
            class="m3-btn m3-btn--outlined"
            :disabled="actingProfile || netTuning.readOnlySysctl"
            @click="revertBbrProfile"
          >
            <span>{{ t("spa.core.revertTuning") }}</span>
          </button>
        </div>
      </section>

      <section class="m3-card">
        <div class="card-head">
          <h2>{{ t("spa.core.sidecarUpdaterTitle") }}</h2>
          <div class="tuning-metrics">
            <span v-if="xrayCaps" class="metric-chip">{{ binaryModeLabel(xrayCaps.binaryMode) }}</span>
            <span class="metric-chip">{{ speedLimitEngine }}</span>
          </div>
        </div>

        <div v-if="isSuperAdmin" class="tuning-controls" style="margin-bottom: 14px">
          <select v-model="forkProtocolEngine" class="profile-select">
            <option value="auto">AnyTLS/TUIC/Naive: Auto</option>
            <option value="sing-box">AnyTLS/TUIC/Naive: sing-box</option>
            <option value="xray">AnyTLS/TUIC/Naive: Patched Xray</option>
          </select>
          <button
            type="button"
            class="m3-btn m3-btn--outlined"
            :disabled="savingForkEngine"
            @click="applyForkProtocolEngine"
          >
            <span>{{ t("confirm") }}</span>
          </button>
        </div>

        <div class="binaries-grid">
          <article v-for="bin in binaries" :key="bin.core" class="binary-card">
            <div class="binary-top">
              <div>
                <strong>{{ bin.core }}</strong>
                <div class="binary-sub">{{ bin.protocols || bin.serviceCore }}</div>
              </div>
              <span class="m3-pill" :class="bin.source !== 'missing' ? 'm3-pill--ok' : 'm3-pill--warn'">
                {{ bin.source !== 'missing' ? t("pages.core.installedTag") : t("pages.core.missing") }}
              </span>
            </div>
            <div class="binary-meta">
              <span>{{ t("pages.core.version") }}: <code>{{ bin.installedVersion || bin.version || "-" }}</code></span>
              <span>{{ t("pages.core.backend") }}: <code>{{ bin.source }}</code></span>
              <span v-if="bin.binaryMode" class="m3-pill m3-pill--info">{{ binaryModeLabel(bin.binaryMode) }}</span>
              <span v-else-if="bin.customPatched" class="m3-pill m3-pill--info">custom-patched</span>
            </div>
          </article>
        </div>
      </section>
    </div>
  </AppShell>
</template>

<style scoped>
.cores-stack {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.cores-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.cores-header h1 {
  margin: 0 0 4px;
  font-size: 22px;
}

.cores-header p {
  margin: 0;
  color: var(--md-sys-color-on-surface-variant);
}

.card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
}

.card-head h2 {
  margin: 0;
  font-size: 17px;
}

.tuning-card {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.tuning-metrics {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.metric-chip {
  padding: 5px 10px;
  border-radius: 999px;
  background: var(--md-sys-color-surface-container);
  font-size: 12px;
  font-family: var(--font-mono);
}

.tuning-note {
  margin: 0;
  font-size: 13px;
  color: var(--md-sys-color-on-surface-variant);
}

.tuning-controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  margin-top: 6px;
}

.profile-select {
  height: 38px;
  padding: 0 12px;
  border-radius: 999px;
  border: 1px solid var(--md-sys-color-outline-variant);
  background: var(--md-sys-color-surface-container-low);
  color: var(--md-sys-color-on-surface);
}

.binaries-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 12px;
}

.binary-card {
  padding: 14px;
  border-radius: var(--md-shape-md);
  background: var(--md-sys-color-surface-container-low);
  border: 1px solid var(--md-sys-color-outline-variant);
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.binary-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
}

.binary-sub {
  font-size: 12px;
  color: var(--md-sys-color-on-surface-variant);
}

.binary-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  font-size: 12px;
  color: var(--md-sys-color-on-surface-variant);
}
</style>
