<script setup lang="ts">
interface Props {
  compact?: boolean;
  size?: number;
}

withDefaults(defineProps<Props>(), {
  compact: false,
  size: 34,
});
</script>

<template>
  <div class="vpnui-brand" :class="{ 'vpnui-brand--compact': compact }">
    <svg
      class="vpnui-brand-mark"
      :width="size"
      :height="size"
      viewBox="0 0 128 128"
      fill="none"
      aria-hidden="true"
    >
      <defs>
        <linearGradient id="vpnui-spa-grad" x1="12" y1="12" x2="116" y2="116" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stop-color="#008771" />
          <stop offset="55%" stop-color="#0fa68b" />
          <stop offset="100%" stop-color="#1bbf9f" />
        </linearGradient>
      </defs>
      <rect x="8" y="8" width="112" height="112" rx="30" fill="url(#vpnui-spa-grad)" />
      <rect
        x="10"
        y="10"
        width="108"
        height="108"
        rx="28"
        stroke="#ffffff"
        stroke-opacity="0.28"
        stroke-width="3"
      />
      <path
        d="M36 44L64 28L92 44V67C92 82.8 79.2 93.8 64 100C48.8 93.8 36 82.8 36 67V44Z"
        fill="#ffffff"
        fill-opacity="0.14"
        stroke="#ffffff"
        stroke-width="5.5"
        stroke-linejoin="round"
      />
      <path
        d="M50 64.5L64 50.5L78 64.5M64 51V81"
        stroke="#ffffff"
        stroke-width="6"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
    </svg>
    <div v-if="!compact" class="vpnui-brand-text">
      <span class="vpnui-brand-name">VPN-UI</span>
      <span class="vpnui-brand-sub">Panel</span>
    </div>
  </div>
</template>

<style scoped>
.vpnui-brand {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
  user-select: none;
}

.vpnui-brand-mark {
  flex: 0 0 auto;
  display: block;
}

.vpnui-brand-text {
  display: flex;
  align-items: baseline;
  gap: 6px;
  min-width: 0;
}

.vpnui-brand-name {
  font-size: 16px;
  font-weight: 700;
  letter-spacing: 0.04em;
  color: var(--md-sys-color-on-surface);
}

.vpnui-brand-sub {
  font-size: 11px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 999px;
  background: var(--md-sys-color-primary-container);
  color: var(--md-sys-color-primary);
}
</style>
