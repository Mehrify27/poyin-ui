<script setup lang="ts">
import { useI18n } from "vue-i18n";
import AppShell from "@/components/AppShell.vue";
import M3Icon from "@/components/M3Icon.vue";

const { t } = useI18n();
</script>

<template>
  <AppShell>
    <div class="m3-card not-found-card">
      <M3Icon name="explore_off" :size="40" />
      <h1>404</h1>
      <p>{{ t("somethingWentWrong") }}</p>
      <RouterLink to="/" class="m3-btn m3-btn--primary">
        {{ t("spa.navHome") }}
      </RouterLink>
    </div>
  </AppShell>
</template>

<style scoped>
.not-found-card {
  max-width: 460px;
  margin: 40px auto;
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
}

.not-found-card h1 {
  margin: 0;
  font-size: 32px;
}

.not-found-card p {
  margin: 0 0 8px;
  color: var(--md-sys-color-on-surface-variant);
}
</style>
