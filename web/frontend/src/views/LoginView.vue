<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { useRouter } from "vue-router";
import { ApiError, panelApi } from "@/api/client";
import AppLogo from "@/components/AppLogo.vue";
import M3Icon from "@/components/M3Icon.vue";
import { useAppStore } from "@/stores/app";

const { t } = useI18n();
const router = useRouter();
const appStore = useAppStore();

const username = ref("");
const password = ref("");
const twoFactorCode = ref("");
const showPassword = ref(false);
const requiresTwoFactor = ref(false);
const submitting = ref(false);
const errorMessage = ref("");

const locales = computed(
  () =>
    appStore.bootstrap?.supportedLocales ?? [
      { code: "en-US", name: "English", icon: "🇺🇸", rtl: false },
      { code: "fa-IR", name: "فارسی", icon: "🇮🇷", rtl: true },
    ],
);

const themeIcon = computed(() => {
  if (appStore.theme === "light") return "light_mode";
  if (appStore.theme === "ultra-dark") return "contrast";
  return "dark_mode";
});

async function checkTwoFactor(): Promise<void> {
  const userTrimmed = username.value.trim();
  if (!userTrimmed) return;
  try {
    requiresTwoFactor.value = await panelApi.checkTwoFactor(userTrimmed);
  } catch {
    requiresTwoFactor.value = false;
  }
}

async function submitLogin(): Promise<void> {
  errorMessage.value = "";
  const userTrimmed = username.value.trim();
  if (!userTrimmed) {
    errorMessage.value = t("pages.login.toasts.emptyUsername");
    return;
  }
  if (!password.value) {
    errorMessage.value = t("pages.login.toasts.emptyPassword");
    return;
  }

  submitting.value = true;
  try {
    await panelApi.login({
      username: userTrimmed,
      password: password.value,
      twoFactorCode: twoFactorCode.value.trim() || undefined,
    });
    const nextBootstrap = await appStore.initBootstrap();
    const target =
      nextBootstrap?.landingPath === "/cores" &&
      (nextBootstrap.perms?.coreSettings || nextBootstrap.user?.isSuperAdmin)
        ? "/cores"
        : "/";
    await router.replace(target);
  } catch (err) {
    if (err instanceof ApiError) {
      errorMessage.value = err.message;
    } else {
      errorMessage.value = t("somethingWentWrong");
    }
    await checkTwoFactor();
  } finally {
    submitting.value = false;
  }
}

async function onLocaleChange(event: Event): Promise<void> {
  const select = event.target as HTMLSelectElement;
  await appStore.changeLocale(select.value);
}
</script>

<template>
  <main class="login-stage">
    <section class="m3-card login-card">
      <header class="login-head">
        <AppLogo />
        <div class="login-head-controls">
          <button
            type="button"
            class="login-icon-btn"
            :title="t('menu.theme')"
            @click="appStore.cycleTheme()"
          >
            <M3Icon :name="themeIcon" :size="18" />
          </button>
          <select
            class="login-lang-select"
            :aria-label="t('spa.language')"
            :value="appStore.locale"
            @change="onLocaleChange"
          >
            <option v-for="loc in locales" :key="loc.code" :value="loc.code">
              {{ loc.name }}
            </option>
          </select>
        </div>
      </header>

      <div class="login-intro">
        <h1>{{ t("pages.login.title") }}</h1>
        <p>{{ t("spa.appTitle") }}</p>
      </div>

      <div v-if="errorMessage" class="login-error" role="alert">
        <M3Icon name="error" :size="18" />
        <span>{{ errorMessage }}</span>
      </div>

      <form class="login-form" @submit.prevent="submitLogin">
        <label class="login-field">
          <span>{{ t("username") }}</span>
          <input
            v-model="username"
            class="m3-input"
            type="text"
            autocomplete="username"
            required
            @blur="checkTwoFactor"
          />
        </label>

        <label class="login-field">
          <span>{{ t("password") }}</span>
          <div class="password-wrap">
            <input
              v-model="password"
              class="m3-input"
              :type="showPassword ? 'text' : 'password'"
              autocomplete="current-password"
              required
            />
            <button
              type="button"
              class="password-toggle"
              :aria-label="showPassword ? t('pages.login.hidePassword') : t('pages.login.showPassword')"
              @click="showPassword = !showPassword"
            >
              <M3Icon :name="showPassword ? 'visibility_off' : 'visibility'" :size="18" />
            </button>
          </div>
        </label>

        <label v-if="requiresTwoFactor" class="login-field">
          <span>{{ t("twoFactorCode") }}</span>
          <input
            v-model="twoFactorCode"
            class="m3-input"
            type="text"
            inputmode="numeric"
            autocomplete="one-time-code"
            :placeholder="t('pages.login.toasts.twoFactorRequired')"
          />
        </label>

        <button type="submit" class="m3-btn m3-btn--primary login-submit" :disabled="submitting">
          <M3Icon :name="submitting ? 'hourglass_top' : 'login'" :size="18" />
          <span>{{ submitting ? t("loading") : t("login") }}</span>
        </button>
      </form>

      <footer class="login-foot">
        <a :href="`${appStore.runtime.basePath}panel/`">{{ t("spa.openLegacy") }}</a>
        <span class="login-ver">v{{ appStore.bootstrap?.version || "2.0.2" }}</span>
      </footer>
    </section>
  </main>
</template>

<style scoped>
.login-stage {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px 16px;
}

.login-card {
  width: 100%;
  max-width: 428px;
  padding: 28px;
  display: flex;
  flex-direction: column;
  gap: 20px;
  box-shadow: var(--md-elevation-2);
}

.login-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.login-head-controls {
  display: flex;
  align-items: center;
  gap: 8px;
}

.login-icon-btn {
  width: 34px;
  height: 34px;
  border-radius: 50%;
  border: 1px solid var(--md-sys-color-outline-variant);
  background: var(--md-sys-color-surface-container-low);
  color: var(--md-sys-color-on-surface);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
}

.login-lang-select {
  height: 34px;
  border-radius: 999px;
  border: 1px solid var(--md-sys-color-outline-variant);
  background: var(--md-sys-color-surface-container-low);
  color: var(--md-sys-color-on-surface);
  padding: 0 10px;
  font-size: 13px;
}

.login-intro h1 {
  margin: 0 0 4px;
  font-size: 22px;
}

.login-intro p {
  margin: 0;
  color: var(--md-sys-color-on-surface-variant);
}

.login-error {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  border-radius: var(--md-shape-sm);
  background: var(--md-sys-color-error-container);
  color: var(--md-sys-color-error);
  font-size: 13px;
}

.login-form {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.login-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 13px;
  font-weight: 500;
}

.password-wrap {
  position: relative;
  display: flex;
  align-items: center;
}

.password-wrap .m3-input {
  padding-inline-end: 42px;
}

.password-toggle {
  position: absolute;
  inset-inline-end: 6px;
  width: 32px;
  height: 32px;
  border: none;
  background: transparent;
  color: var(--md-sys-color-on-surface-variant);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
}

.login-submit {
  width: 100%;
  margin-top: 6px;
  padding: 11px 18px;
}

.login-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 12px;
  color: var(--md-sys-color-on-surface-variant);
  padding-top: 8px;
  border-top: 1px solid var(--md-sys-color-outline-variant);
}

.login-ver {
  font-family: var(--font-mono);
}
</style>
