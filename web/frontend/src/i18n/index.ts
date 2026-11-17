import type { WritableComputedRef } from "vue";
import { createI18n, type DefineLocaleMessage } from "vue-i18n";
import enUS from "@/locales/en-US.json";
import { getRuntimeConfig } from "@/lib/bootstrap";

type LocaleMessagesMap = DefineLocaleMessage;

export const RTL_LOCALES = new Set(["ar-EG", "fa-IR"]);

export const SUPPORTED_LOCALE_CODES = [
  "ar-EG",
  "en-US",
  "fa-IR",
  "zh-CN",
  "zh-TW",
  "ja-JP",
  "ru-RU",
  "vi-VN",
  "es-ES",
  "id-ID",
  "uk-UA",
  "tr-TR",
  "pt-BR",
] as const;

export type LocaleCode = (typeof SUPPORTED_LOCALE_CODES)[number];

const SHORT_LANG_MAP: Record<string, LocaleCode> = {
  ar: "ar-EG",
  en: "en-US",
  fa: "fa-IR",
  ja: "ja-JP",
  ru: "ru-RU",
  vi: "vi-VN",
  es: "es-ES",
  id: "id-ID",
  uk: "uk-UA",
  tr: "tr-TR",
  pt: "pt-BR",
  "zh-cn": "zh-CN",
  "zh-tw": "zh-TW",
};

export function normalizeLocaleCode(raw?: string | null): LocaleCode {
  if (!raw) return "en-US";
  const trimmed = raw.trim();
  if ((SUPPORTED_LOCALE_CODES as readonly string[]).includes(trimmed)) {
    return trimmed as LocaleCode;
  }
  const lower = trimmed.toLowerCase();
  if (SHORT_LANG_MAP[lower]) return SHORT_LANG_MAP[lower];
  const prefix = lower.split(/[-_]/)[0];
  if (prefix && SHORT_LANG_MAP[prefix]) return SHORT_LANG_MAP[prefix];
  return "en-US";
}

function readCookie(name: string): string {
  if (typeof document === "undefined") return "";
  const pairs = document.cookie ? document.cookie.split("; ") : [];
  for (const pair of pairs) {
    const idx = pair.indexOf("=");
    if (idx === -1) continue;
    if (decodeURIComponent(pair.slice(0, idx)) === name) {
      return decodeURIComponent(pair.slice(idx + 1));
    }
  }
  return "";
}

function writeLangCookie(locale: LocaleCode): void {
  if (typeof document === "undefined") return;
  const basePath = getRuntimeConfig().basePath || "/";
  document.cookie = `lang=${encodeURIComponent(locale)}; path=${basePath}; SameSite=Lax; max-age=31536000`;
}

export function detectInitialLocale(fallback: string = "en-US"): LocaleCode {
  const fromCookie = readCookie("lang");
  if (fromCookie) return normalizeLocaleCode(fromCookie);
  if (typeof navigator !== "undefined" && navigator.language) {
    return normalizeLocaleCode(navigator.language);
  }
  return normalizeLocaleCode(fallback);
}

export const i18n = createI18n({
  legacy: false,
  locale: "en-US",
  fallbackLocale: "en-US",
  missingWarn: false,
  fallbackWarn: false,
  messages: {
    "en-US": enUS as unknown as LocaleMessagesMap,
  },
});

async function importLocaleChunk(locale: LocaleCode): Promise<LocaleMessagesMap> {
  switch (locale) {
    case "ar-EG":
      return (await import("@/locales/ar-EG.json")).default as unknown as LocaleMessagesMap;
    case "en-US":
      return enUS as unknown as LocaleMessagesMap;
    case "fa-IR":
      return (await import("@/locales/fa-IR.json")).default as unknown as LocaleMessagesMap;
    case "zh-CN":
      return (await import("@/locales/zh-CN.json")).default as unknown as LocaleMessagesMap;
    case "zh-TW":
      return (await import("@/locales/zh-TW.json")).default as unknown as LocaleMessagesMap;
    case "ja-JP":
      return (await import("@/locales/ja-JP.json")).default as unknown as LocaleMessagesMap;
    case "ru-RU":
      return (await import("@/locales/ru-RU.json")).default as unknown as LocaleMessagesMap;
    case "vi-VN":
      return (await import("@/locales/vi-VN.json")).default as unknown as LocaleMessagesMap;
    case "es-ES":
      return (await import("@/locales/es-ES.json")).default as unknown as LocaleMessagesMap;
    case "id-ID":
      return (await import("@/locales/id-ID.json")).default as unknown as LocaleMessagesMap;
    case "uk-UA":
      return (await import("@/locales/uk-UA.json")).default as unknown as LocaleMessagesMap;
    case "tr-TR":
      return (await import("@/locales/tr-TR.json")).default as unknown as LocaleMessagesMap;
    case "pt-BR":
      return (await import("@/locales/pt-BR.json")).default as unknown as LocaleMessagesMap;
  }
}

export function applyDocumentDirection(locale: LocaleCode): void {
  if (typeof document === "undefined") return;
  const isRtl = RTL_LOCALES.has(locale);
  document.documentElement.setAttribute("dir", isRtl ? "rtl" : "ltr");
  document.documentElement.setAttribute("lang", locale);
}

export async function setActiveLocale(rawLocale: string, persistCookie = true): Promise<LocaleCode> {
  const locale = normalizeLocaleCode(rawLocale);
  const existing = i18n.global.availableLocales as string[];
  if (!existing.includes(locale)) {
    const messages = await importLocaleChunk(locale);
    i18n.global.setLocaleMessage(locale, messages);
  }
  const localeRef = i18n.global.locale as unknown as WritableComputedRef<string>;
  localeRef.value = locale;
  applyDocumentDirection(locale);
  if (persistCookie) {
    writeLangCookie(locale);
  }
  return locale;
}
