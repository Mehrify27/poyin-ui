import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml } from "smol-toml";
import { baseCompile } from "@intlify/message-compiler";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(frontendDir, "../..");
const translationDir = path.join(repoRoot, "web", "translation");
const localesDir = path.join(frontendDir, "src", "locales");

const EXPECTED_LOCALES = [
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
];

const CRITICAL_KEYS = [
  "menu.dashboard",
  "menu.inbounds",
  "menu.clients",
  "menu.core",
  "menu.settings",
  "pages.login.title",
  "pages.inbounds.title",
  "pages.settings.title",
  "pwa.installApp",
  "pwa.offlineTitle",
  "pwa.offlineDesc",
  "pwa.retry",
  "spa.appTitle",
  "spa.capabilities",
  "spa.inbounds.flow",
  "spa.inbounds.perInboundTraffic",
  "spa.inbounds.awg2Title",
  "spa.inbounds.hysteria2Title",
  "spa.core.sidecarUpdaterTitle",
  "spa.core.networkTuningTitle",
  "spa.core.bbrActive",
];

const EN_REQUIRED_KEYS = ["pages.core.title"];

function flatten(obj, prefix = "", out = new Map()) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      flatten(v, key, out);
    } else {
      out.set(key, String(v));
    }
  }
  return out;
}

function validateBraces(str) {
  let depth = 0;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (ch === "{") {
      if (depth > 0) return "nested/unclosed '{'";
      depth = 1;
    } else if (ch === "}") {
      if (depth === 0) return "unmatched '}'";
      depth = 0;
    }
  }
  if (depth !== 0) return "unclosed '{'";
  return null;
}

function main() {
  const errors = [];

  for (const locale of EXPECTED_LOCALES) {
    const jsonPath = path.join(localesDir, `${locale}.json`);
    const tomlPath = path.join(translationDir, `translate.${locale.replace("-", "_")}.toml`);

    if (!fs.existsSync(tomlPath)) {
      errors.push(`Missing source TOML for ${locale}: ${tomlPath}`);
      continue;
    }
    if (!fs.existsSync(jsonPath)) {
      errors.push(`Missing exported JSON for ${locale}: ${jsonPath}`);
      continue;
    }

    const tomlMap = flatten(parseToml(fs.readFileSync(tomlPath, "utf8")));
    const jsonMap = flatten(JSON.parse(fs.readFileSync(jsonPath, "utf8")));

    for (const k of tomlMap.keys()) {
      if (!jsonMap.has(k)) {
        errors.push(`${locale}: lost key during export: ${k}`);
      }
    }
    for (const k of jsonMap.keys()) {
      if (!tomlMap.has(k)) {
        errors.push(`${locale}: unexpected extra JSON key not in TOML: ${k}`);
      }
    }

    for (const reqKey of CRITICAL_KEYS) {
      const v = jsonMap.get(reqKey);
      if (!v || !v.trim()) {
        errors.push(`${locale}: missing or empty critical key "${reqKey}"`);
      }
    }
    if (locale === "en-US") {
      for (const reqKey of EN_REQUIRED_KEYS) {
        const v = jsonMap.get(reqKey);
        if (!v || !v.trim()) {
          errors.push(`${locale}: missing or empty reference key "${reqKey}"`);
        }
      }
    }

    for (const [k, v] of jsonMap.entries()) {
      if (v.includes("{{") || v.includes("}}")) {
        errors.push(`${locale} (${k}): unconverted Go template delimiter in ${JSON.stringify(v)}`);
      }
      const braceErr = validateBraces(v);
      if (braceErr) {
        errors.push(`${locale} (${k}): ${braceErr} in ${JSON.stringify(v)}`);
      }
      let compileErr = null;
      baseCompile(v, {
        onError(err) {
          compileErr = err;
        },
      });
      if (compileErr) {
        errors.push(`${locale} (${k}): vue-i18n compile error: ${compileErr.message}`);
      }
    }
  }

  // Verify placeholder set parity against en-US on keys translated in both
  const enMap = flatten(JSON.parse(fs.readFileSync(path.join(localesDir, "en-US.json"), "utf8")));
  const extractPlaceholders = (s) =>
    [...s.replace(/\{'@'\}/g, "@").matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]).sort();

  for (const locale of EXPECTED_LOCALES) {
    if (locale === "en-US") continue;
    const locMap = flatten(JSON.parse(fs.readFileSync(path.join(localesDir, `${locale}.json`), "utf8")));
    for (const [k, enVal] of enMap.entries()) {
      if (!locMap.has(k)) continue;
      const locVal = locMap.get(k);
      const enPh = extractPlaceholders(enVal).join(",");
      const locPh = extractPlaceholders(locVal).join(",");
      if (enPh !== locPh) {
        errors.push(`${locale} (${k}): placeholder mismatch vs en-US (en=[${enPh}] vs loc=[${locPh}])`);
      }
    }
  }

  if (errors.length > 0) {
    console.error(`i18n verification failed with ${errors.length} error(s):`);
    for (const err of errors.slice(0, 50)) {
      console.error("  -", err);
    }
    process.exit(1);
  }

  console.log(
    `Verified all ${EXPECTED_LOCALES.length} locales cleanly (${enMap.size} en-US keys, zero placeholder/compile errors).`,
  );
}

main();
