import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml } from "smol-toml";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(frontendDir, "../..");
const translationDir = path.join(repoRoot, "web", "translation");
const outDir = path.join(frontendDir, "src", "locales");

const GO_PLACEHOLDER_RE = /\{\{\s*\.([A-Za-z0-9_]+)\s*\}\}/g;

function convertValue(val, stats) {
  if (typeof val === "string") {
    let out = val.replace(GO_PLACEHOLDER_RE, (_, name) => {
      stats.placeholdersConverted += 1;
      return `{${name}}`;
    });
    // Escape literal '@' for vue-i18n's linked-message lexer (@BotFather -> {'@'}BotFather)
    if (out.includes("@")) {
      out = out.replace(/@/g, "{'@'}");
    }
    return out;
  }
  if (Array.isArray(val)) {
    return val.map((item) => convertValue(item, stats));
  }
  if (val && typeof val === "object") {
    const out = {};
    for (const [k, v] of Object.entries(val)) {
      out[k] = convertValue(v, stats);
    }
    return out;
  }
  return val;
}

function countLeafKeys(obj) {
  let count = 0;
  for (const val of Object.values(obj)) {
    if (val && typeof val === "object" && !Array.isArray(val)) {
      count += countLeafKeys(val);
    } else {
      count += 1;
    }
  }
  return count;
}

function main() {
  if (!fs.existsSync(translationDir)) {
    throw new Error(`Translation directory not found: ${translationDir}`);
  }
  fs.mkdirSync(outDir, { recursive: true });

  const files = fs
    .readdirSync(translationDir)
    .filter((f) => /^translate\.[a-z]{2}_[A-Z]{2}\.toml$/.test(f))
    .sort();

  if (files.length === 0) {
    throw new Error(`No translate.*.toml files found in ${translationDir}`);
  }

  let totalConverted = 0;
  const exportedLocales = [];

  for (const file of files) {
    const m = /^translate\.([a-z]{2}_[A-Z]{2})\.toml$/.exec(file);
    const bcp47 = m[1].replace("_", "-");
    const raw = fs.readFileSync(path.join(translationDir, file), "utf8");
    const parsed = parseToml(raw);
    const stats = { placeholdersConverted: 0 };
    const converted = convertValue(parsed, stats);
    const leaves = countLeafKeys(converted);

    const outPath = path.join(outDir, `${bcp47}.json`);
    fs.writeFileSync(outPath, `${JSON.stringify(converted, null, 2)}\n`, "utf8");
    totalConverted += stats.placeholdersConverted;
    exportedLocales.push({ bcp47, leaves, placeholders: stats.placeholdersConverted });
  }

  console.log(
    `Exported ${exportedLocales.length} locales (${totalConverted} Go placeholders converted -> vue-i18n)`,
  );
}

main();
