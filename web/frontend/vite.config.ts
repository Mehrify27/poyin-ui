import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, URL } from "node:url";
import { defineConfig, type Plugin } from "vite";
import vue from "@vitejs/plugin-vue";

function keepDistPlaceholder(): Plugin {
  return {
    name: "keep-dist-placeholder",
    closeBundle() {
      const distDir = path.dirname(fileURLToPath(new URL("./dist/index.html", import.meta.url)));
      fs.mkdirSync(distDir, { recursive: true });
      fs.writeFileSync(path.join(distDir, ".gitkeep"), "");
    },
  };
}

export default defineConfig({
  base: "./",
  plugins: [vue(), keepDistPlaceholder()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    assetsInlineLimit: 4096,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules")) {
            if (id.includes("@fontsource")) return "fonts";
            if (id.includes("vue-i18n") || id.includes("@intlify")) return "i18n";
            if (id.includes("vue-router") || id.includes("pinia") || id.includes("/vue/")) {
              return "vendor";
            }
          }
          return undefined;
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      "^/(panel|api|login|logout|getTwoFactorEnable|ws|manifest\\.webmanifest|sw\\.js)": {
        target: "http://127.0.0.1:2053",
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
