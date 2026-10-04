//
// SPDX-License-Identifier: GPL-3.0-or-later
//
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue2";

const imageFile = /\.(png|jpe?g|gif|svg|webp)$/i;

export default defineConfig({
  // The NS8 core serves the module UI below its own path
  base: "./",
  plugins: [vue()],
  resolve: {
    alias: [
      {
        find: "@",
        replacement: fileURLToPath(new URL("./src", import.meta.url)),
      },
      // ns8-ui-lib imports Node "crypto" for uuid; Vite would replace it
      // with an empty stub and break every task call (see src/shims/crypto.js)
      {
        find: /^crypto$/,
        replacement: fileURLToPath(
          new URL("./src/shims/crypto.js", import.meta.url)
        ),
      },
    ],
    // Components are imported without the .vue extension
    extensions: [".mjs", ".js", ".json", ".vue"],
  },
  css: {
    preprocessorOptions: {
      scss: {
        silenceDeprecations: [
          "import",
          "global-builtin",
          "color-functions",
          "if-function",
          "slash-div",
        ],
      },
    },
  },
  build: {
    outDir: "dist",
    // NS8 looks for the module logo as img/*logo*png, so never inline images
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 2000,
    rollupOptions: {
      output: {
        entryFileNames: "js/[name].[hash].js",
        chunkFileNames: "js/[name].[hash].js",
        assetFileNames: (asset) => {
          const name = asset.names?.[0] ?? "";
          if (imageFile.test(name)) {
            return "img/[name].[hash][extname]";
          }
          if (name.endsWith(".css")) {
            return "css/[name].[hash][extname]";
          }
          return "assets/[name].[hash][extname]";
        },
      },
    },
  },
});
