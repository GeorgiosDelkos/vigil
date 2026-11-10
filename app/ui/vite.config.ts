import { defineConfig } from "vitest/config";
import solid from "vite-plugin-solid";

// Tauri serves the built files; the dev server port is the one tauri.conf.json's devUrl names.
export default defineConfig({
  plugins: [solid()],
  server: { port: 5173, strictPort: true },
  build: { target: "safari16" },
  // Component tests render into jsdom, with the Tauri modules mocked in each test file. Vitest
  // turns CSS into an empty module unless included, which `?raw` does not escape; scale.test.ts
  // reads the stylesheets as text.
  test: { environment: "jsdom", css: { include: /\.css\?raw$/ } },
});
