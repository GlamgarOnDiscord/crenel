import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Static SPA. Relative base so the built app can be served from any path
// (and screenshotted from a file/preview server). Tailwind v4 serves the
// ported component kits (AI Elements, prompt-kit, motion-primitives, bklit);
// its theme is mapped onto Crenel tokens in src/styles/tw.css.
export default defineConfig({
  base: "./",
  plugins: [react(), tailwindcss()],
  build: { outDir: "dist", sourcemap: false },
});
