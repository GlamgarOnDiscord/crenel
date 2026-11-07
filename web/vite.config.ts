import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Static SPA. Relative base so the built app can be served from any path
// (and screenshotted from a file/preview server).
export default defineConfig({
  base: "./",
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false },
});
