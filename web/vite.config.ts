import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

// Build the SPA straight into the Go embed directory.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  build: {
    outDir: "../internal/web/dist",
    emptyOutDir: true,
    // Emit hashed assets under /static so they never collide with SPA client
    // routes like /assets.
    assetsDir: "static",
  },
  server: {
    proxy: {
      "/api": "http://localhost:8080",
      "/healthz": "http://localhost:8080",
      "/metrics": "http://localhost:8080",
    },
  },
});
