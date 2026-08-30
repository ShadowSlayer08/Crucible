import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies the API to the FastAPI backend (server.py on :8000), so
// the React app calls same-origin paths (/modes, /scan/stream, …) in dev and
// in a production build served by any static host or by FastAPI itself.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/health": "http://localhost:8000",
      "/modes": "http://localhost:8000",
      "/schemas": "http://localhost:8000",
      "/tests": "http://localhost:8000",
      "/scan": "http://localhost:8000",
    },
  },
  build: { outDir: "dist" },
});
