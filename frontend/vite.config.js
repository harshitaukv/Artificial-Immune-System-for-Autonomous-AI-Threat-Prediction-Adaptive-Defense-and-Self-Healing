import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Two apps from one build: the Security Center (index.html) and AstraBot
// (bot.html). FastAPI serves both from ../frontend/dist — AstraBot at /bot.
// In development, Vite proxies API + WebSocket traffic to the backend on :8000.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
      '/ws': { target: 'ws://localhost:8000', ws: true },
      '/demo': { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        bot: resolve(__dirname, 'bot.html'),
      },
    },
  },
})
