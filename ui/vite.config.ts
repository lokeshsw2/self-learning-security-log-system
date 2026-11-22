import path from 'path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Built into ../logparser/web/dist and served by `python -m logparser.web`.
// In development (`npm run dev`) API calls are proxied to that server.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(import.meta.dirname, './src') } },
  build: { outDir: '../logparser/web/dist', emptyOutDir: true },
  server: { proxy: { '/api': 'http://127.0.0.1:8090' } },
})
