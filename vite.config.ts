import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Nmap Analyzer runs 100% client-side. No backend, no external API calls.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, open: true },
  build: { outDir: 'dist', sourcemap: false },
});
