import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],

  server: {
    host: '0.0.0.0',
    port: 5173,
    // Proxy /api → FastAPI backend during local development
    // In Docker production, nginx handles this proxy instead.
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'http://localhost:8000',
        changeOrigin: true,
        secure: false,
      },
      '/ws': {
        target: process.env.VITE_API_URL || 'http://localhost:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },

  build: {
    outDir: 'dist',
    sourcemap: false,    // disable in production for smaller bundle
    rollupOptions: {
      output: {
        // Split vendor chunks for better caching
        manualChunks: {
          vendor:  ['react', 'react-dom'],
          charts:  ['chart.js', 'react-chartjs-2'],
        },
      },
    },
  },
})
