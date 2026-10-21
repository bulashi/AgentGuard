import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react(), {
    name: 'native-health',
    configureServer(server) {
      server.middlewares.use('/healthz', (_request, response) => {
        response.setHeader('Content-Type', 'application/json')
        response.end(JSON.stringify({ status: 'ok', service: 'web-ui', runtime: 'native-development' }))
      })
    },
  }],
  server: {
    fs: { allow: [fileURLToPath(new URL('.', import.meta.url))] },
    proxy: {
      '/api': 'http://127.0.0.1:8090',
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    maxWorkers: 2,
    testTimeout: 20000,
  },
})
