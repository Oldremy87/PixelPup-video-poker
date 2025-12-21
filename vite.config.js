// vite.config.js
import { defineConfig } from 'vite';
import path from 'node:path';
import { nodePolyfills } from 'vite-plugin-node-polyfills'

export default defineConfig({
  publicDir: false,                 // do not copy /public/ into /public/assets
  plugins: [
    nodePolyfills({
      protocolImports: true,
      // leave defaults; plugin injects crypto, stream, util, events, buffer, process, etc.
    }),
  ],
  build: {
    outDir: 'public/assets',
    emptyOutDir: false,
    target: 'es2022',
    sourcemap: true,                // keep on while we verify
    minify: false,                  // TEMP: avoid TDZ-obscuring minification
    lib: {
      entry: {
        'connect.bundle':   path.resolve(__dirname, 'src/connect.ts'),
        'walletBet.bundle': path.resolve(__dirname, 'src/walletBet.ts'),
      },
      formats: ['es'],
    },
    rollupOptions: {
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
      commonjsOptions: {
        transformMixedEsModules: true,
        requireReturnsDefault: 'auto',
        strictRequires: false,
      },
    },
  },
  resolve: {
    alias: {
      // Force the SDK to its browser ESM build
      'nexa-wallet-sdk': path.resolve(
        __dirname,
        'node_modules/nexa-wallet-sdk/dist/index.web.mjs'
      ),
      crypto: 'crypto-browserify',  
      buffer: 'buffer',
      events: 'events/',
      util: 'util/',
      stream: 'stream-browserify', // plugin covers stream; this keeps resolution explicit
    },
    dedupe: ['nexa-wallet-sdk', 'libnexa-ts', '@vgrunner/electrum-cash'],
    mainFields: ['browser', 'module', 'jsnext:main', 'main'],
    conditions: ['browser', 'import', 'module', 'default'],
  },
  define: {
    global: 'globalThis',
    'process.env': {}, // harmless probe target
  },
  optimizeDeps: {
    // Let the plugin handle polyfills during prebundle too
    esbuildOptions: {
      define: { global: 'globalThis' },
    },
  },
});
