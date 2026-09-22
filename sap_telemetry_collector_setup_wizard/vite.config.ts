// tslint:disable:no-default-export - Vite requires default export config.
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig, Plugin} from 'vite';
import {execSync} from 'child_process';

function localGcpAuthPlugin(): Plugin {
  return {
    name: 'local-gcp-auth-plugin',
    configureServer(server) {
      server.middlewares.use('/api/token', (req, res) => {
        try {
          // Reject non-loopback requests to prevent remote token harvesting
          const remoteIp = req.socket?.remoteAddress || '';
          const isLoopback =
            remoteIp === '127.0.0.1' ||
            remoteIp === '::1' ||
            remoteIp === '::ffff:127.0.0.1';

          // Validate Host header against DNS rebinding attacks
          const host = (req.headers.host || '').toLowerCase();
          const isLocalHost =
            host.startsWith('localhost:') ||
            host === 'localhost' ||
            host.startsWith('127.0.0.1:') ||
            host === '127.0.0.1';

          // Validate Origin against cross-origin browser extraction
          const origin = (req.headers.origin || '').toLowerCase();
          const isAllowedOrigin =
            !origin ||
            origin.startsWith('http://localhost:') ||
            origin === 'http://localhost' ||
            origin.startsWith('http://127.0.0.1:') ||
            origin === 'http://127.0.0.1';

          if (!isLoopback || !isLocalHost || !isAllowedOrigin) {
            res.statusCode = 403;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: 'Forbidden: /api/token is restricted to local loopback' }));
            return;
          }

          console.log('\n[Vite Dev Server] Received /api/token request on localhost...');
          let token = '';
          try {
            const raw = execSync('gcloud auth application-default print-access-token --quiet 2>/dev/null || gcloud auth print-access-token --quiet', { encoding: 'utf8' }).trim();
            const lines = raw.split('\n').map(l => l.trim()).filter(l => l.length > 0);
            const tokenLine = lines.find(l => l.startsWith('ya29.')) || lines[lines.length - 1] || '';
            token = tokenLine;
            console.log('[Vite Dev Server OK] Generated valid GCP Access Token via local gcloud CLI.');
          } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            console.error('[Vite Dev Server ERROR] Failed to run gcloud CLI:', msg);
          }

          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ access_token: token }));
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          res.statusCode = 500;
          res.end(JSON.stringify({ error: msg }));
        }
      });

      server.middlewares.use('/api/log', (req, res) => {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            console.log(`[Cloud Run Stream Log] ${parsed.log || body}`);
          } catch {
            console.log(`[Cloud Run Stream Log] ${body}`);
          }
          res.statusCode = 200;
          res.end('OK\n');
        });
      });
    }
  };
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), localGcpAuthPlugin()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
