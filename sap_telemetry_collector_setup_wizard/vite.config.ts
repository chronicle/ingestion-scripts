// tslint:disable:no-default-export - Vite requires default export config.
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig, Plugin} from 'vite';
import {execSync} from 'child_process';
import {IncomingMessage, ServerResponse} from 'http';

function getLocalGcpToken(): string {
  try {
    const raw = execSync('gcloud auth application-default print-access-token --quiet 2>/dev/null || gcloud auth print-access-token --quiet', { encoding: 'utf8' }).trim();
    const lines = raw.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    return lines.find(l => l.startsWith('ya29.')) || lines[lines.length - 1] || '';
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error('[Vite Dev Server ERROR] Failed to run gcloud CLI:', msg);
    return '';
  }
}

async function proxyGcpRequest(
    req: IncomingMessage,
    res: ServerResponse,
    targetBaseUrl: string): Promise<void> {
  try {
    const token = getLocalGcpToken();
    if (!token) {
      res.statusCode = 502;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Failed to acquire GCP access token from local gcloud CLI.' }));
      return;
    }

    const subPath = req.url || '';
    const targetUrl = new URL(subPath, targetBaseUrl).toString();

    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    }
    const body = ['POST', 'PUT', 'PATCH'].includes(req.method || '') ? Buffer.concat(chunks) : undefined;

    const headers: Record<string, string> = {
      'Authorization': `Bearer ${token}`
    };
    if (req.headers['content-type']) {
      headers['Content-Type'] = req.headers['content-type'] as string;
    }

    const gcpRes = await fetch(targetUrl, {
      method: req.method,
      headers,
      body
    });

    res.statusCode = gcpRes.status;
    for (const [key, val] of gcpRes.headers.entries()) {
      if (key.toLowerCase() !== 'content-encoding') {
        res.setHeader(key, val);
      }
    }
    const resBuffer = Buffer.from(await gcpRes.arrayBuffer());
    res.end(resBuffer);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    res.statusCode = 502;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: msg }));
  }
}

function localGcpAuthPlugin(): Plugin {
  return {
    name: 'local-gcp-auth-plugin',
    configureServer(server) {
      server.middlewares.use('/api/gcp/storage', (req, res) => {
        void proxyGcpRequest(req, res, 'https://storage.googleapis.com');
      });

      server.middlewares.use('/api/gcp/compute', (req, res) => {
        void proxyGcpRequest(req, res, 'https://compute.googleapis.com');
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
