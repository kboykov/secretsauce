// Dev-only static server: serves the repo and exposes /preview.html — the real
// src/app.html with a mocked `chrome` API injected so it runs in a normal tab.
//
//   node dev/preview-server.mjs            → http://127.0.0.1:4173/preview.html
//   ?scenario=full|scanning|stored|empty   ?theme=dark|light   ?host=example.com
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml' };

export function previewHtml() {
  const html = fs.readFileSync(path.join(ROOT, 'src', 'app.html'), 'utf8');
  return html
    .replace('<link rel="stylesheet" href="app.css"/>', '<link rel="stylesheet" href="/src/app.css"/>')
    .replace('<link rel="icon" href="icons/icon48.png"/>', '<link rel="icon" href="/src/icons/icon48.png"/>')
    .replace('<script src="shared.js"></script>', '<script src="/dev/mock-chrome.js"></script>\n<script src="/src/shared.js"></script>')
    .replace(/<script src="app\//g, '<script src="/src/app/');
}

export function createServer() {
  return http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/' || url.pathname === '/preview.html') {
      res.writeHead(200, { 'Content-Type': MIME['.html'] });
      res.end(previewHtml());
      return;
    }
    const file = path.join(ROOT, path.normalize(decodeURIComponent(url.pathname)));
    if (!file.startsWith(ROOT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404); res.end('not found'); return;
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT) || 4173;
  createServer().listen(port, '127.0.0.1', () => console.log(`preview → http://127.0.0.1:${port}/preview.html`));
}
