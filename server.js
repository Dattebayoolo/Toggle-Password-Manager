import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 4242;
const PUBLIC_DIR = __dirname;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2'
};

// In-memory file cache for the dev server — avoids re-reading static assets on every request.
// Reset by restarting the server (dev workflow).
const fileCache = new Map();

async function readFileCached(filePath) {
  if (fileCache.has(filePath)) return fileCache.get(filePath);
  const data = await fs.promises.readFile(filePath);
  fileCache.set(filePath, data);
  return data;
}

const server = http.createServer(async (req, res) => {
  // ── Security Headers ────────────────────────────────────────────────────────
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');

  // Content-Security-Policy — strict allowlist for a password manager
  // Allows: same-origin scripts/styles, external fonts (Google Fonts), HIBP API, DuckDuckGo favicons
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https://icons.duckduckgo.com https://api.qrserver.com",
    "connect-src 'self' https://api.pwnedpasswords.com",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'"
  ].join('; '));

  // CRITICAL: Disable caching so development and theme updates apply immediately on refresh!
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  // CORS — local-only origin (127.0.0.1 only serves local requests)
  res.setHeader('Access-Control-Allow-Origin', 'http://127.0.0.1:' + PORT);

  let safeUrl;
  try {
    safeUrl = new URL(req.url, `http://${req.headers.host}`).pathname;
  } catch (e) {
    res.writeHead(400);
    return res.end('Bad Request');
  }

  // Route: / → landing.html (marketing page), /app → main vault app
  let filePath;
  if (safeUrl === '/') {
    filePath = path.join(PUBLIC_DIR, 'landing.html');
  } else if (safeUrl === '/app' || safeUrl === '/app/') {
    filePath = path.join(PUBLIC_DIR, 'index.html');
  } else {
    filePath = path.join(PUBLIC_DIR, safeUrl);
  }

  // Security: prevent path traversal out of PUBLIC_DIR
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  // Direct Favicon handler to avoid browser 404s/errors
  if (safeUrl === '/favicon.ico') {
    const faviconPath = path.join(PUBLIC_DIR, 'favicon.ico');
    try {
      const data = await readFileCached(faviconPath);
      res.writeHead(200, { 'Content-Type': 'image/x-icon' });
      return res.end(data);
    } catch {
      const svgIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%2310b981"><path d="M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/></svg>`;
      res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
      return res.end(svgIcon);
    }
  }

  try {
    const stats = await fs.promises.stat(filePath);

    if (stats.isDirectory()) {
      filePath = path.join(filePath, 'index.html');
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    try {
      const data = await readFileCached(filePath);
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(data);
    } catch (readErr) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end(`Server Error: ${readErr.code}`);
    }
  } catch (statErr) {
    // If the request has an extension (e.g. .css, .js, .png, .ico), return 404 rather than HTML
    const reqExt = path.extname(safeUrl);
    if (reqExt && reqExt !== '.html') {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end(`404 Not Found: ${safeUrl}`);
    }

    // Otherwise fallback to index.html for SPA routing
    try {
      const indexPath = path.join(PUBLIC_DIR, 'index.html');
      const content = await readFileCached(indexPath);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(content);
    } catch {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
    }
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n🛡️  Toggle Password Manager is running locally!`);
  console.log(`🔒 URL: http://127.0.0.1:${PORT}`);
  console.log(`✨ Zero-knowledge, fully encrypted local storage ready.\n`);
});
