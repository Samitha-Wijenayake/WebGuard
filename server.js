/**
 * Local WebGuard server.
 * Serves the app and fetches public http(s) targets so the browser can read headers and HTML.
 * Binds to loopback only and refuses private, link-local, and metadata addresses.
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');
const { URL } = require('url');

const PORT = Number(process.env.PORT) || 4173;
const HOST = '127.0.0.1';
const ROOT = __dirname;
const MAX_REDIRECTS = 5;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function send(res, status, body, type = 'application/json; charset=utf-8') {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  res.writeHead(status, {
    'Content-Type': type,
    'Content-Length': payload.length,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(payload);
}

function isPrivateIp(ip) {
  if (net.isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }
  if (net.isIP(ip) === 6) {
    const value = ip.toLowerCase();
    return value === '::1'
      || value.startsWith('fe80:')
      || value.startsWith('fc')
      || value.startsWith('fd')
      || value.startsWith('::ffff:127.')
      || value.startsWith('::ffff:10.')
      || value.startsWith('::ffff:0.')
      || value.startsWith('::ffff:192.168.')
      || value.startsWith('::ffff:169.254.');
  }
  return true;
}

async function assertPublicTarget(target) {
  if (!['http:', 'https:'].includes(target.protocol)) {
    throw new Error('Only HTTP and HTTPS targets are supported.');
  }
  if (target.username || target.password) {
    throw new Error('URLs with embedded credentials are not allowed.');
  }
  const host = target.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (
    host === 'localhost'
    || host.endsWith('.localhost')
    || host.endsWith('.local')
    || host === 'metadata.google.internal'
    || host === 'metadata.internal'
  ) {
    throw new Error('Local and metadata targets are not allowed.');
  }
  const literal = net.isIP(host);
  const addresses = literal ? [host] : (await dns.lookup(host, { all: true })).map(item => item.address);
  if (!addresses.length) throw new Error('The target hostname did not resolve.');
  if (addresses.some(isPrivateIp)) {
    throw new Error('Private, loopback, and link-local targets are not allowed.');
  }
}

function normalizeHeaders(raw) {
  const headers = {};
  for (const [key, value] of Object.entries(raw || {})) {
    headers[key.toLowerCase()] = Array.isArray(value) ? value.join('\n') : String(value);
  }
  return headers;
}

function requestOnce(target, method, timeout, maxBytes) {
  return new Promise((resolve, reject) => {
    const lib = target.protocol === 'https:' ? https : http;
    const req = lib.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      path: `${target.pathname || '/'}${target.search || ''}`,
      method,
      headers: {
        'User-Agent': 'WebGuard/1.0 (local passive assessment)',
        'Accept': 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
      },
      timeout,
    }, (upstream) => {
      const chunks = [];
      let size = 0;
      let truncated = false;
      upstream.on('data', (chunk) => {
        if (method === 'HEAD') return;
        size += chunk.length;
        if (size <= maxBytes) chunks.push(chunk);
        else truncated = true;
      });
      upstream.on('end', () => {
        resolve({
          status: upstream.statusCode || 0,
          headers: normalizeHeaders(upstream.headers),
          body: Buffer.concat(chunks).toString('utf8'),
          truncated,
        });
      });
    });
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('The target timed out.'));
    });
    req.on('error', (error) => reject(new Error(error.message || 'Network error')));
    req.end();
    if (req.socket) req.socket.unref?.();
  });
}

async function fetchTarget(rawUrl, method, timeout, maxBytes) {
  let current = new URL(rawUrl);
  const redirectChain = [current.href];
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    await assertPublicTarget(current);
    const result = await requestOnce(current, method, timeout, maxBytes);
    const location = result.headers.location;
    const redirect = result.status >= 300 && result.status < 400 && location;
    if (!redirect || method === 'HEAD') {
      return { ...result, finalUrl: current.href, redirectChain, ok: result.status >= 200 && result.status < 400 };
    }
    current = new URL(location, current);
    redirectChain.push(current.href);
  }
  throw new Error('The target redirected too many times.');
}

function serveStatic(req, res) {
  const url = new URL(req.url, `http://${HOST}`);
  let pathname = decodeURIComponent(url.pathname);
  if (pathname.endsWith('/')) pathname += 'index.html';
  const filePath = path.normalize(path.join(ROOT, pathname));
  if (filePath !== ROOT && !filePath.startsWith(`${ROOT}${path.sep}`)) {
    send(res, 403, { error: 'Forbidden' });
    return;
  }
  fs.readFile(filePath, (error, data) => {
    if (error) {
      send(res, 404, { error: 'Not found' });
      return;
    }
    const type = MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
    if (req.method === 'HEAD') {
      res.writeHead(200, {
        'Content-Type': type,
        'Content-Length': data.length,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      });
      res.end();
      return;
    }
    send(res, 200, data, type);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${HOST}:${PORT}`);
    if (url.pathname === '/api/fetch') {
      const target = url.searchParams.get('url') || '';
      const method = (url.searchParams.get('method') || 'GET').toUpperCase();
      const timeout = Math.max(3000, Math.min(Number(url.searchParams.get('timeout')) || 15000, 120000));
      const maxBytes = Math.max(0, Math.min(Number(url.searchParams.get('maxBytes')) || 400000, 800000));
      if (!['GET', 'HEAD'].includes(method)) {
        send(res, 400, { error: 'Only GET and HEAD are supported.' });
        return;
      }
      let parsed;
      try { parsed = new URL(target); } catch { send(res, 400, { error: 'Enter a valid URL including http:// or https://.' }); return; }
      const result = await fetchTarget(parsed.href, method, timeout, maxBytes);
      send(res, 200, result);
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      send(res, 405, { error: 'Method not allowed' });
      return;
    }
    serveStatic(req, res);
  } catch (error) {
    send(res, 400, { error: error.message || 'Request failed' });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`WebGuard running at http://${HOST}:${PORT}`);
});
