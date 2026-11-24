/**
 * WebGuard – Site crawler  (js/crawler.js)
 *
 * Discovers in-scope pages from links (recursively, breadth-first) and from
 * robots.txt / sitemap.xml, fetches them through the local proxy with bounded
 * concurrency, and hands every accessible HTML page to `onPage` for scanning.
 *
 * Guards against duplicates and crawl traps:
 *  - canonical URL keys (no fragment, default ports, trailing slash, index files,
 *    tracking parameters, sorted query string, www/apex treated as one site)
 *  - redirect targets are de-duplicated against already scanned pages
 *  - depth, path-length, repeated-segment and per-path query-variant limits
 *  - a hard cap on total fetch attempts and on consecutive failures
 */
import { proxyFetch } from './net.js';

const SKIP_EXTENSIONS = /\.(png|jpe?g|gif|svg|webp|avif|bmp|ico|tiff?|pdf|zip|gz|tgz|rar|7z|tar|dmg|exe|msi|apk|mp4|m4v|webm|mov|avi|mkv|mp3|wav|ogg|flac|css|js|mjs|map|json|xml|rss|atom|txt|csv|xlsx?|docx?|pptx?|odt|woff2?|ttf|otf|eot)$/i;
const SKIP_PATHS = /\/(log-?out|sign-?out|logoff)(\/|$)|\/wp-json\/|\/cdn-cgi\//i;
const TRACKING_PARAMS = /^(utm_[a-z]+|gclid|fbclid|msclkid|mc_cid|mc_eid|_ga|_gl|ref|ref_src|igshid|yclid)$/i;
const INDEX_FILE = /\/(index|default)\.(html?|php|aspx?|jsp)$/i;

const MAX_DEPTH = 8;
const MAX_PATH_SEGMENTS = 12;
const MAX_QUERY_VARIANTS_PER_PATH = 12;
const MAX_SITEMAP_FILES = 12;
const MAX_SITEMAP_URLS = 5000;
const MAX_CONSECUTIVE_FAILURES = 12;
const PAGE_MAX_BYTES = 800000;

const siteHost = host => host.toLowerCase().replace(/^www\./, '');

/** Canonical identity used for de-duplication. Returns null for unusable URLs. */
export function canonicalKey(rawUrl) {
  let url;
  try { url = new URL(rawUrl); } catch { return null; }
  if (!['http:', 'https:'].includes(url.protocol)) return null;
  url.hash = '';
  const params = [...url.searchParams.entries()]
    .filter(([key]) => !TRACKING_PARAMS.test(key))
    .sort(([a, av], [b, bv]) => (a === b ? av.localeCompare(bv) : a.localeCompare(b)));
  let path = url.pathname.replace(/\/{2,}/g, '/').replace(INDEX_FILE, '/');
  if (path.length > 1) path = path.replace(/\/+$/, '');
  const query = params.length ? `?${new URLSearchParams(params).toString()}` : '';
  return `${siteHost(url.hostname)}${url.port ? `:${url.port}` : ''}${path}${query}`;
}

/** Clean URL that is actually requested (fragment and tracking parameters removed). */
function cleanUrl(rawUrl) {
  const url = new URL(rawUrl);
  url.hash = '';
  [...url.searchParams.keys()].forEach(key => { if (TRACKING_PARAMS.test(key)) url.searchParams.delete(key); });
  return url.href;
}

function isHtmlResponse(data) {
  const type = String(data.headers?.['content-type'] || '').toLowerCase();
  if (type) return type.includes('text/html') || type.includes('application/xhtml');
  return /^\s*(<!doctype html|<html)/i.test(data.body || '');
}

/** Extracts candidate page links from an HTML document. */
export function extractLinks(html, pageUrl) {
  if (!html || typeof DOMParser === 'undefined') return [];
  const doc = new DOMParser().parseFromString(html, 'text/html');
  let base = pageUrl;
  const baseHref = doc.querySelector('base[href]')?.getAttribute('href');
  if (baseHref) { try { base = new URL(baseHref, pageUrl).href; } catch { /* keep page url */ } }
  const raw = [];
  doc.querySelectorAll('a[href], area[href]').forEach(el => raw.push(el.getAttribute('href')));
  doc.querySelectorAll('link[href]').forEach(el => {
    const rel = (el.getAttribute('rel') || '').toLowerCase();
    if (/\b(next|prev|alternate|canonical)\b/.test(rel) && !el.getAttribute('type')) raw.push(el.getAttribute('href'));
  });
  doc.querySelectorAll('iframe[src], frame[src]').forEach(el => raw.push(el.getAttribute('src')));
  const refresh = doc.querySelector('meta[http-equiv="refresh" i]')?.getAttribute('content') || '';
  const refreshMatch = refresh.match(/url\s*=\s*['"]?([^'";]+)/i);
  if (refreshMatch) raw.push(refreshMatch[1]);

  const links = new Set();
  raw.forEach(href => {
    const value = String(href || '').trim();
    if (!value || /^(javascript|mailto|tel|data|blob|ftp|sms):/i.test(value) || value.startsWith('#')) return;
    try { links.add(new URL(value, base).href); } catch { /* ignore malformed */ }
  });
  return [...links];
}

/** Pulls <loc> entries out of a sitemap or sitemap index (tolerates truncated XML). */
function parseSitemap(xml) {
  const locs = [...String(xml || '').matchAll(/<loc>\s*(?:<!\[CDATA\[)?\s*([^<\]\s]+)\s*(?:\]\]>)?\s*<\/loc>/gi)]
    .map(match => match[1].replace(/&amp;/g, '&'));
  return { isIndex: /<sitemapindex[\s>]/i.test(xml), locs };
}

/**
 * Crawls a site.
 * @param {object} options
 * @param {string} options.startUrl     final landing URL (already fetched)
 * @param {object} options.landing      { body, headers, status, finalUrl, redirectChain } for the landing page
 * @param {number} options.limit        maximum number of pages to scan
 * @param {number} options.concurrency  parallel requests (clamped 1–8)
 * @param {number} options.timeout      per-request timeout in ms
 * @param {AbortSignal} options.signal
 * @param {() => boolean} options.isActive  returns false once the scan is cancelled
 * @param {(page) => Promise<void>} options.onPage  called for every accessible HTML page
 * @param {(stats, event) => void} options.onProgress
 */
export async function crawlSite(options) {
  const { startUrl, landing, signal } = options;
  const limit = Math.max(1, Math.min(Number(options.limit) || 100, 500));
  const concurrency = Math.max(1, Math.min(Number(options.concurrency) || 4, 8));
  const timeout = options.timeout || 15000;
  const isActive = options.isActive || (() => true);
  const onPage = options.onPage || (async () => {});
  const onProgress = options.onProgress || (() => {});

  const start = new URL(startUrl);
  const scopeHost = siteHost(start.hostname);
  const scopePort = start.port;

  const discovered = new Map();     // canonical key -> { url, depth, source }
  const queue = [];                  // keys waiting to be fetched (BFS by depth)
  const scannedKeys = new Set();     // keys whose final page has been scanned
  const queryVariants = new Map();   // path key -> number of query variants accepted
  const pages = [];                  // scanned pages
  const failures = [];               // { url, error }
  const skipped = [];                // { url, reason }
  const sitemapInfo = { files: [], urls: 0 };
  let attempts = 0;
  let consecutiveFailures = 0;
  let stopReason = '';

  const stats = () => ({
    discovered: discovered.size,
    scanned: pages.length,
    queued: queue.length,
    failed: failures.length,
    skipped: skipped.length,
    limit,
    sitemapUrls: sitemapInfo.urls,
  });

  function inScope(url) {
    return siteHost(url.hostname) === scopeHost && url.port === scopePort && ['http:', 'https:'].includes(url.protocol);
  }

  function looksLikeTrap(url) {
    const segments = url.pathname.split('/').filter(Boolean);
    if (segments.length > MAX_PATH_SEGMENTS) return 'path too deep';
    const counts = new Map();
    for (const segment of segments) {
      counts.set(segment, (counts.get(segment) || 0) + 1);
      if (counts.get(segment) >= 3) return 'repeating path segments';
    }
    if (url.href.length > 2000) return 'URL too long';
    return '';
  }

  /** Adds a URL to the frontier if it is new, in scope and safe to crawl. */
  function enqueue(rawUrl, depth, source) {
    let url;
    try { url = new URL(cleanUrl(rawUrl)); } catch { return false; }
    if (!inScope(url)) return false;
    // Prefer the landing page's scheme for same-site links (avoid downgrading to http).
    if (url.protocol !== start.protocol && siteHost(url.hostname) === scopeHost) url.protocol = start.protocol;
    const key = canonicalKey(url.href);
    if (!key || discovered.has(key)) return false;
    if (SKIP_EXTENSIONS.test(url.pathname) || SKIP_PATHS.test(url.pathname)) return false;
    if (depth > MAX_DEPTH) return false;
    const trap = looksLikeTrap(url);
    if (trap) { skipped.push({ url: url.href, reason: trap }); return false; }
    if (url.search) {
      const pathKey = canonicalKey(`${url.origin}${url.pathname}`);
      const used = queryVariants.get(pathKey) || 0;
      if (used >= MAX_QUERY_VARIANTS_PER_PATH) return false;
      queryVariants.set(pathKey, used + 1);
    }
    discovered.set(key, { url: url.href, depth, source });
    queue.push(key);
    return true;
  }

  async function fetchText(url, maxBytes) {
    return proxyFetch(url, { method: 'GET', timeout, signal, maxBytes });
  }

  /* ── 1. Seed: landing page ─────────────────────────────── */
  const landingKey = canonicalKey(startUrl);
  discovered.set(landingKey, { url: startUrl, depth: 0, source: 'start' });
  scannedKeys.add(landingKey);
  pages.push({ url: startUrl, status: landing.status, depth: 0, source: 'start' });
  onProgress(stats(), { type: 'page', url: startUrl });
  await onPage({ url: startUrl, finalUrl: startUrl, status: landing.status, headers: landing.headers, body: landing.body, redirectChain: landing.redirectChain, depth: 0, source: 'start' });
  extractLinks(landing.body, startUrl).forEach(link => enqueue(link, 1, 'link'));
  onProgress(stats(), { type: 'links', url: startUrl });

  /* ── 2. Seed: robots.txt sitemaps and sitemap.xml ──────── */
  let robots = null;
  if (isActive()) {
    onProgress(stats(), { type: 'phase', message: 'Reading robots.txt and sitemap.xml.' });
    try { robots = await fetchText(new URL('/robots.txt', start.origin).href, 200000); } catch (error) {
      if (!isActive()) throw new Error('Scan cancelled');
      robots = null;
    }
    const sitemapQueue = [];
    if (robots?.status === 200) {
      [...String(robots.body || '').matchAll(/^\s*sitemap:\s*(\S+)/gim)].forEach(match => {
        try { sitemapQueue.push(new URL(match[1], start.origin).href); } catch { /* ignore */ }
      });
    }
    if (!sitemapQueue.length) sitemapQueue.push(new URL('/sitemap.xml', start.origin).href, new URL('/sitemap_index.xml', start.origin).href);
    const seenSitemaps = new Set();
    while (sitemapQueue.length && seenSitemaps.size < MAX_SITEMAP_FILES && sitemapInfo.urls < MAX_SITEMAP_URLS && isActive()) {
      const sitemapUrl = sitemapQueue.shift();
      if (seenSitemaps.has(sitemapUrl) || /\.gz($|\?)/i.test(sitemapUrl)) continue;
      seenSitemaps.add(sitemapUrl);
      try {
        const data = await fetchText(sitemapUrl, PAGE_MAX_BYTES);
        if (data.status !== 200) continue;
        const { isIndex, locs } = parseSitemap(data.body);
        if (!locs.length) continue;
        sitemapInfo.files.push({ url: sitemapUrl, entries: locs.length, index: isIndex, truncated: Boolean(data.truncated) });
        if (isIndex) {
          locs.forEach(loc => sitemapQueue.push(loc));
        } else {
          locs.forEach(loc => {
            if (sitemapInfo.urls >= MAX_SITEMAP_URLS) return;
            sitemapInfo.urls += 1;
            enqueue(loc, 1, 'sitemap');
          });
        }
        onProgress(stats(), { type: 'sitemap', url: sitemapUrl, entries: locs.length });
      } catch (error) {
        if (!isActive()) throw new Error('Scan cancelled');
      }
    }
  }

  /* ── 3. Breadth-first crawl with a bounded worker pool ─── */
  const maxAttempts = limit * 3;
  let inFlight = 0;

  async function processKey(key) {
    const entry = discovered.get(key);
    attempts += 1;
    onProgress(stats(), { type: 'fetch', url: entry.url });
    let data;
    let lastError;
    for (let attempt = 0; attempt < 2 && !data; attempt += 1) {
      try {
        data = await fetchText(entry.url, PAGE_MAX_BYTES);
        if (data.status === 429 || data.status === 503) {
          const retryAfter = Math.min(Number(data.headers?.['retry-after']) || 3, 10);
          if (attempt === 0) { data = null; await new Promise(resolve => setTimeout(resolve, retryAfter * 1000)); }
        }
      } catch (error) {
        lastError = error;
        if (!isActive() || /cancel/i.test(error.message)) throw new Error('Scan cancelled');
        if (/not allowed|private|loopback|valid url/i.test(error.message)) break; // permanent
      }
    }
    if (!data) {
      consecutiveFailures += 1;
      failures.push({ url: entry.url, error: lastError?.message || 'Request failed' });
      onProgress(stats(), { type: 'error', url: entry.url, error: lastError?.message || 'Request failed' });
      return;
    }

    const finalUrl = data.finalUrl || entry.url;
    let final;
    try { final = new URL(finalUrl); } catch { final = new URL(entry.url); }
    if (!inScope(final)) {
      skipped.push({ url: entry.url, reason: `redirects off-site to ${final.host}` });
      consecutiveFailures = 0;
      return;
    }
    const finalKey = canonicalKey(final.href);
    if (finalKey !== key) {
      if (scannedKeys.has(finalKey)) { skipped.push({ url: entry.url, reason: 'duplicate of an already scanned page' }); consecutiveFailures = 0; return; }
      if (!discovered.has(finalKey)) discovered.set(finalKey, { url: final.href, depth: entry.depth, source: 'redirect' });
    }
    if (data.status >= 400) {
      consecutiveFailures = data.status >= 500 ? consecutiveFailures + 1 : 0;
      failures.push({ url: entry.url, error: `HTTP ${data.status}` });
      onProgress(stats(), { type: 'error', url: entry.url, error: `HTTP ${data.status}` });
      return;
    }
    if (!isHtmlResponse(data)) {
      skipped.push({ url: entry.url, reason: `not an HTML page (${data.headers?.['content-type'] || 'unknown type'})` });
      consecutiveFailures = 0;
      return;
    }
    consecutiveFailures = 0;
    if (pages.length >= limit || scannedKeys.has(finalKey)) return;
    scannedKeys.add(key);
    scannedKeys.add(finalKey);
    pages.push({ url: final.href, status: data.status, depth: entry.depth, source: entry.source, truncated: Boolean(data.truncated) });
    onProgress(stats(), { type: 'page', url: final.href });

    extractLinks(data.body, final.href).forEach(link => enqueue(link, entry.depth + 1, 'link'));
    await onPage({ url: entry.url, finalUrl: final.href, status: data.status, headers: data.headers || {}, body: data.body || '', redirectChain: data.redirectChain?.length ? data.redirectChain : [entry.url], depth: entry.depth, source: entry.source });
  }

  await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      if (error) reject(error); else resolve();
    };
    const pump = () => {
      if (settled) return;
      if (!isActive() || signal?.aborted) { finish(new Error('Scan cancelled')); return; }
      if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES && !stopReason) stopReason = `stopped after ${MAX_CONSECUTIVE_FAILURES} consecutive failed requests`;
      if (attempts >= maxAttempts && !stopReason) stopReason = 'fetch attempt budget reached';
      const canStart = () => !stopReason && queue.length && pages.length + inFlight < limit;
      while (inFlight < concurrency && canStart()) {
        const key = queue.shift();
        inFlight += 1;
        processKey(key)
          .catch(error => { if (/cancel/i.test(error.message)) finish(error); else failures.push({ url: discovered.get(key)?.url, error: error.message }); })
          .finally(() => { inFlight -= 1; pump(); });
      }
      if (inFlight === 0 && !canStart()) finish();
    };
    pump();
  });

  if (!stopReason && pages.length >= limit && queue.length) stopReason = `page limit of ${limit} reached`;
  onProgress(stats(), { type: 'done' });

  return {
    pages,
    failures,
    skipped,
    robots,
    sitemaps: sitemapInfo.files,
    stats: { ...stats(), attempts, stopReason: stopReason || 'all discovered pages were visited' },
    unvisited: queue.slice(0, 200).map(key => discovered.get(key)?.url).filter(Boolean),
  };
}
