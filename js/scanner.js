import { getState, setState } from './state.js';
import { saveScan } from './storage.js';
import { proxyFetch } from './net.js';

let cancelled = false;
let activeController = null;
let scanGeneration = 0;

const checkLoaders = [
  ['https', () => import('./checks/https.js')],
  ['tls', () => import('./checks/tls.js')],
  ['headers', () => import('./checks/headers.js')],
  ['csp', () => import('./checks/csp.js')],
  ['exposed-files', () => import('./checks/exposed-files.js')],
];

const unavailableChecks = [
  ['email-dns', 'Email DNS Analysis', 'Mailbox DNS records are not looked up by this scan.'],
  ['subdomains', 'Subdomain Discovery', 'Certificate Transparency and brute-force subdomain discovery are not run.'],
  ['dns-security', 'DNS Security Analysis', 'DNSSEC and resolver data are not queried by this scan.'],
  ['certificate-transparency', 'Certificate Transparency', 'Certificate Transparency logs are not queried by this scan.'],
  ['port-scan', 'Network Port Exposure', 'Network port discovery is outside the scope of this browser-safe passive scan.'],
  ['server-vulnerabilities', 'Server Vulnerability Verification', 'Server-side package and patch verification requires authenticated infrastructure access.'],
  ['dependency-vulnerabilities', 'Dependency Vulnerability Resolution', 'Dependency manifests are not available from a public landing page.'],
  ['authentication', 'Authentication and Authorization', 'Authenticated workflows are not exercised by this read-only scan.'],
  ['rate-limiting', 'Rate Limiting Controls', 'Rate-limit behavior cannot be safely verified without sending repeated requests.'],
];

function safeTarget(rawUrl) {
  let url;
  try { url = new URL(rawUrl); } catch { throw new Error('Enter a valid URL including http:// or https://.'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP and HTTPS targets are supported.');
  const host = url.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host === 'metadata.google.internal') throw new Error('Local and cloud metadata targets are not allowed.');
  if (/^(127\.|10\.|192\.168\.|169\.254\.)/.test(host) || /^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) throw new Error('Private and link-local network targets are not allowed.');
  return url.href;
}

function resolveTimeout(options) {
  const raw = Number(options.timeout ?? getState().settings.timeout ?? 30);
  const ms = raw > 0 && raw < 1000 ? raw * 1000 : raw;
  return Math.max(3000, Math.min(ms || 30000, 120000));
}

async function fetchTarget(url, timeout, signal, maxBytes = 500000) {
  const data = await proxyFetch(url, { method: 'GET', timeout, signal, maxBytes });
  return {
    response: { status: data.status, url: data.finalUrl, ok: data.ok },
    headers: data.headers || {},
    text: data.body || '',
    finalUrl: data.finalUrl || url,
    redirectChain: data.redirectChain?.length ? data.redirectChain : [url],
  };
}

function sameOriginLinks(html, baseUrl) {
  if (!html || typeof DOMParser === 'undefined') return [];
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const origin = new URL(baseUrl).origin;
  const links = [];
  doc.querySelectorAll('a[href]').forEach((anchor) => {
    try {
      const next = new URL(anchor.getAttribute('href'), baseUrl);
      if (next.origin !== origin || next.protocol === 'javascript:') return;
      next.hash = '';
      if (/\.(png|jpe?g|gif|svg|webp|pdf|zip|mp4|mp3|css|js|ico)$/i.test(next.pathname)) return;
      links.push(next.href);
    } catch { /* ignore invalid links */ }
  });
  return [...new Set(links)];
}

async function crawlPages(startUrl, html, limit, timeout, signal, onProgress) {
  const origin = new URL(startUrl).origin;
  const seen = new Set([startUrl]);
  const queue = sameOriginLinks(html, startUrl).filter(link => new URL(link).origin === origin);
  const pages = [{ url: startUrl, status: 200 }];
  const cap = Math.max(1, Math.min(Number(limit) || 1, 500));
  while (queue.length && pages.length < cap) {
    if (cancelled || signal?.aborted) throw new Error('Scan cancelled');
    const next = queue.shift();
    if (!next || seen.has(next)) continue;
    seen.add(next);
    try {
      const data = await proxyFetch(next, { method: 'GET', timeout, signal, maxBytes: 120000 });
      const finalUrl = data.finalUrl || next;
      if (new URL(finalUrl).origin === origin) {
        pages.push({ url: finalUrl, status: data.status });
        sameOriginLinks(data.body || '', finalUrl).forEach((link) => {
          if (!seen.has(link)) queue.push(link);
        });
      }
    } catch (error) {
      if (String(error.message).includes('cancel')) throw error;
      pages.push({ url: next, status: 0 });
    }
    onProgress(pages.length, seen.size + queue.length);
  }
  return pages;
}

function scoreResults(results) {
  const weights = { critical: 24, high: 14, medium: 7, low: 3 };
  const allFindings = [];
  const seenFindings = new Set();
  results.forEach(result => (result.findings || []).forEach(finding => {
    const key = `${result.id}|${finding.title}|${finding.evidence}`;
    if (seenFindings.has(key)) return;
    seenFindings.add(key);
    allFindings.push({ ...finding, category: result.category, checkId: result.id });
  }));
  const testable = results.filter(result => result.testable !== false).length;
  const coverage = results.length ? Math.round((testable / results.length) * 100) : 0;
  const penalty = allFindings.reduce((sum, finding) => finding.status === 'passed' || finding.status === 'not-testable' || finding.status === 'info' ? sum : sum + (weights[finding.severity] || 0), 0);
  const score = Math.max(0, Math.min(100, 100 - penalty));
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    passed: 0,
    failed: 0,
    warning: 0,
    notTestable: 0,
    total: allFindings.length,
    coverage,
  };
  allFindings.forEach(finding => {
    const severity = finding.severity || 'info';
    if (summary[severity] !== undefined) {
      summary[severity]++;
    }
    const status = (finding.status || '').toLowerCase();
    if (status === 'passed') summary.passed++;
    if (status === 'failed') summary.failed++;
    if (status === 'warning') summary.warning++;
    if (status === 'not-testable') summary.notTestable++;
  });
  return { score, summary, findings: allFindings };
}

export async function startScan(rawUrl, options = {}, onProgress = () => {}) {
  const generation = ++scanGeneration;
  cancelled = false;
  activeController?.abort();
  activeController = new AbortController();
  const signal = activeController.signal;
  const stillActive = () => generation === scanGeneration && !cancelled;
  const url = safeTarget(rawUrl);
  const timeout = resolveTimeout(options);
  const scan = { id: `scan-${Date.now()}`, url, mode: options.mode || 'passive', startTime: new Date().toISOString(), createdAt: new Date().toISOString(), status: 'running' };
  setState({ activeScan: scan });
  const report = (percent, message, extra = {}) => onProgress({ percent, message, ...extra });
  report(5, 'Validating target and requesting the landing page.', { step: 'init' });
  let fetchedData;
  try { fetchedData = await fetchTarget(url, timeout, signal); } catch (error) {
    if (String(error.message).toLowerCase().includes('cancel')) throw new Error('Scan cancelled');
    throw new Error(error.message || 'Target could not be fetched.');
  }
  if (!stillActive()) throw new Error('Scan cancelled');
  if (new URL(fetchedData.finalUrl).origin !== new URL(url).origin) throw new Error('The target redirected to another origin. Scanning stopped to preserve scope.');
  report(18, 'Landing page loaded. Following same-origin links.', { step: 'crawl', stats: { pagesFound: 1, pagesChecked: 1 } });
  const pages = await crawlPages(fetchedData.finalUrl, fetchedData.text, options.crawlLimit, timeout, signal, (checked, found) => {
    report(18 + Math.min(12, checked), `Checked ${checked} page(s).`, { step: 'crawl', stats: { pagesFound: found, pagesChecked: checked } });
  });
  report(32, 'Running security checks.', { step: 'checks', stats: { pagesFound: pages.length, pagesChecked: pages.length } });

  const results = [];
  if (!stillActive()) throw new Error('Scan cancelled');
  const loadedChecks = [];
  for (const [index, [id, loader]] of checkLoaders.entries()) {
    if (!stillActive()) throw new Error('Scan cancelled');
    const labels = { https: 'HTTPS / Protocol Security', tls: 'TLS Certificate', headers: 'Security Headers', csp: 'Content Security Policy (CSP)', 'exposed-files': 'Exposed Sensitive Files' };
    const checkPercent = 40 + Math.round((index / checkLoaders.length) * 35);
    report(checkPercent, `Running ${labels[id] || id}.`, { step: 'checks', check: { name: labels[id] || id, status: 'running' } });
    const module = await loader();
    try {
      loadedChecks.push(await module.check(url, fetchedData));
    } catch (error) {
      loadedChecks.push({ id, name: id, category: 'Assessment', status: 'error', testable: true, score: 0, findings: [{ title: `${id} check failed`, severity: 'info', status: 'error', evidence: error.message, impact: 'The check could not complete.', remediation: 'Retry the scan.', confidence: 'confirmed' }] });
    }
  }
  const pageIntel = await import('./checks/page-intel.js');
  const intel = await pageIntel.analyze(url, fetchedData, { timeout, signal });
  loadedChecks.push(...intel.checks);
  results.push(...loadedChecks);
  loadedChecks.forEach(result => {
    let status = 'passed';
    if (result.status === 'failed' || result.status === 'error') status = 'failed';
    else if (result.status === 'warning' || result.status === 'info') status = result.status === 'info' ? 'passed' : 'warning';
    report(40 + Math.round((loadedChecks.indexOf(result) / loadedChecks.length) * 40), `${result.name || result.id} complete.`, { step: 'checks', check: { name: result.name || result.id, status } });
  });
  unavailableChecks.forEach(([id, name, limitation]) => {
    results.push({
      id, name, category: 'Assessment Coverage', status: 'not-testable', severity: 'info', score: 0, testable: false,
      findings: [{ title: `${name} not testable in this scan`, severity: 'info', status: 'not-testable', evidence: limitation, impact: 'No security conclusion is drawn from this unavailable test.', remediation: 'Use an authorised server-side assessment or enable a dedicated safe browser check when supported.', confidence: 'confirmed' }],
      summary: limitation, limitation,
    });
  });
  report(90, 'Calculating score and saving results.', { step: 'analysis' });
  const scored = scoreResults(results);
  const finalScan = {
    ...scan,
    status: 'complete',
    createdAt: scan.createdAt,
    completedAt: new Date().toISOString(),
    duration: Date.now() - new Date(scan.startTime).getTime(),
    score: scored.score,
    summary: scored.summary,
    findings: scored.findings,
    checks: results,
    attackSurface: { ...intel.attackSurface, endpoints: [...new Set([...(intel.attackSurface.endpoints || []), ...pages.map(page => page.url)])].slice(0, 50), pages },
    quality: intel.quality,
    privacy: intel.privacy,
    vulnIntel: intel.vulnIntel,
    fetched: { finalUrl: fetchedData.finalUrl, status: fetchedData.response.status },
  };
  await saveScan(finalScan);
  setState({ activeScan: null, currentScan: finalScan, scanResults: finalScan, viewScanId: finalScan.id });
  report(100, 'Scan complete.', { step: 'complete', complete: true, result: finalScan, stats: { pagesFound: pages.length, pagesChecked: pages.length, passed: scored.summary.passed, failed: scored.summary.failed } });
  return finalScan;
}

export async function cancelScan() {
  cancelled = true;
  scanGeneration += 1;
  activeController?.abort();
}