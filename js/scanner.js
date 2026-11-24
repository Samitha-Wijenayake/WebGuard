import { getState, setState } from './state.js';
import { saveScan } from './storage.js';
import { proxyFetch } from './net.js';
import { crawlSite, canonicalKey } from './crawler.js';

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

const CHECK_LABELS = {
  https: 'HTTPS / Protocol Security',
  tls: 'TLS Certificate',
  headers: 'Security Headers',
  csp: 'Content Security Policy (CSP)',
  'exposed-files': 'Exposed Sensitive Files',
};

// Checks that describe the whole origin run once; everything else runs on every scanned page.
const SITE_LEVEL_CHECKS = new Set(['tls', 'exposed-files']);
const STATUS_RANK = { failed: 4, error: 4, warning: 3, info: 1, passed: 0, 'not-testable': 0 };
const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function checkError(id, error) {
  return { id, name: CHECK_LABELS[id] || id, category: 'Assessment', status: 'error', testable: true, score: 0, findings: [{ title: `${CHECK_LABELS[id] || id} check failed`, severity: 'info', status: 'error', evidence: error.message, impact: 'The check could not complete.', remediation: 'Retry the scan.', confidence: 'confirmed' }] };
}

/**
 * Merges the results of one check across every page it ran on.
 * Identical findings are reported once with the list of affected pages.
 */
function mergeCheckResults(entries, totalPages) {
  const base = entries[0].result;
  if (entries.length === 1 && totalPages <= 1) {
    return { ...base, findings: (base.findings || []).map(finding => ({ ...finding, url: finding.url || entries[0].pageUrl })), pagesChecked: 1 };
  }
  const groups = new Map();
  entries.forEach(({ pageUrl, result }) => {
    (result.findings || []).forEach(finding => {
      const key = `${finding.title}|${finding.severity}|${finding.status}`;
      if (!groups.has(key)) groups.set(key, { finding, urls: [] });
      const group = groups.get(key);
      if (!group.urls.includes(pageUrl)) group.urls.push(pageUrl);
    });
  });
  const findings = [...groups.values()].map(({ finding, urls }) => ({
    ...finding,
    url: finding.url || urls[0],
    affectedUrls: urls.slice(0, 100),
    pageCount: urls.length,
    evidence: `Observed on ${urls.length} of ${totalPages} scanned page${totalPages === 1 ? '' : 's'}.\n${finding.evidence || ''}`.trim(),
  }));
  const worst = entries.map(entry => entry.result).reduce((a, b) => ((STATUS_RANK[b.status] || 0) > (STATUS_RANK[a.status] || 0) ? b : a), base);
  const severity = entries.map(entry => entry.result.severity || 'info').reduce((a, b) => ((SEVERITY_RANK[b] || 0) > (SEVERITY_RANK[a] || 0) ? b : a), 'info');
  return {
    ...base,
    status: worst.status,
    severity,
    score: Math.min(...entries.map(entry => Number(entry.result.score ?? 0))),
    testable: entries.some(entry => entry.result.testable !== false),
    summary: worst.summary || base.summary,
    findings,
    pagesChecked: entries.length,
  };
}

function uiStatus(result) {
  if (result.status === 'failed' || result.status === 'error') return 'failed';
  if (result.status === 'warning') return 'warning';
  return 'passed';
}

const unique = list => [...new Set(list.filter(Boolean))];

export async function startScan(rawUrl, options = {}, onProgress = () => {}) {
  const generation = ++scanGeneration;
  cancelled = false;
  activeController?.abort();
  activeController = new AbortController();
  const signal = activeController.signal;
  const stillActive = () => generation === scanGeneration && !cancelled;
  const url = safeTarget(rawUrl);
  const timeout = resolveTimeout(options);
  const crawlLimit = Math.max(1, Math.min(Number(options.crawlLimit) || Number(getState().settings?.crawlLimit) || 100, 500));
  const concurrency = Math.max(1, Math.min(Number(options.concurrency) || Number(getState().settings?.concurrency) || 4, 8));
  const scan = { id: `scan-${Date.now()}`, url, mode: options.mode || 'passive', startTime: new Date().toISOString(), createdAt: new Date().toISOString(), status: 'running' };
  setState({ activeScan: scan });

  let lastPercent = 0;
  const report = (percent, message, extra = {}) => {
    lastPercent = Math.max(lastPercent, Math.min(99, Math.round(percent)));
    onProgress({ percent: extra.complete ? 100 : lastPercent, message, ...extra });
  };

  report(3, 'Validating target and requesting the landing page.', { step: 'init' });
  let fetchedData;
  try { fetchedData = await fetchTarget(url, timeout, signal, 800000); } catch (error) {
    if (String(error.message).toLowerCase().includes('cancel')) throw new Error('Scan cancelled');
    throw new Error(error.message || 'Target could not be fetched.');
  }
  if (!stillActive()) throw new Error('Scan cancelled');
  if (canonicalKey(fetchedData.finalUrl)?.split('/')[0] !== canonicalKey(url)?.split('/')[0]) throw new Error('The target redirected to another site. Scanning stopped to preserve scope.');

  const checkModules = {};
  for (const [id, loader] of checkLoaders) checkModules[id] = await loader();
  const pageIntel = await import('./checks/page-intel.js');

  /* ── Site-level checks (once per origin) ─────────────────── */
  report(6, 'Running site-level checks (TLS certificate, exposed files).', { step: 'init' });
  const siteResults = [];
  for (const id of SITE_LEVEL_CHECKS) {
    if (!stillActive()) throw new Error('Scan cancelled');
    report(lastPercent, '', { step: 'init', check: { name: CHECK_LABELS[id], status: 'running' } });
    let result;
    try { result = await checkModules[id].check(url, fetchedData); } catch (error) { result = checkError(id, error); }
    siteResults.push(result);
    report(lastPercent + 2, `${CHECK_LABELS[id]} complete.`, { step: 'init', check: { name: result.name || CHECK_LABELS[id], status: uiStatus(result) } });
  }

  /* ── Crawl + per-page checks ─────────────────────────────── */
  const perPage = new Map();          // check id -> [{ pageUrl, result }]
  const announced = new Set();
  let landingIntel = null;
  const pageIntelOutputs = [];
  let lastStats = { discovered: 1, scanned: 0, queued: 0, failed: 0, skipped: 0, limit: crawlLimit };
  const statsFor = (s) => ({ pagesFound: s.discovered, pagesChecked: s.scanned, queued: s.queued, errors: s.failed, limit: s.limit });

  const record = (result, pageUrl) => {
    const id = result.id;
    if (!perPage.has(id)) perPage.set(id, []);
    perPage.get(id).push({ pageUrl, result });
    if (!announced.has(id)) {
      announced.add(id);
      report(lastPercent, '', { step: 'crawl', check: { name: result.name || CHECK_LABELS[id] || id, status: 'running' } });
    }
  };

  async function scanPage(page) {
    if (!stillActive()) throw new Error('Scan cancelled');
    const pageData = {
      response: { status: page.status, url: page.finalUrl, ok: page.status >= 200 && page.status < 400 },
      headers: page.headers || {},
      text: page.body || '',
      finalUrl: page.finalUrl,
      redirectChain: page.redirectChain || [page.url],
    };
    for (const [id] of checkLoaders) {
      if (SITE_LEVEL_CHECKS.has(id)) continue;
      let result;
      try { result = await checkModules[id].check(page.finalUrl, pageData); } catch (error) { result = checkError(id, error); }
      record(result, page.finalUrl);
    }
    const isLanding = page.source === 'start';
    const intel = await pageIntel.analyze(page.finalUrl, pageData, { timeout, signal, siteLevel: isLanding });
    if (isLanding) landingIntel = intel;
    pageIntelOutputs.push(intel);
    intel.checks.forEach(result => record(result, page.finalUrl));
  }

  report(12, 'Landing page loaded. Discovering pages from links, robots.txt and sitemap.xml.', { step: 'crawl', stats: { pagesFound: 1, pagesChecked: 0 } });
  const crawl = await crawlSite({
    startUrl: fetchedData.finalUrl,
    landing: { body: fetchedData.text, headers: fetchedData.headers, status: fetchedData.response.status, finalUrl: fetchedData.finalUrl, redirectChain: fetchedData.redirectChain },
    limit: crawlLimit,
    concurrency,
    timeout,
    signal,
    isActive: stillActive,
    onPage: scanPage,
    onProgress: (stats, event) => {
      lastStats = stats;
      const target = Math.max(1, Math.min(stats.limit, stats.scanned + stats.queued));
      const percent = 12 + 76 * (stats.scanned / target);
      const extra = { step: 'crawl', stats: statsFor(stats) };
      if (event.type === 'fetch') report(percent, '', { ...extra, currentUrl: event.url });
      else if (event.type === 'page') report(percent, `Scanned page ${stats.scanned}/${stats.limit}: ${event.url}`, extra);
      else if (event.type === 'error') report(percent, `Could not scan ${event.url} (${event.error}).`, extra);
      else if (event.type === 'sitemap') report(percent, `Sitemap ${event.url} listed ${event.entries} URL(s).`, extra);
      else if (event.type === 'phase') report(percent, event.message, extra);
      else report(percent, '', extra);
    },
  });
  if (!stillActive()) throw new Error('Scan cancelled');
  const scannedPages = crawl.pages;
  report(89, `Crawl finished: ${scannedPages.length} page(s) scanned, ${crawl.stats.discovered} discovered (${crawl.stats.stopReason}).`, { step: 'analysis', stats: statsFor(crawl.stats) });

  /* ── Merge results ───────────────────────────────────────── */
  const results = [...siteResults];
  perPage.forEach(entries => results.push(mergeCheckResults(entries, scannedPages.length)));
  results.forEach(result => {
    if (SITE_LEVEL_CHECKS.has(result.id)) return;
    report(90, '', { step: 'analysis', check: { name: result.name || CHECK_LABELS[result.id] || result.id, status: uiStatus(result) } });
  });
  unavailableChecks.forEach(([id, name, limitation]) => {
    results.push({
      id, name, category: 'Assessment Coverage', status: 'not-testable', severity: 'info', score: 0, testable: false,
      findings: [{ title: `${name} not testable in this scan`, severity: 'info', status: 'not-testable', evidence: limitation, impact: 'No security conclusion is drawn from this unavailable test.', remediation: 'Use an authorised server-side assessment or enable a dedicated safe browser check when supported.', confidence: 'confirmed' }],
      summary: limitation, limitation,
    });
  });

  report(92, 'Calculating score and saving results.', { step: 'analysis' });
  const scored = scoreResults(results);
  const intel = landingIntel || { attackSurface: {}, quality: {}, privacy: {}, vulnIntel: { libraries: [], cves: [] } };
  const allIntel = pageIntelOutputs.length ? pageIntelOutputs : [intel];
  const libraries = [];
  const libraryKeys = new Set();
  allIntel.flatMap(item => item.vulnIntel?.libraries || []).forEach(library => {
    const key = `${library.name}|${library.version}`;
    if (!libraryKeys.has(key)) { libraryKeys.add(key); libraries.push(library); }
  });
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
    attackSurface: {
      ...intel.attackSurface,
      externalDomains: unique(allIntel.flatMap(item => item.attackSurface?.externalDomains || [])).slice(0, 100),
      technologies: unique(allIntel.flatMap(item => item.attackSurface?.technologies || [])),
      externalScripts: unique(allIntel.flatMap(item => item.attackSurface?.externalScripts || [])).slice(0, 100),
      endpoints: unique([...scannedPages.map(page => page.url), ...(intel.attackSurface?.endpoints || [])]).slice(0, 200),
      pages: scannedPages,
    },
    quality: intel.quality,
    privacy: {
      ...intel.privacy,
      trackers: unique(allIntel.flatMap(item => item.privacy?.trackers || [])),
      externalDomains: unique(allIntel.flatMap(item => item.privacy?.externalDomains || [])).slice(0, 100),
    },
    vulnIntel: { ...(intel.vulnIntel || {}), libraries },
    crawl: {
      ...crawl.stats,
      sitemaps: crawl.sitemaps,
      failures: crawl.failures.slice(0, 100),
      skipped: crawl.skipped.slice(0, 100),
      unvisited: crawl.unvisited,
      concurrency,
    },
    fetched: { finalUrl: fetchedData.finalUrl, status: fetchedData.response.status },
  };
  await saveScan(finalScan);
  setState({ activeScan: null, currentScan: finalScan, scanResults: finalScan, viewScanId: finalScan.id });
  report(100, 'Scan complete.', { step: 'complete', complete: true, result: finalScan, stats: { ...statsFor(crawl.stats), passed: scored.summary.passed, failed: scored.summary.failed } });
  void lastStats;
  return finalScan;
}

export async function cancelScan() {
  cancelled = true;
  scanGeneration += 1;
  activeController?.abort();
}
