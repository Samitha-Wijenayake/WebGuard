import { initRouter, navigateTo } from './router.js';
import { getState, setState } from './state.js';
import { initStorage, loadSettings, saveSettings, exportData, clearAllData } from './storage.js';

const pageModules = {
  overview: () => import('./pages/overview.js'),
  'new-scan': () => import('./pages/new-scan.js'),
  'scan-history': () => import('./pages/scan-history.js'),
  findings: () => import('./pages/findings.js'),
  'attack-surface': () => import('./pages/attack-surface.js'),
  'vuln-intel': () => import('./pages/vuln-intel.js'),
  privacy: () => import('./pages/privacy.js'),
  quality: () => import('./pages/quality.js'),
  compliance: () => import('./pages/compliance.js'),
  reports: () => import('./pages/reports.js'),
};

const fallbackPages = new Set(['settings', 'about']);
const main = document.querySelector('#main-content');
let renderSequence = 0;

function renderIcons() {
  if (typeof lucide !== 'undefined') lucide.createIcons();
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

function renderFallbackPage(page) {
  const labels = {
    privacy: ['Privacy Assessment', 'Tracker and third-party resource analysis is available after a scan.'],
    quality: ['Website Quality', 'SEO, accessibility, and performance signals will appear for an inspected page.'],
    compliance: ['Compliance Assessment', 'OWASP and best-practice mappings are derived from completed security findings.'],
    reports: ['Reports', 'Generate or export reports from a completed scan.'],
    settings: ['Settings', 'Control local scan preferences and data retention.'],
    about: ['About WebGuard', 'Browser-based website security assessment with explicit testability limits.'],
  };
  const [title, description] = labels[page] || ['WebGuard', 'Page unavailable'];
  const state = getState();
  const settings = state.settings;

  if (page === 'settings') {
    main.innerHTML = `<div class="page-header"><div><h1 class="page-title"><i data-lucide="settings"></i>${title}</h1><p class="page-subtitle">${description}</p></div></div>
      <form class="card" id="settings-form" style="max-width:720px">
        <div class="form-row"><div class="form-group"><label class="label" for="setting-limit">Default crawl limit</label><input class="input" id="setting-limit" type="number" min="50" max="500" value="${settings.crawlLimit}"></div>
        <div class="form-group"><label class="label" for="setting-timeout">Request timeout (ms)</label><input class="input" id="setting-timeout" type="number" min="3000" max="120000" value="${settings.timeout}"></div></div>
        <div class="form-row"><div class="form-group"><label class="label" for="setting-concurrency">Scan concurrency</label><input class="input" id="setting-concurrency" type="number" min="1" max="10" value="${settings.concurrency}"></div>
        <div class="form-group"><label class="label" for="setting-retention">Retention (days)</label><input class="input" id="setting-retention" type="number" min="1" max="3650" value="${settings.retentionDays}"></div></div>
        <p class="text-muted mb-3">API keys are optional and remain in this browser. Browser storage is not a secure secrets vault.</p>
        <div class="form-group mb-3"><label class="label" for="setting-nvd">NVD API key</label><input class="input" id="setting-nvd" type="password" autocomplete="off" value="${escapeHtml(settings.nvdApiKey || '')}" placeholder="Optional"></div>
        <div class="form-group mb-3"><label class="label" for="setting-psi">PageSpeed Insights key</label><input class="input" id="setting-psi" type="password" autocomplete="off" value="${escapeHtml(settings.pagesInsightsKey || '')}" placeholder="Optional"></div>
        <div class="form-actions"><button class="btn btn-primary" type="submit"><i data-lucide="save"></i> Save Settings</button><button class="btn btn-secondary" type="button" id="export-data"><i data-lucide="download"></i> Export Local Data</button><button class="btn btn-danger" type="button" id="clear-data"><i data-lucide="trash-2"></i> Clear Data</button></div>
        <p id="settings-status" class="text-muted mt-3" role="status"></p>
      </form>`;
    renderIcons();
    main.querySelector('#settings-form').addEventListener('submit', event => {
      event.preventDefault();
      const next = { ...settings, crawlLimit: Number(main.querySelector('#setting-limit').value), timeout: Number(main.querySelector('#setting-timeout').value), concurrency: Number(main.querySelector('#setting-concurrency').value), retentionDays: Number(main.querySelector('#setting-retention').value), nvdApiKey: main.querySelector('#setting-nvd').value.trim(), pagesInsightsKey: main.querySelector('#setting-psi').value.trim() };
      saveSettings(next); setState({ settings: next }); main.querySelector('#settings-status').textContent = 'Settings saved locally.';
    });
    main.querySelector('#export-data').addEventListener('click', async () => {
      const blob = new Blob([JSON.stringify(await exportData(), null, 2)], { type: 'application/json' });
      const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = 'webguard-local-data.json'; link.click(); URL.revokeObjectURL(link.href);
    });
    main.querySelector('#clear-data').addEventListener('click', async () => { if (confirm('Clear all locally stored WebGuard data?')) { await clearAllData(); setState({ currentScan: null, scanResults: null, viewScanId: null, scans: [] }); main.querySelector('#settings-status').textContent = 'Local data cleared.'; } });
    return;
  }

  main.innerHTML = `<div class="page-header"><div><h1 class="page-title"><i data-lucide="circle-help"></i>${escapeHtml(title)}</h1><p class="page-subtitle">${escapeHtml(description)}</p></div></div><div class="card empty-state"><i data-lucide="scan-search"></i><h3>No completed scan selected</h3><p>Run a real passive scan to populate this assessment. Tests blocked by browser CORS are marked Not Testable.</p><a class="btn btn-primary" href="#" data-nav="new-scan"><i data-lucide="play"></i> Start a scan</a></div>`;
  renderIcons();
  main.querySelector('[data-nav]')?.addEventListener('click', event => { event.preventDefault(); navigateTo('new-scan'); });
}

async function renderPage(page) {
  if (!main) return;
  const sequence = ++renderSequence;
  main.innerHTML = '<div class="loading-overlay"><div class="spinner spinner--lg"></div><p class="mt-4 text-muted">Loading view...</p></div>';
  setState({ currentPage: page });
  try {
    if (pageModules[page]) {
      const module = await pageModules[page]();
      if (sequence !== renderSequence) return;
      await module.render(main);
    } else if (fallbackPages.has(page)) {
      renderFallbackPage(page);
    } else {
      renderFallbackPage('about');
    }
  } catch (error) {
    if (sequence !== renderSequence) return;
    main.innerHTML = `<div class="card alert-danger"><h2>Unable to load this view</h2><p>${escapeHtml(error.message)}</p></div>`;
  }
}

async function boot() {
  await initStorage();
  const settings = loadSettings();
  setState({ settings });
  document.documentElement.dataset.theme = settings.theme || 'dark';
  initRouter();
  document.addEventListener('pagechange', event => {
    void renderPage(event.detail.page);
  });
  const sidebar = document.querySelector('#sidebar');
  const overlay = document.querySelector('#sidebar-overlay');
  const setSidebar = (open) => {
    sidebar?.classList.toggle('open', open);
    overlay?.classList.toggle('visible', open);
  };
  document.querySelector('#sidebar-toggle')?.addEventListener('click', () => setSidebar(!sidebar?.classList.contains('open')));
  document.querySelector('#sidebar-collapse')?.addEventListener('click', () => {
    const collapsed = sidebar?.classList.toggle('is-collapsed');
    document.body.classList.toggle('sidebar-collapsed', Boolean(collapsed));
    const button = document.querySelector('#sidebar-collapse');
    button?.setAttribute('aria-label', collapsed ? 'Expand navigation' : 'Collapse navigation');
    button?.setAttribute('title', collapsed ? 'Expand navigation' : 'Collapse navigation');
    if (button) button.innerHTML = `<i data-lucide="${collapsed ? 'panel-left-open' : 'panel-left-close'}"></i>`;
    renderIcons();
  });
  overlay?.addEventListener('click', () => setSidebar(false));
  document.querySelectorAll('.nav-item[data-page]').forEach(item => item.addEventListener('click', () => setSidebar(false)));
  document.querySelector('#initial-loader')?.remove();
  navigateTo('overview');
}

try {
  await boot();
} catch (error) {
  if (main) main.innerHTML = `<div class="card alert-danger"><h2>WebGuard failed to start</h2><p>${escapeHtml(error.message)}</p></div>`;
}