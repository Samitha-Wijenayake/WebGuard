// new-scan.js - Scan Launcher and Live Progress Page
import { getState, setState } from '../state.js';

let _scanUrl = '';
let _scannerModule = null;
let _elapsedInterval = null;
let _elapsedSeconds = 0;
let _logEntries = [];

export function setScanUrl(url) {
  _scanUrl = url;
}

export async function render(container) {
  container.innerHTML = '';
  _logEntries = [];
  if (_elapsedInterval) { clearInterval(_elapsedInterval); _elapsedInterval = null; }

  const state = getState();
  if (state.pendingScanUrl) {
    _scanUrl = state.pendingScanUrl;
    const autoStart = state.pendingAutoStart;
    const mode = state.pendingScanMode || 'passive';
    setState({ pendingScanUrl: null, pendingAutoStart: false, pendingScanMode: null });
    if (autoStart) {
      const settings = state.settings || {};
      await startScan(container, _scanUrl, {
        mode,
        crawlLimit: settings.crawlLimit || 25,
        timeout: Number(settings.timeout) > 1000 ? Math.round(settings.timeout / 1000) : (settings.timeout || 30),
        concurrency: settings.concurrency || 3,
      });
      return;
    }
  }

  renderIdle(container);
}

function renderIdle(container) {
  const state = getState();
  const prefillUrl = _scanUrl || state.pendingScanUrl || '';

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><i data-lucide="scan-line"></i> New Security Scan</h1>
        <p class="page-subtitle">Configure and launch a website security assessment</p>
      </div>
    </div>

    <div class="card scan-config-card" style="max-width:720px;margin:0 auto;">
      <h2 class="card-title mb-4"><i data-lucide="settings-2"></i> Scan Configuration</h2>

      <div class="form-group mb-3">
        <label class="label" for="ns-url">Target URL</label>
        <div class="input-group">
          <i data-lucide="globe" class="input-icon"></i>
          <input id="ns-url" class="input input-with-icon" type="url"
            placeholder="https://example.com" value="${escHtml(prefillUrl)}" required autocomplete="url"/>
        </div>
      </div>

      <div class="form-group mb-3">
        <label class="label">Scan Mode</label>
        <div class="scan-mode-toggle">
          <label class="toggle-option">
            <input type="radio" name="ns-mode" value="passive" checked />
            <span class="toggle-btn"><i data-lucide="eye"></i> Passive</span>
          </label>
          <label class="toggle-option">
            <input type="radio" name="ns-mode" value="verified" />
            <span class="toggle-btn"><i data-lucide="shield-check"></i> Verified</span>
          </label>
        </div>
        <p class="text-muted mt-1" style="font-size:0.85rem;" id="ns-mode-desc">
          <i data-lucide="info"></i> Passive: Read-only security analysis. Safe for any site. No form submissions or authentication.
        </p>
      </div>

      <div class="form-group mb-3">
        <label class="label" for="ns-crawl">Crawl Limit: <span id="ns-crawl-val">250</span> pages</label>
        <input id="ns-crawl" type="range" min="50" max="500" step="10" value="250" class="range-input" />
        <div class="range-marks">
          <span>50</span><span>250</span><span>500</span>
        </div>
      </div>

      <details class="advanced-options mb-4">
        <summary class="btn btn-ghost btn-sm" style="cursor:pointer;list-style:none;">
          <i data-lucide="sliders-horizontal"></i> Advanced Options
        </summary>
        <div class="advanced-options-body mt-3">
          <div class="form-row">
            <div class="form-group">
              <label class="label" for="ns-timeout">Timeout (seconds)</label>
              <input id="ns-timeout" class="input" type="number" value="30" min="5" max="120" />
            </div>
            <div class="form-group">
              <label class="label" for="ns-concurrency">Concurrency</label>
              <input id="ns-concurrency" class="input" type="number" value="5" min="1" max="20" />
            </div>
          </div>
        </div>
      </details>

      <div class="form-actions">
        <button id="ns-start-btn" class="btn btn-primary btn-lg">
          <i data-lucide="play"></i> Start Scan
        </button>
        <button id="ns-demo-btn" class="btn btn-secondary">
          <i data-lucide="database"></i> Load Demo
        </button>
      </div>

      <div class="mt-3 alert-info" style="font-size:0.85rem;">
        <i data-lucide="shield"></i>
        <strong>Ethical Notice:</strong> Only scan websites you own or have explicit permission to test.
        WebGuard performs non-destructive, passive analysis only.
      </div>
    </div>
  `;

  if (typeof lucide !== 'undefined') lucide.createIcons();

  // Crawl slider
  const crawlSlider = container.querySelector('#ns-crawl');
  const crawlVal = container.querySelector('#ns-crawl-val');
  crawlSlider?.addEventListener('input', () => { if (crawlVal) crawlVal.textContent = crawlSlider.value; });

  // Mode desc
  container.querySelectorAll('input[name="ns-mode"]').forEach(input => {
    input.addEventListener('change', () => {
      const desc = container.querySelector('#ns-mode-desc');
      if (!desc) return;
      if (input.value === 'passive') {
        desc.innerHTML = '<i data-lucide="info"></i> Passive: Read-only security analysis. Safe for any site. No form submissions or authentication.';
      } else {
        desc.innerHTML = '<i data-lucide="alert-triangle"></i> Verified: Performs additional active checks. Only use on sites you own or have permission to test.';
      }
      if (typeof lucide !== 'undefined') lucide.createIcons();
    });
  });

  // Start scan
  container.querySelector('#ns-start-btn')?.addEventListener('click', async () => {
    const url = container.querySelector('#ns-url')?.value.trim();
    if (!url) { alert('Please enter a URL to scan.'); return; }
    const mode = container.querySelector('input[name="ns-mode"]:checked')?.value || 'passive';
    const crawlLimit = parseInt(container.querySelector('#ns-crawl')?.value || '250');
    const timeout = parseInt(container.querySelector('#ns-timeout')?.value || '30');
    const concurrency = parseInt(container.querySelector('#ns-concurrency')?.value || '5');
    await startScan(container, url, { mode, crawlLimit, timeout, concurrency });
  });
  container.querySelector('#ns-url')?.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') container.querySelector('#ns-start-btn')?.click();
  });

  // Demo
  container.querySelector('#ns-demo-btn')?.addEventListener('click', async () => {
    await loadDemoData(container);
  });
}

function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const CHECK_STEPS = [
  { id: 'init', name: 'Initializing' },
  { id: 'crawl', name: 'Crawling' },
  { id: 'checks', name: 'Security Checks' },
  { id: 'analysis', name: 'Analysis' },
  { id: 'complete', name: 'Complete' }
];

const SECURITY_MODULES = [
  'HTTPS / Protocol Security', 'TLS Certificate', 'Security Headers',
  'Content Security Policy (CSP)', 'Exposed Sensitive Files', 'Cookie Security',
  'CORS Headers', 'Forms and Input', 'Mixed Content', 'JavaScript Libraries',
  'Technology Signals', 'security.txt', 'Redirect Behaviour', 'Cache Headers',
  'Subresource Integrity', 'Robots and Sitemap', 'Privacy and Trackers',
  'Email DNS Analysis', 'Subdomain Discovery', 'DNS Security Analysis', 'Certificate Transparency',
  'Network Port Exposure', 'Server Vulnerability Verification', 'Dependency Vulnerability Resolution',
  'Authentication and Authorization', 'Rate Limiting Controls'
];

async function startScan(container, url, options) {
  _scanUrl = url;
  _elapsedSeconds = 0;
  _logEntries = [];

  renderScanning(container, url, options);

  try {
    _scannerModule = await import('../scanner.js');
    await _scannerModule.startScan(url, options, (progress) => {
      updateProgress(container, progress);
      addLog(container, progress.message || progress.status || '');
    });
  } catch (err) {
    // Scanner not available or scan cancelled
    if (err.message && err.message.includes('cancel')) {
      renderIdle(container);
    } else {
      if (_elapsedInterval) { clearInterval(_elapsedInterval); _elapsedInterval = null; }
    addLog(container, `Error: ${err.message}`);
    const card = container.querySelector('.card');
    if (card && !container.querySelector('#ns-error')) {
      const note = document.createElement('p');
      note.id = 'ns-error';
      note.className = 'alert-danger mt-3';
      note.textContent = err.message;
      card.appendChild(note);
    }
    }
  }
}

function renderScanning(container, url, options) {
  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><i data-lucide="scan-line"></i> Scanning in Progress</h1>
        <p class="page-subtitle">Live security assessment — do not close this tab</p>
      </div>
    </div>

    <div class="card mb-3">
      <div class="scan-target-row">
        <div>
          <div class="label">Target</div>
          <div class="scan-url-display">${escHtml(url)}</div>
        </div>
        <span class="badge badge-low">${escHtml(options.mode || 'passive')}</span>
        <div class="elapsed-wrap">
          <i data-lucide="clock"></i>
          <span id="ns-elapsed">0s</span>
        </div>
      </div>

      <!-- Progress bar -->
      <div class="progress-wrap mt-3 mb-3">
        <div class="progress-bar-container">
          <div class="progress-bar-fill" id="ns-progress-fill" style="width:0%"></div>
        </div>
        <span id="ns-progress-pct" class="progress-pct">0%</span>
      </div>

      <!-- Steps -->
      <div class="scan-steps mb-3">
        ${CHECK_STEPS.map((step, i) => `
          <div class="scan-step" id="step-${step.id}" data-index="${i}">
            <div class="step-dot"></div>
            <span class="step-label">${step.name}</span>
          </div>
          ${i < CHECK_STEPS.length - 1 ? '<div class="step-connector"></div>' : ''}
        `).join('')}
      </div>

      <!-- Stats bar -->
      <div class="scan-stats-bar mb-3">
        <div class="scan-stat"><span id="stat-pages-found">0</span><span>Pages Found</span></div>
        <div class="scan-stat"><span id="stat-pages-checked">0</span><span>Checked</span></div>
        <div class="scan-stat"><span id="stat-passed">0</span><span>Passed</span></div>
        <div class="scan-stat text-critical"><span id="stat-failed">0</span><span>Failed</span></div>
      </div>

      <button id="ns-cancel-btn" class="btn btn-danger">
        <i data-lucide="x-circle"></i> Cancel Scan
      </button>
    </div>

    <!-- Live check list -->
    <div class="card mb-3">
      <h3 class="card-title mb-3"><i data-lucide="list-checks"></i> Security Checks</h3>
      <div class="check-list" id="ns-check-list">
        ${SECURITY_MODULES.map(m => `
          <div class="check-item" id="check-${m.replace(/[^a-z0-9]/gi, '-').toLowerCase()}">
            <span class="check-status-icon status-pending"><i data-lucide="minus-circle"></i></span>
            <span class="check-name">${escHtml(m)}</span>
            <span class="check-status-label">Pending</span>
          </div>
        `).join('')}
      </div>
    </div>

    <!-- Scan log -->
    <div class="card">
      <h3 class="card-title mb-2"><i data-lucide="terminal"></i> Scan Log</h3>
      <div class="scan-log" id="ns-scan-log"></div>
    </div>
  `;

  if (typeof lucide !== 'undefined') lucide.createIcons();

  // Start elapsed timer
  if (_elapsedInterval) clearInterval(_elapsedInterval);
  _elapsedInterval = setInterval(() => {
    _elapsedSeconds++;
    const el = container.querySelector('#ns-elapsed');
    if (el) {
      const m = Math.floor(_elapsedSeconds / 60);
      const s = _elapsedSeconds % 60;
      el.textContent = m > 0 ? `${m}m ${s}s` : `${s}s`;
    }
  }, 1000);

  // Cancel button
  container.querySelector('#ns-cancel-btn')?.addEventListener('click', async () => {
    if (_scannerModule?.cancelScan) await _scannerModule.cancelScan();
    if (_elapsedInterval) { clearInterval(_elapsedInterval); _elapsedInterval = null; }
    renderIdle(container);
  });
}

function updateProgress(container, progress) {
  const pct = Math.round(progress.percent || 0);
  const fill = container.querySelector('#ns-progress-fill');
  const pctEl = container.querySelector('#ns-progress-pct');
  if (fill) fill.style.width = `${pct}%`;
  if (pctEl) pctEl.textContent = `${pct}%`;

  // Update step
  if (progress.step) {
    const steps = container.querySelectorAll('.scan-step');
    steps.forEach(el => {
      const isActive = el.id === `step-${progress.step}`;
      const idx = parseInt(el.dataset.index);
      const activeIdx = CHECK_STEPS.findIndex(s => s.id === progress.step);
      el.classList.toggle('active', isActive);
      el.classList.toggle('complete', idx < activeIdx);
    });
  }

  // Update stats
  if (progress.stats) {
    const { pagesFound, pagesChecked, passed, failed } = progress.stats;
    const sf = (id, val) => { const el = container.querySelector(id); if (el && val !== undefined) el.textContent = val; };
    sf('#stat-pages-found', pagesFound);
    sf('#stat-pages-checked', pagesChecked);
    sf('#stat-passed', passed);
    sf('#stat-failed', failed);
  }

  // Update check status
  if (progress.check) {
    const id = `check-${progress.check.name.replace(/[^a-z0-9]/gi, '-').toLowerCase()}`;
    const el = container.querySelector(`#${id}`);
    if (el) {
      const icon = el.querySelector('.check-status-icon');
      const label = el.querySelector('.check-status-label');
      const statusMap = {
        running: { cls: 'status-running', icon: 'loader', label: 'Running' },
        passed: { cls: 'status-passed', icon: 'check-circle', label: 'Passed' },
        failed: { cls: 'status-failed', icon: 'x-circle', label: 'Failed' },
        warning: { cls: 'status-warning', icon: 'alert-triangle', label: 'Warning' },
        error: { cls: 'status-error', icon: 'alert-octagon', label: 'Error' }
      };
      const s = statusMap[progress.check.status] || statusMap.running;
      if (icon) {
        icon.className = `check-status-icon ${s.cls}`;
        icon.innerHTML = `<i data-lucide="${s.icon}"></i>`;
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }
      if (label) label.textContent = s.label;
    }
  }

  // Complete
  if (progress.complete) {
    if (_elapsedInterval) { clearInterval(_elapsedInterval); _elapsedInterval = null; }
    renderComplete(container, progress.result);
  }
}

function addLog(container, msg) {
  if (!msg) return;
  const now = new Date().toLocaleTimeString();
  _logEntries.push({ time: now, msg });
  if (_logEntries.length > 20) _logEntries.shift();
  const logEl = container.querySelector('#ns-scan-log');
  if (logEl) {
    logEl.innerHTML = _logEntries.map(e =>
      `<div class="log-line"><span class="log-time">${escHtml(e.time)}</span> <span>${escHtml(e.msg)}</span></div>`
    ).join('');
    logEl.scrollTop = logEl.scrollHeight;
  }
}

function renderComplete(container, result) {
  if (!result) return;
  const score = Number(result.score || 0);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  const durationMs = Number(result.duration || 0);
  const duration = durationMs >= 60000
    ? `${Math.floor(durationMs / 60000)}m ${Math.round((durationMs % 60000) / 1000)}s`
    : `${Math.max(1, Math.round(durationMs / 1000))}s`;
  const pages = result.attackSurface?.pages?.length || 0;
  const totalFindings = result.summary?.total ?? result.findings?.length ?? 0;
  container.innerHTML = `
    <div class="scan-complete-page">
      <div class="scan-complete-heading">
        <div>
          <div class="scan-complete-eyebrow"><i data-lucide="check-circle-2"></i> Assessment finished</div>
          <h1 class="page-title">Scan Complete</h1>
          <p class="page-subtitle">The read-only assessment for <strong>${escHtml(result.url || 'selected target')}</strong> is ready to review.</p>
        </div>
        <span class="scan-complete-status"><span class="status-dot status-dot--online"></span> Complete</span>
      </div>

      <section class="scan-complete-hero card" aria-label="Scan result">
        <div class="scan-score-block">
          <span class="scan-score-label">Security score</span>
          <div class="scan-score-value">${score}</div>
          <div class="scan-score-meta"><span class="scan-grade">${grade}</span><span>out of 100</span></div>
        </div>
        <div class="scan-result-copy">
          <span class="scan-result-kicker">Final result</span>
          <h2>${score >= 75 ? 'Strong security posture' : score >= 50 ? 'Review recommended' : 'Attention required'}</h2>
          <p>${totalFindings} finding${totalFindings === 1 ? '' : 's'} recorded across ${pages} scanned page${pages === 1 ? '' : 's'}.</p>
        </div>
        <div class="scan-complete-metrics">
          <div><span>Pages scanned</span><strong>${pages}</strong></div>
          <div><span>Total findings</span><strong>${totalFindings}</strong></div>
          <div><span>Duration</span><strong>${duration}</strong></div>
        </div>
      </section>

      <section class="scan-severity-card card" aria-label="Finding severity summary">
        <div class="scan-section-heading"><div><h2>Finding severity</h2><p>Prioritize the controls that need attention first.</p></div><i data-lucide="bar-chart-3"></i></div>
        <div class="scan-severity-grid">
          <div class="scan-severity-item scan-severity-item--critical"><span>Critical</span><strong>${result.summary?.critical || 0}</strong></div>
          <div class="scan-severity-item scan-severity-item--high"><span>High</span><strong>${result.summary?.high || 0}</strong></div>
          <div class="scan-severity-item scan-severity-item--medium"><span>Medium</span><strong>${result.summary?.medium || 0}</strong></div>
          <div class="scan-severity-item scan-severity-item--low"><span>Low</span><strong>${result.summary?.low || 0}</strong></div>
        </div>
      </section>

      <section class="scan-complete-actions card">
        <div><h2>Next actions</h2><p>Investigate the result or generate a report for your records.</p></div>
        <div class="complete-actions">
          <a href="#" class="btn btn-primary" data-nav="findings"><i data-lucide="list"></i> View Full Results</a>
          <a href="#" class="btn btn-secondary" data-nav="reports"><i data-lucide="file-text"></i> Generate Report</a>
          <button class="btn btn-ghost" id="ns-new-scan-btn"><i data-lucide="plus"></i> New Scan</button>
        </div>
      </section>
    </div>
  `;
  if (typeof lucide !== 'undefined') lucide.createIcons();
  container.querySelectorAll('[data-nav]').forEach(el => {
    el.addEventListener('click', e => {
      e.preventDefault();
      document.querySelector(`[data-page="${el.dataset.nav}"]`)?.click();
    });
  });
  container.querySelector('#ns-new-scan-btn')?.addEventListener('click', () => renderIdle(container));
}

async function loadDemoData(container) {
  // Load demo scan data into state and go to findings
  const demoResult = {
    id: 'demo-' + Date.now(),
    url: 'https://example.com',
    score: 62,
    startTime: new Date().toISOString(),
    duration: 18500,
    mode: 'passive',
    summary: { critical: 2, high: 5, medium: 8, low: 11, passed: 24, total: 50 },
    findings: []
  };
  setState({ currentScan: demoResult, viewScanId: demoResult.id });
  document.querySelector('[data-page="findings"]')?.click();
}
