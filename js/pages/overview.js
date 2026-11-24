// overview.js - Dashboard Overview Page
import { setState } from '../state.js';
import { getAllScans } from '../storage.js';

function cssVar(name, fallback) {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

export async function render(container) {
  container.innerHTML = '';

  let scans = [];
  try { scans = await getAllScans(); } catch (e) { scans = []; }

  const lastScan = scans.length > 0 ? scans[0] : null;

  function getGrade(score) {
    if (score >= 90) return { grade: 'A', cls: 'badge-passed' };
    if (score >= 75) return { grade: 'B', cls: 'badge-low' };
    if (score >= 60) return { grade: 'C', cls: 'badge-warning' };
    if (score >= 40) return { grade: 'D', cls: 'badge-high' };
    return { grade: 'F', cls: 'badge-critical' };
  }

  function escHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  const recentScans = scans.slice(0, 5);
  const lastSummary = lastScan?.summary || {};
  const lastSurface = lastScan?.attackSurface || {};
  const recentFindings = (lastScan?.findings || []).filter(finding => finding.status !== 'passed').slice(0, 5);
  const dashboardStats = [
    ['shield-check', lastScan ? `${lastScan.score || 0}` : '—', 'Overall score', lastScan ? 'text-success' : 'text-muted'],
    ['scan-line', lastScan ? `${lastSummary.coverage || 0}%` : '—', 'Assessment coverage', 'text-blue'],
    ['alert-octagon', lastSummary.critical || 0, 'Critical findings', 'text-critical'],
    ['alert-triangle', lastSummary.high || 0, 'High-risk findings', 'text-high'],
    ['file-search', lastSurface.pages?.length || 0, 'Pages scanned', 'text-secondary'],
    ['cpu', lastSurface.technologies?.length || 0, 'Technology signals', 'text-secondary'],
    ['network', lastSurface.subdomains?.length || 0, 'Subdomains', 'text-secondary'],
    ['package-search', lastScan?.vulnIntel?.libraries?.length || 0, 'Dependencies flagged', 'text-secondary'],
  ];

  const severityRows = ['critical', 'high', 'medium', 'low'].map(key => [key, Number(lastSummary[key] || 0)]);
  const severityMax = Math.max(1, ...severityRows.map(([, count]) => count));
  const lastGrade = getGrade(lastScan?.score || 0);
  const verdict = !lastScan ? '' : (lastScan.score >= 75 ? 'Strong security posture' : lastScan.score >= 50 ? 'Review recommended' : 'Attention required');

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><i data-lucide="layout-dashboard"></i> Security Overview</h1>
        <p class="page-subtitle">${lastScan
          ? `Latest assessment of <strong>${escHtml(lastScan.url)}</strong> · ${escHtml(new Date(lastScan.startTime).toLocaleString())}`
          : 'Website security assessment and vulnerability intelligence'}</p>
      </div>
      <div class="page-header-actions">
        ${lastScan ? '<a href="#" class="btn btn-secondary" data-nav="reports"><i data-lucide="file-text"></i> Report</a>' : ''}
        <a href="#" class="btn btn-primary" data-nav="new-scan"><i data-lucide="plus"></i> New scan</a>
      </div>
    </div>

    <!-- Scan Form Card -->
    <section class="card scan-form-card mb-4" aria-label="Run a security scan">
      <div class="scan-form-inner">
        <div class="scan-form-intro">
          <h2 class="card-title mb-2"><i data-lucide="radar"></i> Run an assessment</h2>
          <p class="text-secondary">Enter a URL to perform a comprehensive security assessment across all 26 check categories.</p>
        </div>
        <form id="overview-scan-form">
          <div class="scan-form-row">
            <div class="input-group">
              <i data-lucide="globe" class="input-icon"></i>
              <input id="overview-url-input" class="input input-with-icon" type="url"
                placeholder="https://example.com" required autocomplete="url" aria-label="Target URL" />
            </div>
            <button type="submit" class="btn btn-primary btn-lg">
              <i data-lucide="play"></i> Start Security Scan
            </button>
          </div>
          <div class="scan-form-options">
            <div class="scan-mode-toggle">
              <span class="label">Mode</span>
              <label class="toggle-option">
                <input type="radio" name="overview-mode" value="passive" checked />
                <span class="toggle-btn"><i data-lucide="eye"></i> Passive</span>
              </label>
              <label class="toggle-option">
                <input type="radio" name="overview-mode" value="verified" />
                <span class="toggle-btn"><i data-lucide="shield-check"></i> Verified</span>
              </label>
            </div>
            <div class="scan-mode-desc">
              <div id="mode-desc-passive" class="mode-desc">
                <i data-lucide="info"></i>
                <span><strong>Passive:</strong> Read-only analysis — no authentication or form submission. Safe for any site.</span>
              </div>
              <div id="mode-desc-verified" class="mode-desc hidden">
                <i data-lucide="alert-triangle"></i>
                <span><strong>Verified:</strong> Performs additional active checks. Only use on sites you own or have permission to test.</span>
              </div>
            </div>
          </div>
        </form>
      </div>
    </section>

    <!-- KPI grid -->
    <section class="kpi-grid mb-4" aria-label="Key metrics">
      ${dashboardStats.map(([icon, value, label, tone]) => `<div class="stat-card"><div class="stat-icon ${tone}"><i data-lucide="${icon}"></i></div><div class="stat-value ${tone}">${value}</div><div class="stat-label">${label}</div></div>`).join('')}
    </section>

    <div class="dash-grid">
      <!-- Security posture -->
      <section class="card card-fill span-4 pair">
        <div class="card-header">
          <div><h3 class="card-title"><i data-lucide="shield"></i> Security posture</h3><p class="card-subtitle">Score and open findings by severity</p></div>
          ${lastScan ? `<span class="badge ${lastGrade.cls}">Grade ${lastGrade.grade}</span>` : ''}
        </div>
        ${lastScan ? `
          <div class="posture-body">
            <div class="score-ring-wrap">
              <svg class="score-ring" viewBox="0 0 120 120" aria-hidden="true">
                <circle cx="60" cy="60" r="50" fill="none" stroke="var(--surface-3)" stroke-width="10"/>
                <circle cx="60" cy="60" r="50" fill="none" stroke="var(--accent)" stroke-width="10"
                  stroke-dasharray="${Math.round((lastScan.score || 0) / 100 * 314)} 314"
                  stroke-linecap="round" transform="rotate(-90 60 60)"/>
              </svg>
              <div class="score-ring-label">
                <span class="score-value">${lastScan.score || 0}</span>
                <span class="text-muted" style="font-size:0.75rem">of 100</span>
              </div>
            </div>
            <div class="severity-bars">
              ${severityRows.map(([key, count]) => `
                <div class="severity-bar severity-bar--${key}">
                  <span style="text-transform:capitalize">${key}</span>
                  <div class="severity-bar-track"><div class="severity-bar-fill" style="width:${Math.round(count / severityMax * 100)}%"></div></div>
                  <strong>${count}</strong>
                </div>`).join('')}
            </div>
          </div>
          <div class="posture-verdict">
            <strong>${verdict}</strong>
            <a href="#" class="btn btn-ghost btn-sm" data-nav="findings">View findings <i data-lucide="arrow-right"></i></a>
          </div>`
        : `<div class="empty-state compact-empty"><i data-lucide="shield-off"></i><p>Run a scan to calculate the security score.</p></div>`}
      </section>

      <!-- Risk Distribution Chart -->
      <section class="card card-fill span-4 pair">
        <div class="card-header">
          <div><h3 class="card-title"><i data-lucide="pie-chart"></i> Risk distribution</h3><p class="card-subtitle">All checks from the latest scan</p></div>
        </div>
        ${lastScan
          ? `<div class="chart-container"><canvas id="risk-chart" aria-label="Risk distribution chart"></canvas></div>`
          : `<div class="empty-state compact-empty"><i data-lucide="pie-chart"></i><p>Run a scan to see risk distribution.</p></div>`}
      </section>

      <!-- Website context -->
      <section class="card card-fill website-context-card span-4">
        <div class="card-header"><div><h3 class="card-title"><i data-lucide="globe-2"></i> Website context</h3><p class="card-subtitle">Latest inspected surface</p></div><span class="badge badge-info">${lastScan ? 'Inspected' : 'Awaiting scan'}</span></div>
        ${lastScan ? `<div class="website-context-domain" title="${escHtml(lastScan.url)}">${escHtml(lastScan.url)}</div><div class="website-context-meta"><span><strong>${lastSurface.pages?.length || 0}</strong> pages</span><span><strong>${lastSurface.externalDomains?.length || 0}</strong> ext. domains</span><span><strong>${lastSurface.endpoints?.length || 0}</strong> endpoints</span></div><div class="website-context-tags">${(lastSurface.technologies || []).slice(0, 6).map(tech => `<span>${escHtml(tech.name || tech)}</span>`).join('') || '<span>No technology banners disclosed</span>'}</div>` : '<div class="empty-state compact-empty"><i data-lucide="scan-search"></i><p>Run a scan to build the website profile.</p></div>'}
      </section>

      <!-- Recent Scans -->
      <section class="card card-fill span-7">
        <div class="card-header">
          <div><h3 class="card-title"><i data-lucide="history"></i> Recent scans</h3><p class="card-subtitle">${scans.length} stored in this browser</p></div>
          <a href="#" class="btn btn-ghost btn-sm" data-nav="scan-history">View all <i data-lucide="arrow-right"></i></a>
        </div>
        ${recentScans.length === 0
          ? `<div class="empty-state compact-empty">
              <i data-lucide="shield-off"></i>
              <p>No scans yet. Run your first scan above.</p>
            </div>`
          : `<table class="table">
              <thead>
                <tr><th>Target</th><th>Score</th><th>Grade</th><th>Critical</th><th>Date</th><th></th></tr>
              </thead>
              <tbody>
                ${recentScans.map(scan => {
                  const { grade, cls } = getGrade(scan.score || 0);
                  return `<tr>
                    <td class="truncate scan-url-cell" title="${escHtml(scan.url)}">${escHtml(scan.url)}</td>
                    <td><strong>${scan.score || 0}</strong></td>
                    <td><span class="badge ${cls}">${grade}</span></td>
                    <td class="${scan.summary?.critical ? 'text-critical' : ''}">${scan.summary?.critical || 0}</td>
                    <td>${new Date(scan.startTime).toLocaleDateString()}</td>
                    <td style="text-align:right"><a href="#" class="btn btn-ghost btn-sm view-scan-btn" data-scan-id="${escHtml(scan.id)}">View</a></td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table>`
        }
      </section>

      <!-- Important findings -->
      <section class="card card-fill recent-findings-card span-5">
        <div class="card-header"><div><h3 class="card-title"><i data-lucide="triangle-alert"></i> Important findings</h3><p class="card-subtitle">Prioritised from the latest scan</p></div><a href="#" class="btn btn-ghost btn-sm" data-nav="findings">Open queue <i data-lucide="arrow-right"></i></a></div>
        ${recentFindings.length ? `<div class="dashboard-finding-list">${recentFindings.map(finding => `<div class="dashboard-finding-item"><span class="severity-dot severity-dot--${escHtml(finding.severity || 'info')}"></span><div><strong title="${escHtml(finding.title || 'Finding')}">${escHtml(finding.title || 'Finding')}</strong><small>${escHtml(finding.category || 'General')}</small></div><span class="badge ${finding.status === 'failed' ? 'badge-failed' : 'badge-warning'}">${escHtml(finding.status || 'info')}</span></div>`).join('')}</div>` : '<div class="empty-state compact-empty"><i data-lucide="check-circle-2"></i><p>No unresolved findings in the latest scan.</p></div>'}
      </section>
    </div>
  `;

  // After DOM ready, wire up events
  if (typeof lucide !== 'undefined') lucide.createIcons();

  // Mode toggle description
  const modeInputs = container.querySelectorAll('input[name="overview-mode"]');
  modeInputs.forEach(input => {
    input.addEventListener('change', () => {
      container.querySelector('#mode-desc-passive').classList.toggle('hidden', input.value !== 'passive');
      container.querySelector('#mode-desc-verified').classList.toggle('hidden', input.value !== 'verified');
    });
  });

  // Form submit
  const form = container.querySelector('#overview-scan-form');
  form?.addEventListener('submit', e => {
    e.preventDefault();
    const url = container.querySelector('#overview-url-input').value.trim();
    const mode = container.querySelector('input[name="overview-mode"]:checked')?.value || 'passive';
    if (!url) return;
    setState({ pendingScanUrl: url, pendingScanMode: mode, pendingAutoStart: true });
    document.querySelector('[data-page="new-scan"]')?.click();
  });

  // Nav links
  container.querySelectorAll('[data-nav]').forEach(el => {
    el.addEventListener('click', e => {
      e.preventDefault();
      document.querySelector(`[data-page="${el.dataset.nav}"]`)?.click();
    });
  });

  // View scan buttons
  container.querySelectorAll('.view-scan-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.preventDefault();
      setState({ viewScanId: btn.dataset.scanId });
      document.querySelector('[data-page="findings"]')?.click();
    });
  });

  // Risk chart
  if (lastScan && typeof Chart !== 'undefined') {
    const ctx = container.querySelector('#risk-chart');
    if (ctx) {
      new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Critical', 'High', 'Medium', 'Low', 'Passed'],
          datasets: [{
            data: [
              lastScan.summary?.critical || 0,
              lastScan.summary?.high || 0,
              lastScan.summary?.medium || 0,
              lastScan.summary?.low || 0,
              lastScan.summary?.passed || 0
            ],
            backgroundColor: ['--sev-critical', '--sev-high', '--sev-medium', '--sev-low', '--sev-passed'].map(name => cssVar(name, '#888')),
            borderWidth: 3,
            borderColor: cssVar('--surface', '#111827'),
            hoverOffset: 4
          }]
        },
        options: {
          maintainAspectRatio: false,
          cutout: '68%',
          plugins: {
            legend: {
              position: 'right',
              labels: { color: cssVar('--text-2', '#aab6c9'), usePointStyle: true, pointStyle: 'circle', boxWidth: 8, padding: 14, font: { size: 12, family: 'Inter' } }
            }
          }
        }
      });
    }
  }
}

export function setScanUrl(url) {
  const input = document.querySelector('#overview-url-input');
  if (input) input.value = url;
}
