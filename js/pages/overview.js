// overview.js - Dashboard Overview Page
import { setState } from '../state.js';
import { getAllScans } from '../storage.js';

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

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><i data-lucide="shield"></i> WebGuard Security Platform</h1>
        <p class="page-subtitle">Website security assessment and vulnerability intelligence</p>
      </div>
    </div>

    <!-- Scan Form Card -->
    <div class="card scan-form-card mb-4">
      <div class="scan-form-inner">
        <h2 class="card-title mb-2"><i data-lucide="search"></i> Security Scan</h2>
        <p class="text-secondary mb-3">Enter a URL to perform a comprehensive security assessment.</p>
        <form id="overview-scan-form">
          <div class="input-group mb-3">
            <i data-lucide="globe" class="input-icon"></i>
            <input id="overview-url-input" class="input input-with-icon" type="url"
              placeholder="https://example.com" required autocomplete="url" />
          </div>
          <div class="scan-mode-toggle mb-3">
            <span class="label">Scan Mode:</span>
            <label class="toggle-option">
              <input type="radio" name="overview-mode" value="passive" checked />
              <span class="toggle-btn">
                <i data-lucide="eye"></i> Passive
              </span>
            </label>
            <label class="toggle-option">
              <input type="radio" name="overview-mode" value="verified" />
              <span class="toggle-btn">
                <i data-lucide="shield-check"></i> Verified
              </span>
            </label>
          </div>
          <div class="scan-mode-desc mb-3">
            <div id="mode-desc-passive" class="mode-desc">
              <i data-lucide="info"></i>
              <strong>Passive:</strong> Read-only analysis — no authentication or form submission. Safe for any site.
            </div>
            <div id="mode-desc-verified" class="mode-desc hidden">
              <i data-lucide="alert-triangle"></i>
              <strong>Verified:</strong> Performs additional active checks. Only use on sites you own or have permission to test.
            </div>
          </div>
          <button type="submit" class="btn btn-primary btn-lg" style="width:100%">
            <i data-lucide="play"></i> Start Security Scan
          </button>
        </form>
      </div>
    </div>

    <!-- Stats Row -->
    <div class="stats-row mb-4">
      ${dashboardStats.map(([icon, value, label, tone]) => `<div class="stat-card"><div class="stat-icon ${tone}"><i data-lucide="${icon}"></i></div><div class="stat-value ${tone}">${value}</div><div class="stat-label">${label}</div></div>`).join('')}
    </div>

    <!-- Two-column layout -->
    <div class="two-col-grid mb-4">
      <!-- Recent Scans -->
      <div class="card">
        <div class="card-header">
          <h3 class="card-title"><i data-lucide="history"></i> Recent Scans</h3>
          <a href="#" class="btn btn-ghost btn-sm" data-nav="scan-history">View All</a>
        </div>
        ${recentScans.length === 0
          ? `<div class="empty-state">
              <i data-lucide="shield-off"></i>
              <p>No scans yet. Run your first scan above!</p>
            </div>`
          : `<table class="table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Score</th>
                  <th>Grade</th>
                  <th>Date</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                ${recentScans.map(scan => {
                  const { grade, cls } = getGrade(scan.score || 0);
                  return `<tr>
                    <td class="truncate" style="max-width:150px" title="${escHtml(scan.url)}">${escHtml(scan.url)}</td>
                    <td>${scan.score || 0}</td>
                    <td><span class="badge ${cls}">${grade}</span></td>
                    <td>${new Date(scan.startTime).toLocaleDateString()}</td>
                    <td><a href="#" class="btn btn-ghost btn-sm view-scan-btn" data-scan-id="${escHtml(scan.id)}">View</a></td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table>`
        }
      </div>

      <!-- Risk Distribution Chart -->
      <div class="card">
        <div class="card-header">
          <h3 class="card-title"><i data-lucide="pie-chart"></i> Risk Distribution</h3>
        </div>
        ${lastScan
          ? `<div class="chart-container" style="position:relative;height:220px;display:flex;align-items:center;justify-content:center;">
              <canvas id="risk-chart"></canvas>
            </div>`
          : `<div class="empty-state">
              <i data-lucide="pie-chart"></i>
              <p>Run a scan to see risk distribution</p>
            </div>`
        }
      </div>
    </div>

    <div class="dashboard-intel-grid mb-4">
      <div class="card website-context-card">
        <div class="card-header"><div><h3 class="card-title"><i data-lucide="globe-2"></i> Website context</h3><p class="card-subtitle">Latest inspected surface</p></div><span class="badge badge-info">${lastScan ? 'Inspected' : 'Awaiting scan'}</span></div>
        ${lastScan ? `<div class="website-context-domain">${escHtml(lastScan.url)}</div><div class="website-context-meta"><span><strong>${lastSurface.pages?.length || 0}</strong> pages</span><span><strong>${lastSurface.externalDomains?.length || 0}</strong> external domains</span><span><strong>${lastSurface.endpoints?.length || 0}</strong> endpoints</span></div><div class="website-context-tags">${(lastSurface.technologies || []).slice(0, 5).map(tech => `<span>${escHtml(tech)}</span>`).join('') || '<span>No technology banners disclosed</span>'}</div>` : '<div class="empty-state compact-empty"><i data-lucide="scan-search"></i><p>Run a scan to build the website profile.</p></div>'}
      </div>
      <div class="card recent-findings-card">
        <div class="card-header"><div><h3 class="card-title"><i data-lucide="triangle-alert"></i> Important findings</h3><p class="card-subtitle">Prioritised from the latest scan</p></div><a href="#" class="btn btn-ghost btn-sm" data-nav="findings">Open queue</a></div>
        ${recentFindings.length ? `<div class="dashboard-finding-list">${recentFindings.map(finding => `<div class="dashboard-finding-item"><span class="severity-dot severity-dot--${escHtml(finding.severity || 'info')}"></span><div><strong>${escHtml(finding.title || 'Finding')}</strong><small>${escHtml(finding.category || 'General')}</small></div><span class="badge ${finding.status === 'failed' ? 'badge-failed' : 'badge-warning'}">${escHtml(finding.status || 'info')}</span></div>`).join('')}</div>` : '<div class="empty-state compact-empty"><i data-lucide="check-circle-2"></i><p>No unresolved findings in the latest scan.</p></div>'}
      </div>
    </div>

    <!-- Security Score Overview -->
    ${lastScan ? (() => {
      const { grade, cls } = getGrade(lastScan.score || 0);
      return `
      <div class="card mb-4">
        <div class="card-header">
          <h3 class="card-title"><i data-lucide="shield"></i> Last Scan Overview</h3>
          <span class="text-muted">${escHtml(lastScan.url)}</span>
        </div>
        <div class="score-overview-row">
          <div class="score-overview-score">
            <div class="score-ring-wrap">
              <svg class="score-ring" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="50" fill="none" stroke="var(--border-color)" stroke-width="10"/>
                <circle cx="60" cy="60" r="50" fill="none" stroke="var(--color-primary)" stroke-width="10"
                  stroke-dasharray="${Math.round((lastScan.score || 0) / 100 * 314)} 314"
                  stroke-linecap="round" transform="rotate(-90 60 60)"/>
              </svg>
              <div class="score-ring-label">
                <span class="score-value">${lastScan.score || 0}</span>
                <span class="score-grade badge ${cls}">${grade}</span>
              </div>
            </div>
          </div>
          <div class="score-overview-stats">
            <div class="finding-stat"><span class="badge badge-critical">Critical</span> <strong>${lastScan.summary?.critical || 0}</strong></div>
            <div class="finding-stat"><span class="badge badge-high">High</span> <strong>${lastScan.summary?.high || 0}</strong></div>
            <div class="finding-stat"><span class="badge badge-medium">Medium</span> <strong>${lastScan.summary?.medium || 0}</strong></div>
            <div class="finding-stat"><span class="badge badge-low">Low</span> <strong>${lastScan.summary?.low || 0}</strong></div>
          </div>
          <div class="score-overview-actions">
            <a href="#" class="btn btn-primary" data-nav="findings">View Findings</a>
            <a href="#" class="btn btn-secondary" data-nav="reports">Generate Report</a>
          </div>
        </div>
      </div>`;
    })() : ''}
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
            backgroundColor: ['#EF4444','#F97316','#EAB308','#3B82F6','#22C55E'],
            borderWidth: 2,
            borderColor: '#121C2D'
          }]
        },
        options: {
          cutout: '65%',
          plugins: { legend: { position: 'bottom', labels: { color: '#CBD5E1', font: { size: 12 } } } }
        }
      });
    }
  }
}

export function setScanUrl(url) {
  const input = document.querySelector('#overview-url-input');
  if (input) input.value = url;
}
