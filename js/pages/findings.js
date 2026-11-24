// findings.js - Security Findings Viewer
import { getState } from '../state.js';
import { getScan } from '../storage.js';

export async function render(container) {
  container.innerHTML = '';

  const state = getState();
  let scan = state.viewScanId ? null : state.currentScan || null;

  if (state.viewScanId) {
    try { scan = await getScan(state.viewScanId); } catch (e) {}
  }

  function escHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function severityClass(sev) {
    const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low', info: 'badge-info', passed: 'badge-passed' };
    return map[(sev || '').toLowerCase()] || 'badge-info';
  }

  function normalizeStatus(st) {
    return String(st || 'info').toLowerCase().replace(/[\s_]+/g, '-');
  }

  function statusClass(st) {
    const map = { passed: 'badge-passed', failed: 'badge-failed', warning: 'badge-warning', 'not-testable': 'badge-not-testable', error: 'badge-not-testable', info: 'badge-info' };
    return map[normalizeStatus(st)] || 'badge-info';
  }

  if (!scan) {
    container.innerHTML = `
      <div class="page-header">
        <h1 class="page-title"><i data-lucide="shield-alert"></i> Security Findings</h1>
      </div>
      <div class="empty-state card">
        <i data-lucide="shield-off"></i>
        <h3>No Scan Selected</h3>
        <p>Run a new scan or select one from Scan History to view findings.</p>
        <div class="mt-3">
          <a href="#" class="btn btn-primary" data-nav="new-scan"><i data-lucide="play"></i> New Scan</a>
          <a href="#" class="btn btn-secondary ml-2" data-nav="scan-history"><i data-lucide="history"></i> Scan History</a>
        </div>
      </div>`;
    if (typeof lucide !== 'undefined') lucide.createIcons();
    container.querySelectorAll('[data-nav]').forEach(el => {
      el.addEventListener('click', e => {
        e.preventDefault();
        document.querySelector(`[data-page="${el.dataset.nav}"]`)?.click();
      });
    });
    return;
  }

  const findings = scan.findings || [];
  const categories = [...new Set(findings.map(f => f.category || 'General'))].sort((a, b) => a.localeCompare(b));
  const severities = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const statuses = [
    { id: 'passed', label: 'Passed' },
    { id: 'failed', label: 'Failed' },
    { id: 'warning', label: 'Warning' },
    { id: 'info', label: 'Info' },
    { id: 'not-testable', label: 'Not Testable' },
    { id: 'error', label: 'Error' },
  ];

  let filters = {
    severities: new Set(severities.map(s => s.toLowerCase())),
    statuses: new Set(statuses.map(s => s.id)),
    category: '',
    search: '',
    sortKey: 'severity',
    sortDirection: 'desc',
    page: 1,
    pageSize: 10,
  };

  const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const statusOrder = { failed: 5, warning: 4, error: 3, 'not-testable': 2, info: 1, passed: 0 };
  const scanDate = scan.completedAt || scan.startTime || scan.createdAt;
  const summaryCounts = {
    total: findings.length,
    critical: findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length,
    high: findings.filter(f => (f.severity || '').toLowerCase() === 'high').length,
    medium: findings.filter(f => (f.severity || '').toLowerCase() === 'medium').length,
    low: findings.filter(f => (f.severity || '').toLowerCase() === 'low').length,
    passed: findings.filter(f => normalizeStatus(f.status) === 'passed').length,
    warning: findings.filter(f => normalizeStatus(f.status) === 'warning').length,
    notTestable: findings.filter(f => normalizeStatus(f.status) === 'not-testable').length,
  };

  function applyFilters() {
    return findings.filter(f => {
      const sev = (f.severity || 'info').toLowerCase();
      const st = normalizeStatus(f.status);
      const cat = (f.category || 'General');
      if (!filters.severities.has(sev)) return false;
      if (!filters.statuses.has(st)) return false;
      if (filters.category && cat !== filters.category) return false;
      if (filters.search) {
        const q = filters.search.toLowerCase();
        return (f.title || '').toLowerCase().includes(q)
          || (f.url || '').toLowerCase().includes(q)
          || (f.description || '').toLowerCase().includes(q);
      }
      return true;
    });
  }

  function sortFindings(list) {
    const direction = filters.sortDirection === 'asc' ? 1 : -1;
    return [...list].sort((first, second) => {
      let left;
      let right;
      if (filters.sortKey === 'severity') {
        left = severityOrder[(first.severity || 'info').toLowerCase()] || 0;
        right = severityOrder[(second.severity || 'info').toLowerCase()] || 0;
      } else if (filters.sortKey === 'status') {
        left = statusOrder[normalizeStatus(first.status)] || 0;
        right = statusOrder[normalizeStatus(second.status)] || 0;
      } else if (filters.sortKey === 'date') {
        left = new Date(first.date || scanDate || 0).getTime();
        right = new Date(second.date || scanDate || 0).getTime();
      } else {
        left = String(first[filters.sortKey] || first.title || '').toLowerCase();
        right = String(second[filters.sortKey] || second.title || '').toLowerCase();
      }
      if (left < right) return -1 * direction;
      if (left > right) return 1 * direction;
      return 0;
    });
  }

  function resetFilters() {
    filters.severities = new Set(severities.map(severity => severity.toLowerCase()));
    filters.statuses = new Set(statuses.map(status => status.id));
    filters.category = '';
    filters.search = '';
    filters.sortKey = 'severity';
    filters.sortDirection = 'desc';
    filters.page = 1;
    container.querySelectorAll('.sev-check, .st-check').forEach(input => { input.checked = true; });
    const category = container.querySelector('#fd-cat-filter');
    const search = container.querySelector('#fd-search');
    if (category) category.value = '';
    if (search) search.value = '';
  }

  function exportCSV() {
    const cols = ['Severity', 'Status', 'Category', 'Title', 'URL', 'Confidence', 'Description'];
    const rows = applyFilters().map(f => [
      f.severity || '', f.status || '', f.category || '', f.title || '',
      f.url || '', f.confidence || '', (f.description || '').replace(/\n/g, ' ')
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));
    const csv = [cols.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `webguard-findings-${scan.id}.csv`;
    a.click();
  }

  function renderFindings() {
    const filtered = sortFindings(applyFilters());
    const pageCount = Math.max(1, Math.ceil(filtered.length / filters.pageSize));
    filters.page = Math.min(filters.page, pageCount);
    const start = (filters.page - 1) * filters.pageSize;
    const pageItems = filtered.slice(start, start + filters.pageSize);
    const countEl = container.querySelector('#fd-count');
    if (countEl) countEl.textContent = filtered.length ? `Showing ${start + 1}-${Math.min(start + filters.pageSize, filtered.length)} of ${filtered.length} findings` : 'No findings match the current filters';

    const listEl = container.querySelector('#fd-list');
    if (!listEl) return;

    if (filtered.length === 0) {
      listEl.innerHTML = `<div class="empty-state"><i data-lucide="check-circle"></i><p>No findings match your current filters.</p></div>`;
      const detail = container.querySelector('#fd-detail');
      if (detail) detail.innerHTML = '<div class="detail-eyebrow">Risk context</div><p class="text-muted mt-2">Select a finding to inspect its evidence and remediation.</p>';
      if (typeof lucide !== 'undefined') lucide.createIcons();
      return;
    }

    const sortIcon = key => filters.sortKey === key ? (filters.sortDirection === 'asc' ? 'arrow-up' : 'arrow-down') : 'chevrons-up-down';
    listEl.innerHTML = `<div class="findings-table-wrap"><table class="table findings-table"><thead><tr>
      <th><button class="sort-button" data-sort-key="severity">Severity <i data-lucide="${sortIcon('severity')}"></i></button></th>
      <th><button class="sort-button" data-sort-key="title">Finding <i data-lucide="${sortIcon('title')}"></i></button></th>
      <th>Affected URL</th>
      <th><button class="sort-button" data-sort-key="category">Category <i data-lucide="${sortIcon('category')}"></i></button></th>
      <th><button class="sort-button" data-sort-key="status">Status <i data-lucide="${sortIcon('status')}"></i></button></th>
      <th><button class="sort-button" data-sort-key="date">Date <i data-lucide="${sortIcon('date')}"></i></button></th><th></th></tr></thead><tbody>${pageItems.map(f => `
      <tr class="finding-row" tabindex="0" data-finding-index="${findings.indexOf(f)}">
        <td><span class="badge ${severityClass(f.severity)}">${escHtml(f.severity || 'Info')}</span></td>
        <td><strong>${escHtml(f.title || 'Unnamed Finding')}</strong><small>${escHtml(f.confidence || 'Observed')}${(f.pageCount || 0) > 1 ? ` · ${f.pageCount} pages` : ''}</small></td>
        <td class="finding-table-url" title="${escHtml(f.url || scan.url)}">${escHtml(f.url || scan.url)}</td>
        <td>${escHtml(f.category || 'General')}</td>
        <td><span class="badge ${statusClass(f.status)}">${escHtml(f.status || 'Info')}</span></td>
        <td>${escHtml(new Date(f.date || scanDate).toLocaleDateString())}</td>
        <td><i data-lucide="chevron-right" class="row-chevron"></i></td>
      </tr>`).join('')}</tbody></table></div><div class="findings-pagination"><button class="btn btn-ghost btn-sm" id="fd-prev" type="button" ${filters.page <= 1 ? 'disabled' : ''}><i data-lucide="chevron-left"></i> Previous</button><span>Page ${filters.page} of ${pageCount}</span><button class="btn btn-ghost btn-sm" id="fd-next" type="button" ${filters.page >= pageCount ? 'disabled' : ''}>Next <i data-lucide="chevron-right"></i></button></div>`;

    if (typeof lucide !== 'undefined') lucide.createIcons();
    listEl.querySelectorAll('.sort-button').forEach(button => {
      button.addEventListener('click', () => {
        const key = button.dataset.sortKey;
        filters.sortDirection = filters.sortKey === key && filters.sortDirection === 'desc' ? 'asc' : 'desc';
        filters.sortKey = key;
        filters.page = 1;
        renderFindings();
      });
    });
    listEl.querySelector('#fd-prev')?.addEventListener('click', () => { filters.page -= 1; renderFindings(); });
    listEl.querySelector('#fd-next')?.addEventListener('click', () => { filters.page += 1; renderFindings(); });
    listEl.querySelectorAll('.finding-row').forEach(row => {
      const open = () => renderDetail(findings[Number(row.dataset.findingIndex)]);
      row.addEventListener('click', open);
      row.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(); } });
    });
    if (pageItems[0]) renderDetail(pageItems[0]);
  }

  function renderDetail(finding) {
    const detail = container.querySelector('#fd-detail');
    if (!detail || !finding) return;
    detail.innerHTML = `<div class="detail-eyebrow">Risk context</div><div class="detail-title-row"><h2>${escHtml(finding.title || 'Finding')}</h2><span class="badge ${severityClass(finding.severity)}">${escHtml(finding.severity || 'Info')}</span></div><div class="detail-meta"><span>${escHtml(finding.category || 'General')}</span><span>${escHtml(finding.status || 'Info')}</span></div><div class="detail-block"><span>Evidence</span><pre class="code-block">${escHtml(finding.evidence || 'No technical evidence was recorded.')}</pre></div><div class="detail-block"><span>Risk explanation</span><p>${escHtml(finding.impact || finding.description || 'No additional impact description was recorded.')}</p></div><div class="detail-block detail-remediation"><span>Recommended remediation</span><p>${escHtml(finding.remediation || finding.recommendation || 'Review this control and validate the fix with a follow-up scan.')}</p></div>${(finding.affectedUrls?.length || 0) > 1
      ? `<div class="detail-block"><span>Affected pages (${finding.pageCount || finding.affectedUrls.length})</span><ul class="affected-list">${finding.affectedUrls.map(link => `<li><a class="detail-url" href="${escHtml(link)}" target="_blank" rel="noopener">${escHtml(link)}</a></li>`).join('')}</ul>${(finding.pageCount || 0) > finding.affectedUrls.length ? `<p class="text-muted mt-2">and ${finding.pageCount - finding.affectedUrls.length} more</p>` : ''}</div>`
      : finding.url ? `<div class="detail-block"><span>Affected URL</span><a class="detail-url" href="${escHtml(finding.url)}" target="_blank" rel="noopener">${escHtml(finding.url)}</a></div>` : ''}`;
  }

  const getGrade = s => {
    if (s >= 90) return { grade: 'A', cls: 'badge-passed' };
    if (s >= 75) return { grade: 'B', cls: 'badge-low' };
    if (s >= 60) return { grade: 'C', cls: 'badge-warning' };
    if (s >= 40) return { grade: 'D', cls: 'badge-high' };
    return { grade: 'F', cls: 'badge-critical' };
  };
  const { grade, cls } = getGrade(scan.score || 0);

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><i data-lucide="shield-alert"></i> Security Findings</h1>
        <p class="page-subtitle">
          <span class="text-muted">${escHtml(scan.url)}</span>
          &nbsp;·&nbsp;
          Score: <strong>${scan.score || 0}</strong>
          <span class="badge ${cls} ml-1">${grade}</span>
          &nbsp;·&nbsp;
          ${new Date(scan.startTime).toLocaleString()}
        </p>
      </div>
      <button id="fd-export-btn" class="btn btn-secondary btn-sm">
        <i data-lucide="download"></i> Export CSV
      </button>
    </div>

    <section class="finding-summary-grid" aria-label="Finding summary">
      <div class="finding-summary-card finding-summary-card--total"><span>Total findings</span><strong>${summaryCounts.total}</strong><small>From this scan</small></div>
      <div class="finding-summary-card finding-summary-card--critical"><span>Critical</span><strong>${summaryCounts.critical}</strong><small>Immediate attention</small></div>
      <div class="finding-summary-card finding-summary-card--high"><span>High</span><strong>${summaryCounts.high}</strong><small>Prioritise remediation</small></div>
      <div class="finding-summary-card finding-summary-card--medium"><span>Medium</span><strong>${summaryCounts.medium}</strong><small>Review and address</small></div>
      <div class="finding-summary-card finding-summary-card--low"><span>Low</span><strong>${summaryCounts.low}</strong><small>Advisory findings</small></div>
      <div class="finding-summary-card finding-summary-card--status"><span>Passed</span><strong>${summaryCounts.passed}</strong><small>Controls satisfied</small></div>
      <div class="finding-summary-card finding-summary-card--status"><span>Warning</span><strong>${summaryCounts.warning}</strong><small>Needs review</small></div>
      <div class="finding-summary-card finding-summary-card--status"><span>Not testable</span><strong>${summaryCounts.notTestable}</strong><small>Outside scan scope</small></div>
    </section>

    <div class="findings-layout">
      <!-- Filter sidebar -->
      <aside class="findings-sidebar card">
        <div class="filter-panel-heading"><div><span class="filter-panel-kicker">Findings queue</span><h3 class="card-title"><i data-lucide="filter"></i> Filters</h3></div><span class="filter-panel-count">${findings.length}</span></div>

        <div class="filter-section filter-section--options">
          <div class="filter-section-heading"><span class="label">Severity</span><span class="filter-section-hint">Risk level</span></div>
          <div class="filter-option-grid">
          ${severities.map(sev => `
            <label class="filter-checkbox">
              <input type="checkbox" class="sev-check" value="${sev.toLowerCase()}" checked />
              <span class="badge ${severityClass(sev.toLowerCase())}">${sev}</span>
              <span class="filter-count">${findings.filter(f => (f.severity||'info').toLowerCase() === sev.toLowerCase()).length}</span>
            </label>`).join('')}
          </div>
        </div>

        <div class="filter-section filter-section--options">
          <div class="filter-section-heading"><span class="label">Status</span><span class="filter-section-hint">Workflow state</span></div>
          <div class="filter-option-grid filter-option-grid--status">
          ${statuses.map(st => `
            <label class="filter-checkbox">
              <input type="checkbox" class="st-check" value="${st.id}" checked />
              <span>${st.label}</span>
            </label>`).join('')}
          </div>
        </div>

        <div class="filter-section filter-section--field">
          <div class="filter-section-heading"><span class="label">Category</span><span class="filter-section-hint">Assessment area</span></div>
          <select id="fd-cat-filter" class="select">
            <option value="">All Categories</option>
            ${categories.map(c => `<option value="${escHtml(c)}">${escHtml(c)}</option>`).join('')}
          </select>
        </div>

        <div class="filter-section filter-section--field filter-section--search">
          <div class="filter-section-heading"><label class="label" for="fd-search">Search findings</label><i data-lucide="search"></i></div>
          <div class="filter-search-wrap"><i data-lucide="search"></i><input id="fd-search" class="input" type="search" placeholder="Name, URL or evidence" /></div>
        </div>
        <div class="filter-panel-actions"><button id="fd-clear-filters" class="btn btn-ghost btn-sm w-full" type="button"><i data-lucide="rotate-ccw"></i> Clear filters</button></div>
      </aside>

      <!-- Main findings list -->
        <main class="findings-main">
        <div class="findings-summary mb-3">
          <span id="fd-count" class="text-muted"></span>
        </div>
        <div id="fd-list"></div>
        <aside id="fd-detail" class="finding-detail card" aria-live="polite"></aside>
      </main>
    </div>
  `;

  if (typeof lucide !== 'undefined') lucide.createIcons();
  renderFindings();

  // Filter events
  container.querySelectorAll('.sev-check').forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) filters.severities.add(cb.value); else filters.severities.delete(cb.value);
      filters.page = 1;
      renderFindings();
    });
  });
  container.querySelectorAll('.st-check').forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) filters.statuses.add(cb.value); else filters.statuses.delete(cb.value);
      filters.page = 1;
      renderFindings();
    });
  });
  container.querySelector('#fd-cat-filter')?.addEventListener('change', e => {
    filters.category = e.target.value; filters.page = 1; renderFindings();
  });
  container.querySelector('#fd-search')?.addEventListener('input', e => {
    filters.search = e.target.value; filters.page = 1; renderFindings();
  });
  container.querySelector('#fd-clear-filters')?.addEventListener('click', () => { resetFilters(); renderFindings(); });
  container.querySelector('#fd-export-btn')?.addEventListener('click', exportCSV);
}
