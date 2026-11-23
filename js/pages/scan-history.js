// scan-history.js - Scan History Page
import { getState, setState } from '../state.js';
import { getAllScans, deleteScan } from '../storage.js';

const PAGE_SIZE = 10;

export async function render(container) {
  container.innerHTML = '';

  let scans = [];
  try { scans = await getAllScans(); } catch (e) { scans = []; }

  let currentPage = 1;
  let filters = { dateFrom: '', dateTo: '', scoreMin: 0, scoreMax: 100, sortBy: 'date-desc', search: '' };

  function escHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function getGrade(score) {
    if (score >= 90) return { grade: 'A', cls: 'badge-passed' };
    if (score >= 75) return { grade: 'B', cls: 'badge-low' };
    if (score >= 60) return { grade: 'C', cls: 'badge-warning' };
    if (score >= 40) return { grade: 'D', cls: 'badge-high' };
    return { grade: 'F', cls: 'badge-critical' };
  }

  function applyFilters(list) {
    let result = [...list];
    if (filters.search) {
      const q = filters.search.toLowerCase();
      result = result.filter(s => (s.url || '').toLowerCase().includes(q));
    }
    if (filters.dateFrom) result = result.filter(s => new Date(s.startTime) >= new Date(filters.dateFrom));
    if (filters.dateTo) result = result.filter(s => new Date(s.startTime) <= new Date(filters.dateTo + 'T23:59:59'));
    result = result.filter(s => (s.score || 0) >= filters.scoreMin && (s.score || 0) <= filters.scoreMax);
    if (filters.sortBy === 'date-desc') result.sort((a, b) => new Date(b.startTime) - new Date(a.startTime));
    else if (filters.sortBy === 'date-asc') result.sort((a, b) => new Date(a.startTime) - new Date(b.startTime));
    else if (filters.sortBy === 'score-desc') result.sort((a, b) => (b.score || 0) - (a.score || 0));
    else if (filters.sortBy === 'score-asc') result.sort((a, b) => (a.score || 0) - (b.score || 0));
    return result;
  }

  function formatDuration(ms) {
    if (!ms) return '—';
    const s = Math.round(ms / 1000);
    if (s < 60) return `${s}s`;
    return `${Math.floor(s / 60)}m ${s % 60}s`;
  }

  function renderTable() {
    const filtered = applyFilters(scans);
    const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    if (currentPage > totalPages) currentPage = totalPages;
    const pageData = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

    const tableWrap = container.querySelector('#sh-table-wrap');
    const paginationWrap = container.querySelector('#sh-pagination');
    const countEl = container.querySelector('#sh-count');

    if (countEl) countEl.textContent = `${filtered.length} scan${filtered.length !== 1 ? 's' : ''}`;

    if (!tableWrap) return;
    if (filtered.length === 0) {
      tableWrap.innerHTML = `
        <div class="empty-state">
          <i data-lucide="history"></i>
          <h3>No scans found</h3>
          <p>${scans.length === 0 ? 'Run your first scan to see results here.' : 'No scans match your current filters.'}</p>
          ${scans.length === 0 ? '<a href="#" class="btn btn-primary" data-nav="new-scan"><i data-lucide="play"></i> New Scan</a>' : ''}
        </div>`;
      if (typeof lucide !== 'undefined') lucide.createIcons();
      tableWrap.querySelector('[data-nav="new-scan"]')?.addEventListener('click', e => {
        e.preventDefault();
        document.querySelector('[data-page="new-scan"]')?.click();
      });
      if (paginationWrap) paginationWrap.innerHTML = '';
      return;
    }

    tableWrap.innerHTML = `
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>Date</th>
              <th>Target URL</th>
              <th>Score</th>
              <th>Grade</th>
              <th>Critical</th>
              <th>High</th>
              <th>Medium</th>
              <th>Low</th>
              <th>Duration</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${pageData.map(scan => {
              const { grade, cls } = getGrade(scan.score || 0);
              const critical = scan.summary?.critical || 0;
              return `<tr>
                <td>${new Date(scan.startTime).toLocaleString()}</td>
                <td class="truncate" style="max-width:200px" title="${escHtml(scan.url)}">${escHtml(scan.url)}</td>
                <td><strong>${scan.score || 0}</strong></td>
                <td><span class="badge ${cls}">${grade}</span></td>
                <td class="${critical > 0 ? 'text-critical' : ''}">${critical}</td>
                <td>${scan.summary?.high || 0}</td>
                <td>${scan.summary?.medium || 0}</td>
                <td>${scan.summary?.low || 0}</td>
                <td>${formatDuration(scan.duration)}</td>
                <td>
                  <div class="action-btns">
                    <button class="btn btn-ghost btn-sm view-btn" data-id="${escHtml(scan.id)}" title="View">
                      <i data-lucide="eye"></i>
                    </button>
                    <button class="btn btn-ghost btn-sm export-btn" data-id="${escHtml(scan.id)}" title="Export JSON">
                      <i data-lucide="download"></i>
                    </button>
                    <button class="btn btn-danger btn-sm delete-btn" data-id="${escHtml(scan.id)}" title="Delete">
                      <i data-lucide="trash-2"></i>
                    </button>
                  </div>
                </td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>`;

    if (typeof lucide !== 'undefined') lucide.createIcons();

    // Wire actions
    tableWrap.querySelectorAll('.view-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        setState({ viewScanId: btn.dataset.id });
        document.querySelector('[data-page="findings"]')?.click();
      });
    });

    tableWrap.querySelectorAll('.export-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const scan = scans.find(s => s.id === btn.dataset.id);
        if (!scan) return;
        const blob = new Blob([JSON.stringify(scan, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `webguard-scan-${btn.dataset.id}.json`;
        a.click();
      });
    });

    tableWrap.querySelectorAll('.delete-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm('Delete this scan? This cannot be undone.')) return;
        try { await deleteScan(btn.dataset.id); } catch (e) {}
        scans = scans.filter(s => s.id !== btn.dataset.id);
        renderTable();
      });
    });

    // Pagination
    if (paginationWrap) {
      if (totalPages <= 1) { paginationWrap.innerHTML = ''; return; }
      paginationWrap.innerHTML = `
        <div class="pagination">
          <button class="btn btn-ghost btn-sm" id="pg-prev" ${currentPage === 1 ? 'disabled' : ''}>
            <i data-lucide="chevron-left"></i> Prev
          </button>
          <span class="pg-info">Page ${currentPage} of ${totalPages}</span>
          <button class="btn btn-ghost btn-sm" id="pg-next" ${currentPage === totalPages ? 'disabled' : ''}>
            Next <i data-lucide="chevron-right"></i>
          </button>
        </div>`;
      if (typeof lucide !== 'undefined') lucide.createIcons();
      paginationWrap.querySelector('#pg-prev')?.addEventListener('click', () => { currentPage--; renderTable(); });
      paginationWrap.querySelector('#pg-next')?.addEventListener('click', () => { currentPage++; renderTable(); });
    }
  }

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><i data-lucide="history"></i> Scan History</h1>
        <p class="page-subtitle">Review and manage your previous security assessments</p>
      </div>
      <div class="page-header-actions">
        <span id="sh-count" class="text-muted"></span>
        <button id="sh-clear-all" class="btn btn-danger btn-sm">
          <i data-lucide="trash-2"></i> Clear All
        </button>
      </div>
    </div>

    <!-- Filter Bar -->
    <div class="card filter-bar mb-3">
      <div class="filter-row">
        <div class="filter-group">
          <label class="label">Search</label>
          <input id="sh-search" class="input" type="search" placeholder="Filter by URL..." />
        </div>
        <div class="filter-group">
          <label class="label">From</label>
          <input id="sh-date-from" class="input" type="date" />
        </div>
        <div class="filter-group">
          <label class="label">To</label>
          <input id="sh-date-to" class="input" type="date" />
        </div>
        <div class="filter-group">
          <label class="label">Min Score</label>
          <input id="sh-score-min" class="input" type="number" min="0" max="100" value="0" style="width:80px" />
        </div>
        <div class="filter-group">
          <label class="label">Sort</label>
          <select id="sh-sort" class="select">
            <option value="date-desc">Newest First</option>
            <option value="date-asc">Oldest First</option>
            <option value="score-desc">Highest Score</option>
            <option value="score-asc">Lowest Score</option>
          </select>
        </div>
      </div>
    </div>

    <div id="sh-table-wrap"></div>
    <div id="sh-pagination" class="mt-3"></div>
  `;

  if (typeof lucide !== 'undefined') lucide.createIcons();
  renderTable();

  // Filter events
  container.querySelector('#sh-search')?.addEventListener('input', e => {
    filters.search = e.target.value; currentPage = 1; renderTable();
  });
  container.querySelector('#sh-date-from')?.addEventListener('change', e => {
    filters.dateFrom = e.target.value; currentPage = 1; renderTable();
  });
  container.querySelector('#sh-date-to')?.addEventListener('change', e => {
    filters.dateTo = e.target.value; currentPage = 1; renderTable();
  });
  container.querySelector('#sh-score-min')?.addEventListener('change', e => {
    filters.scoreMin = parseInt(e.target.value) || 0; currentPage = 1; renderTable();
  });
  container.querySelector('#sh-sort')?.addEventListener('change', e => {
    filters.sortBy = e.target.value; currentPage = 1; renderTable();
  });
  container.querySelector('#sh-clear-all')?.addEventListener('click', async () => {
    if (!confirm(`Delete all ${scans.length} scans? This cannot be undone.`)) return;
    for (const scan of scans) {
      try { await deleteScan(scan.id); } catch (e) {}
    }
    scans = [];
    renderTable();
  });
}
