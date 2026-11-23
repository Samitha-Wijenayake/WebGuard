import { getState } from '../state.js';
import { getScan } from '../storage.js';

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

export async function render(container) {
  const state = getState();
  const scan = state.viewScanId ? await getScan(state.viewScanId).catch(() => null) : state.currentScan;
  const privacy = scan?.privacy || {};
  const trackers = privacy.trackers || [];
  const domains = privacy.externalDomains || [];
  if (!scan) {
    container.innerHTML = `<div class="page-header"><h1 class="page-title"><i data-lucide="eye-off"></i> Privacy Assessment</h1></div><div class="card empty-state"><h3>No completed scan selected</h3><p>Run a scan to inventory third-party hosts and cookies.</p></div>`;
    if (typeof lucide !== 'undefined') lucide.createIcons();
    return;
  }
  container.innerHTML = `
    <div class="page-header"><div><h1 class="page-title"><i data-lucide="eye-off"></i> Privacy Assessment</h1><p class="page-subtitle">${escapeHtml(scan.url)}</p></div></div>
    <div class="stats-row mb-4">
      <div class="stat-card"><div class="stat-value">${trackers.length}</div><div class="stat-label">Tracker patterns</div></div>
      <div class="stat-card"><div class="stat-value">${domains.length}</div><div class="stat-label">External hosts</div></div>
    </div>
    <div class="card mb-4"><h3 class="card-title">Tracker patterns</h3>${trackers.length ? `<ul>${trackers.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>` : '<p class="text-muted">No common tracker hosts were found in the landing page.</p>'}</div>
    <div class="card"><h3 class="card-title">External hosts</h3>${domains.length ? `<ul>${domains.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>` : '<p class="text-muted">The landing page did not reference another host.</p>'}</div>`;
  if (typeof lucide !== 'undefined') lucide.createIcons();
}
