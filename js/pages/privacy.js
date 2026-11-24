import { getState } from '../state.js';
import { getScan } from '../storage.js';
import { renderNoScan } from './_empty.js';

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
    renderNoScan(container, { icon: 'eye-off', title: 'Privacy Assessment', subtitle: 'Tracker and third-party resource analysis', message: 'Run a scan to inventory third-party hosts and cookies.' });
    return;
  }
  container.innerHTML = `
    <div class="page-header"><div><h1 class="page-title"><i data-lucide="eye-off"></i> Privacy Assessment</h1><p class="page-subtitle">Third-party exposure for <strong>${escapeHtml(scan.url)}</strong></p></div></div>
    <div class="stats-row mb-4">
      <div class="stat-card"><div class="stat-icon ${trackers.length ? 'text-high' : 'text-success'}"><i data-lucide="radar"></i></div><div class="stat-value">${trackers.length}</div><div class="stat-label">Tracker patterns</div></div>
      <div class="stat-card"><div class="stat-icon"><i data-lucide="share-2"></i></div><div class="stat-value">${domains.length}</div><div class="stat-label">External hosts</div></div>
    </div>
    <div class="assessment-grid">
      <section class="card">
        <div class="card-header"><div><h3 class="card-title"><i data-lucide="radar"></i> Tracker patterns</h3><p class="card-subtitle">Known analytics and advertising hosts</p></div><span class="count-pill ${trackers.length ? 'is-open' : 'is-clear'}">${trackers.length}</span></div>
        ${trackers.length ? `<ul class="plain-list">${trackers.map(item => `<li><i data-lucide="radio-tower"></i>${escapeHtml(item)}</li>`).join('')}</ul>` : '<div class="empty-state compact-empty"><i data-lucide="check-circle-2"></i><p>No common tracker hosts were found in the landing page.</p></div>'}
      </section>
      <section class="card">
        <div class="card-header"><div><h3 class="card-title"><i data-lucide="share-2"></i> External hosts</h3><p class="card-subtitle">Third-party origins referenced by the page</p></div><span class="count-pill">${domains.length}</span></div>
        ${domains.length ? `<ul class="plain-list">${domains.map(item => `<li><i data-lucide="globe"></i>${escapeHtml(item)}</li>`).join('')}</ul>` : '<div class="empty-state compact-empty"><i data-lucide="check-circle-2"></i><p>The landing page did not reference another host.</p></div>'}
      </section>
    </div>`;
  if (typeof lucide !== 'undefined') lucide.createIcons();
}
