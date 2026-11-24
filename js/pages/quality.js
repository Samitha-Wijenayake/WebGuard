import { getState } from '../state.js';
import { getScan } from '../storage.js';
import { renderNoScan } from './_empty.js';

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

export async function render(container) {
  const state = getState();
  const scan = state.viewScanId ? await getScan(state.viewScanId).catch(() => null) : state.currentScan;
  const quality = scan?.quality;
  if (!scan || !quality) {
    renderNoScan(container, { icon: 'gauge', title: 'Website Quality', subtitle: 'SEO, accessibility and page structure signals', message: 'Run a scan to read the landing page title, description, and image text.' });
    return;
  }
  const missingAlt = Number(quality.imagesMissingAlt || 0);
  const h1 = Number(quality.h1 || 0);
  const rows = [
    ['Page title', quality.title || 'Missing', Boolean(quality.title), 'heading'],
    ['Meta description', quality.description || 'Missing', Boolean(quality.description), 'align-left'],
    ['Viewport meta tag', quality.viewport ? 'Present' : 'Missing', Boolean(quality.viewport), 'smartphone'],
    ['H1 headings', String(h1), h1 === 1, 'heading-1'],
    ['Images', String(quality.images || 0), true, 'image'],
    ['Images missing alt', String(missingAlt), missingAlt === 0, 'image-off'],
  ];
  const passing = rows.filter(row => row[2]).length;
  container.innerHTML = `
    <div class="page-header"><div><h1 class="page-title"><i data-lucide="gauge"></i> Website Quality</h1><p class="page-subtitle">Landing page signals for <strong>${escapeHtml(scan.url)}</strong></p></div></div>
    <div class="stats-row mb-4">
      <div class="stat-card"><div class="stat-icon text-success"><i data-lucide="check-circle-2"></i></div><div class="stat-value">${passing}/${rows.length}</div><div class="stat-label">Signals in good shape</div></div>
      <div class="stat-card"><div class="stat-icon"><i data-lucide="image"></i></div><div class="stat-value">${quality.images || 0}</div><div class="stat-label">Images on page</div></div>
      <div class="stat-card"><div class="stat-icon ${missingAlt ? 'text-high' : 'text-success'}"><i data-lucide="image-off"></i></div><div class="stat-value">${missingAlt}</div><div class="stat-label">Missing alt text</div></div>
    </div>
    <section class="card">
      <div class="card-header"><div><h3 class="card-title"><i data-lucide="list-checks"></i> Quality signals</h3><p class="card-subtitle">Read from the landing page HTML</p></div></div>
      <div class="quality-grid">
        ${rows.map(([label, value, ok, icon]) => `<div class="check-tile"><span class="check-tile-icon ${ok ? 'is-ok' : 'is-warn'}"><i data-lucide="${icon}"></i></span><div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div></div>`).join('')}
      </div>
    </section>`;
  if (typeof lucide !== 'undefined') lucide.createIcons();
}
