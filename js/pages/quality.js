import { getState } from '../state.js';
import { getScan } from '../storage.js';

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

export async function render(container) {
  const state = getState();
  const scan = state.viewScanId ? await getScan(state.viewScanId).catch(() => null) : state.currentScan;
  const quality = scan?.quality;
  if (!scan || !quality) {
    container.innerHTML = `<div class="page-header"><h1 class="page-title"><i data-lucide="gauge"></i> Website Quality</h1></div><div class="card empty-state"><h3>No completed scan selected</h3><p>Run a scan to read the landing page title, description, and image text.</p></div>`;
    if (typeof lucide !== 'undefined') lucide.createIcons();
    return;
  }
  const rows = [
    ['Page title', quality.title || 'Missing'],
    ['Meta description', quality.description || 'Missing'],
    ['Viewport meta tag', quality.viewport ? 'Present' : 'Missing'],
    ['H1 headings', String(quality.h1 || 0)],
    ['Images', String(quality.images || 0)],
    ['Images missing alt', String(quality.imagesMissingAlt || 0)],
  ];
  container.innerHTML = `
    <div class="page-header"><div><h1 class="page-title"><i data-lucide="gauge"></i> Website Quality</h1><p class="page-subtitle">${escapeHtml(scan.url)}</p></div></div>
    <div class="card"><table class="table"><tbody>${rows.map(([label, value]) => `<tr><th>${escapeHtml(label)}</th><td>${escapeHtml(value)}</td></tr>`).join('')}</tbody></table></div>`;
  if (typeof lucide !== 'undefined') lucide.createIcons();
}
