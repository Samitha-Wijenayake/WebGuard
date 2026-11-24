import { getState } from '../state.js';
import { getScan } from '../storage.js';
import { renderNoScan } from './_empty.js';

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

const MAPPINGS = [
  ['Transport encryption', finding => /https|tls|mixed|redirect/i.test(`${finding.checkId} ${finding.title}`)],
  ['Security headers', finding => /header|csp|cache|cors|cookie/i.test(`${finding.checkId} ${finding.category} ${finding.title}`)],
  ['Sensitive data exposure', finding => /exposed|cookie|form|robots/i.test(`${finding.checkId} ${finding.title}`)],
  ['Third-party content', finding => /privacy|sri|tracker|librar/i.test(`${finding.checkId} ${finding.title}`)],
];

export async function render(container) {
  const state = getState();
  const scan = state.viewScanId ? await getScan(state.viewScanId).catch(() => null) : state.currentScan;
  if (!scan) {
    renderNoScan(container, { icon: 'clipboard-check', title: 'Compliance Assessment', subtitle: 'Best-practice mapping of security findings', message: 'Run a scan to map findings onto assessment areas.' });
    return;
  }
  const findings = (scan.findings || []).filter(item => item.status === 'failed' || item.status === 'warning');
  const areas = MAPPINGS.map(([area, match]) => [area, findings.filter(match)]);
  const openAreas = areas.filter(([, related]) => related.length).length;
  const rows = areas.map(([area, related]) => `<tr><td><strong>${escapeHtml(area)}</strong></td><td><span class="count-pill ${related.length ? 'is-open' : 'is-clear'}">${related.length}</span></td><td>${escapeHtml(related.slice(0, 3).map(item => item.title).join('; ') || 'No failed or warning findings in this area')}</td></tr>`);
  container.innerHTML = `
    <div class="page-header"><div><h1 class="page-title"><i data-lucide="clipboard-check"></i> Compliance Assessment</h1><p class="page-subtitle">Best-practice mapping for <strong>${escapeHtml(scan.url)}</strong></p></div></div>
    <div class="stats-row mb-4">
      <div class="stat-card"><div class="stat-icon"><i data-lucide="scan-line"></i></div><div class="stat-value">${scan.summary?.coverage ?? 0}%</div><div class="stat-label">Assessment coverage</div></div>
      <div class="stat-card"><div class="stat-icon ${findings.length ? 'text-high' : 'text-success'}"><i data-lucide="alert-triangle"></i></div><div class="stat-value">${findings.length}</div><div class="stat-label">Failed or warning items</div></div>
      <div class="stat-card"><div class="stat-icon ${openAreas ? 'text-critical' : 'text-success'}"><i data-lucide="layers"></i></div><div class="stat-value">${openAreas}/${areas.length}</div><div class="stat-label">Areas with open items</div></div>
    </div>
    <section class="card">
      <div class="card-header"><div><h3 class="card-title"><i data-lucide="layers"></i> Control areas</h3><p class="card-subtitle">Failed and warning findings grouped by area</p></div></div>
      <table class="table"><thead><tr><th>Area</th><th>Open items</th><th>Examples</th></tr></thead><tbody>${rows.join('')}</tbody></table>
    </section>`;
  if (typeof lucide !== 'undefined') lucide.createIcons();
}
