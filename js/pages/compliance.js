import { getState } from '../state.js';
import { getScan } from '../storage.js';

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
    container.innerHTML = `<div class="page-header"><h1 class="page-title"><i data-lucide="clipboard-check"></i> Compliance Assessment</h1></div><div class="card empty-state"><h3>No completed scan selected</h3><p>Run a scan to map findings onto assessment areas.</p></div>`;
    if (typeof lucide !== 'undefined') lucide.createIcons();
    return;
  }
  const findings = (scan.findings || []).filter(item => item.status === 'failed' || item.status === 'warning');
  const rows = MAPPINGS.map(([area, match]) => {
    const related = findings.filter(match);
    return `<tr><td>${escapeHtml(area)}</td><td>${related.length}</td><td>${escapeHtml(related.slice(0, 3).map(item => item.title).join('; ') || 'No failed or warning findings in this area')}</td></tr>`;
  });
  container.innerHTML = `
    <div class="page-header"><div><h1 class="page-title"><i data-lucide="clipboard-check"></i> Compliance Assessment</h1><p class="page-subtitle">${escapeHtml(scan.url)} · coverage ${scan.summary?.coverage ?? 0}%</p></div></div>
    <div class="card"><table class="table"><thead><tr><th>Area</th><th>Open items</th><th>Examples</th></tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
  if (typeof lucide !== 'undefined') lucide.createIcons();
}
