import { getState } from '../state.js';
import { getScan, saveReport } from '../storage.js';
import { renderNoScan } from './_empty.js';

async function loadScan() {
  const state = getState();
  if (state.viewScanId) {
    try { return await getScan(state.viewScanId); } catch { return null; }
  }
  return state.currentScan || null;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

export async function render(container) {
  const scan = await loadScan();
  if (!scan) {
    renderNoScan(container, { icon: 'file-text', title: 'Reports', subtitle: 'Export completed assessments', message: 'Run a scan, then open Reports to export it.' });
    return;
  }

  const findings = scan.findings || [];
  const reportSummary = scan.summary || {};
  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><i data-lucide="file-text"></i> Reports</h1>
        <p class="page-subtitle">Export the assessment of <strong>${escapeHtml(scan.url)}</strong></p>
      </div>
    </div>
    <div class="report-layout">
      <section class="card">
        <div class="card-header"><div><h3 class="card-title"><i data-lucide="download"></i> Export formats</h3><p class="card-subtitle">This report is built from the selected local scan. It includes the score, severity counts, and finding titles.</p></div></div>
        <div class="report-option">
          <span class="report-option-icon"><i data-lucide="file-text"></i></span>
          <div><strong>PDF report</strong><p>Cover page, executive summary and up to 45 detailed findings with evidence and remediation.</p></div>
          <button class="btn btn-primary" id="report-pdf" type="button"><i data-lucide="download"></i> Download PDF</button>
        </div>
        <div class="report-option">
          <span class="report-option-icon"><i data-lucide="braces"></i></span>
          <div><strong>JSON export</strong><p>The complete scan record, saved in this browser and downloaded for tooling or archiving.</p></div>
          <button class="btn btn-secondary" id="report-json" type="button"><i data-lucide="braces"></i> Download JSON</button>
        </div>
        <p id="report-status" class="text-muted mt-3" role="status"></p>
      </section>
      <aside class="card">
        <div class="card-header"><div><h3 class="card-title"><i data-lucide="clipboard-list"></i> Report contents</h3><p class="card-subtitle">${escapeHtml(new Date(scan.startTime || Date.now()).toLocaleString())}</p></div></div>
        <div class="report-summary-list">
          <div><span>Security score</span><strong>${scan.score ?? 0} / 100</strong></div>
          <div><span>Coverage</span><strong>${reportSummary.coverage ?? 0}%</strong></div>
          <div><span>Critical</span><strong class="text-critical">${reportSummary.critical || 0}</strong></div>
          <div><span>High</span><strong class="text-high">${reportSummary.high || 0}</strong></div>
          <div><span>Medium</span><strong>${reportSummary.medium || 0}</strong></div>
          <div><span>Low</span><strong>${reportSummary.low || 0}</strong></div>
          <div><span>Total findings</span><strong>${findings.length}</strong></div>
        </div>
      </aside>
    </div>`;
  if (typeof lucide !== 'undefined') lucide.createIcons();

  container.querySelector('#report-json').addEventListener('click', async () => {
    try {
      const report = { id: `report-${Date.now()}`, scanId: scan.id, createdAt: new Date().toISOString(), scan };
      await saveReport(report);
      const link = document.createElement('a');
      link.href = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
      link.download = `webguard-${scan.id}.json`;
      link.click();
      URL.revokeObjectURL(link.href);
      container.querySelector('#report-status').textContent = 'JSON report saved in this browser and downloaded.';
    } catch (error) {
      container.querySelector('#report-status').textContent = `JSON export failed: ${error.message}`;
    }
  });

  container.querySelector('#report-pdf').addEventListener('click', async () => {
    const status = container.querySelector('#report-status');
    if (!window.jspdf?.jsPDF) {
      status.textContent = 'PDF library did not load. Check your network connection and try again.';
      return;
    }
    try {
      const doc = new window.jspdf.jsPDF();
      const summary = scan.summary || {};
      const writeWrapped = (text, x, y, width = 180, size = 10) => {
        doc.setFontSize(size);
        const lines = doc.splitTextToSize(text, width);
        doc.text(lines, x, y);
        return y + lines.length * (size * 0.45 + 1.8);
      };
      doc.setFillColor(7, 13, 24);
      doc.rect(0, 0, 210, 297, 'F');
      doc.setTextColor(244, 248, 255);
      doc.setFontSize(28);
      doc.text('WebGuard', 18, 42);
      doc.setFontSize(13);
      doc.setTextColor(78, 161, 255);
      doc.text('SECURITY ASSESSMENT REPORT', 18, 53);
      doc.setTextColor(182, 198, 217);
      writeWrapped(scan.url, 18, 74, 170, 11);
      doc.setFontSize(42);
      doc.setTextColor(50, 209, 214);
      doc.text(String(scan.score ?? 0), 18, 116);
      doc.setFontSize(11);
      doc.setTextColor(182, 198, 217);
      doc.text('Overall security score', 18, 126);
      doc.setFontSize(10);
      doc.text(`Coverage ${summary.coverage ?? 0}%   |   Generated ${new Date().toLocaleString()}`, 18, 145);
      doc.addPage();
      doc.setTextColor(20, 34, 56);
      doc.setFontSize(18);
      doc.text('Executive summary', 14, 20);
      let y = 33;
      y = writeWrapped(`This report documents a read-only WebGuard assessment of ${scan.url}. Findings are based on the responses and landing-page resources available during the scan.`, 14, y, 180, 10);
      y += 8;
      y = writeWrapped(`Severity distribution: ${summary.critical || 0} critical, ${summary.high || 0} high, ${summary.medium || 0} medium, ${summary.low || 0} low. ${summary.notTestable || 0} checks were not testable in this browser-safe workflow.`, 14, y, 180, 10);
      y += 10;
      doc.setFontSize(14);
      doc.text('Detailed findings', 14, y);
      y += 10;
      findings.slice(0, 45).forEach(item => {
        if (y > 275) { doc.addPage(); y = 20; }
        doc.setFontSize(10);
        doc.setTextColor(20, 34, 56);
        y = writeWrapped(`${(item.severity || 'info').toUpperCase()} | ${item.title || 'Finding'}`, 14, y, 180, 10);
        doc.setTextColor(70, 91, 112);
        y = writeWrapped(`Evidence: ${item.evidence || 'Not provided'}\nRemediation: ${item.remediation || 'Review the affected control.'}`, 18, y + 1, 174, 8);
        y += 4;
      });
      doc.save(`webguard-${scan.id}.pdf`);
      await saveReport({ id: `report-${Date.now()}`, scanId: scan.id, createdAt: new Date().toISOString(), format: 'pdf' });
      status.textContent = 'Professional PDF report downloaded.';
    } catch (error) {
      status.textContent = `PDF export failed: ${error.message}`;
    }
  });
}
