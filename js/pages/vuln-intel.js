// vuln-intel.js - Vulnerability Intelligence Page
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

  function cvssClass(score) {
    if (!score) return 'badge-info';
    if (score >= 9) return 'badge-critical';
    if (score >= 7) return 'badge-high';
    if (score >= 4) return 'badge-medium';
    return 'badge-low';
  }

  const vi = scan?.vulnIntel || {};
  const libraries = vi.libraries || [];
  const cves = vi.cves || [];
  const hasNvdKey = !!(state.settings?.nvdApiKey);

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><i data-lucide="bug"></i> Vulnerability Intelligence</h1>
        <p class="page-subtitle">Detected libraries and known CVEs</p>
      </div>
    </div>

    <!-- API Key notice -->
    <div class="alert-${hasNvdKey ? 'info' : 'warning'} mb-4">
      <i data-lucide="${hasNvdKey ? 'key' : 'alert-triangle'}"></i>
      ${hasNvdKey
        ? '<strong>NVD API Key configured.</strong> Enhanced CVE lookup is enabled.'
        : `<strong>No NVD API key configured.</strong> CVE data may be limited or unavailable. 
           <a href="#" data-nav="settings" class="ml-1">Configure API Keys →</a>`
      }
    </div>

    ${!scan ? `
      <div class="empty-state card">
        <i data-lucide="bug"></i>
        <h3>No Scan Data</h3>
        <p>Run a scan to discover vulnerable libraries and CVEs.</p>
        <a href="#" class="btn btn-primary" data-nav="new-scan"><i data-lucide="play"></i> New Scan</a>
      </div>` : `

    <!-- Libraries Table -->
    <div class="card mb-4">
      <div class="card-header">
        <h3 class="card-title"><i data-lucide="package"></i> Detected Libraries</h3>
        <span class="badge badge-low">${libraries.length}</span>
      </div>
      ${libraries.length === 0
        ? `<div class="empty-state-sm"><i data-lucide="check-circle"></i> <span>No known vulnerable libraries detected.</span></div>`
        : `<div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>Library</th>
                  <th>Version</th>
                  <th>CVEs</th>
                  <th>Severity</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                ${libraries.map(lib => `
                  <tr>
                    <td><strong>${escHtml(lib.name)}</strong></td>
                    <td><code>${escHtml(lib.version || '?')}</code></td>
                    <td>${lib.cveCount || 0}</td>
                    <td><span class="badge ${cvssClass(lib.cvss)}">${escHtml(lib.severity || 'Unknown')}</span></td>
                    <td class="text-muted">${escHtml(lib.source || '—')}</td>
                  </tr>`).join('')}
              </tbody>
            </table>
          </div>`
      }
    </div>

    <!-- CVE Detail Cards -->
    ${cves.length > 0 ? `
    <div class="card mb-4">
      <h3 class="card-title mb-3"><i data-lucide="alert-octagon"></i> CVE Details</h3>
      <div class="cve-list">
        ${cves.map(cve => `
          <div class="cve-card finding-card severity-${(cve.severity||'low').toLowerCase()}">
            <div class="cve-header">
              <div class="cve-id-wrap">
                <span class="cve-id">${escHtml(cve.id)}</span>
                <span class="badge ${cvssClass(cve.cvss)}">CVSS ${cve.cvss || 'N/A'}</span>
              </div>
              <span class="badge ${cvssClass(cve.cvss)}">${escHtml(cve.severity || '—')}</span>
            </div>
            <div class="cve-desc mt-2">
              <p>${escHtml(cve.description || 'No description available.')}</p>
            </div>
            ${cve.affectedRange ? `<div class="cve-row mt-1"><span class="label">Affected:</span> <code>${escHtml(cve.affectedRange)}</code></div>` : ''}
            ${cve.fixedIn ? `<div class="cve-row"><span class="label">Fixed in:</span> <code class="text-success">${escHtml(cve.fixedIn)}</code></div>` : ''}
            ${cve.remediation ? `<div class="cve-row mt-2"><i data-lucide="wrench"></i> <span>${escHtml(cve.remediation)}</span></div>` : ''}
            ${cve.url ? `<div class="cve-row mt-1"><a href="${escHtml(cve.url)}" target="_blank" rel="noopener" class="link"><i data-lucide="external-link"></i> NIST Advisory</a></div>` : ''}
          </div>`).join('')}
      </div>
    </div>` : ''}

    ${libraries.length === 0 && cves.length === 0 ? `
      <div class="alert-info">
        <i data-lucide="info"></i>
        <span>No vulnerable libraries or CVEs detected in this scan. Keep dependencies up to date!</span>
      </div>` : ''}
    `}
  `;

  if (typeof lucide !== 'undefined') lucide.createIcons();

  container.querySelectorAll('[data-nav]').forEach(el => {
    el.addEventListener('click', e => {
      e.preventDefault();
      document.querySelector(`[data-page="${el.dataset.nav}"]`)?.click();
    });
  });
}
