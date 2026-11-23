// attack-surface.js - Attack Surface Visualization Page
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

  const as = scan?.attackSurface || {};
  const domain = as.domain || (scan ? new URL(scan.url).hostname : null);

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><i data-lucide="radar"></i> Attack Surface</h1>
        <p class="page-subtitle">External exposure and technology discovery</p>
      </div>
    </div>

    ${!scan ? `
      <div class="empty-state card">
        <i data-lucide="radar"></i>
        <h3>No Scan Data</h3>
        <p>Run a scan to discover the attack surface of a target.</p>
        <a href="#" class="btn btn-primary" data-nav="new-scan"><i data-lucide="play"></i> New Scan</a>
      </div>` : `

    <!-- Domain Info -->
    <div class="stats-row mb-4">
      <div class="stat-card">
        <div class="stat-icon"><i data-lucide="globe"></i></div>
        <div class="stat-value stat-value-sm">${escHtml(domain || '—')}</div>
        <div class="stat-label">Main Domain</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon"><i data-lucide="server"></i></div>
        <div class="stat-value stat-value-sm">${escHtml(as.ip || '—')}</div>
        <div class="stat-label">IP Address</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon"><i data-lucide="cpu"></i></div>
        <div class="stat-value stat-value-sm">${escHtml(as.server || '—')}</div>
        <div class="stat-label">Server</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon"><i data-lucide="link-2"></i></div>
        <div class="stat-value">${(as.externalDomains || []).length}</div>
        <div class="stat-label">External Domains</div>
      </div>
    </div>

    <div class="two-col-grid mb-4">
      <!-- Technologies -->
      <div class="card">
        <h3 class="card-title mb-3"><i data-lucide="layers"></i> Technologies Detected</h3>
        ${(as.technologies || []).length === 0
          ? '<p class="text-muted">No technologies detected.</p>'
          : `<div class="tech-badges">
              ${(as.technologies || []).map(t => `<span class="tech-badge">${escHtml(t.name || t)}${t.version ? ` <span class="tech-version">${escHtml(t.version)}</span>` : ''}</span>`).join('')}
            </div>`
        }
      </div>

      <!-- Certificate -->
      <div class="card">
        <h3 class="card-title mb-3"><i data-lucide="lock"></i> TLS Certificate</h3>
        ${as.certificate
          ? `<div class="cert-info">
              <div class="cert-row"><span class="label">Subject</span><span>${escHtml(as.certificate.subject || '—')}</span></div>
              <div class="cert-row"><span class="label">Issuer</span><span>${escHtml(as.certificate.issuer || '—')}</span></div>
              <div class="cert-row"><span class="label">Valid From</span><span>${escHtml(as.certificate.validFrom || '—')}</span></div>
              <div class="cert-row"><span class="label">Valid To</span><span>${escHtml(as.certificate.validTo || '—')}</span></div>
              <div class="cert-row"><span class="label">Protocol</span><span>${escHtml(as.certificate.protocol || '—')}</span></div>
            </div>`
          : '<p class="text-muted">Certificate details not available (browser limitation).</p>'
        }
      </div>
    </div>

    <div class="two-col-grid mb-4">
      <!-- Subdomains -->
      <div class="card">
        <h3 class="card-title mb-3"><i data-lucide="git-branch"></i> Subdomains Discovered
          <span class="badge badge-low ml-2">${(as.subdomains || []).length}</span>
        </h3>
        ${(as.subdomains || []).length === 0
          ? '<p class="text-muted">No subdomains discovered.</p>'
          : `<ul class="domain-list">
              ${(as.subdomains || []).map(s => `<li><i data-lucide="corner-down-right"></i> <span>${escHtml(s)}</span></li>`).join('')}
            </ul>`
        }
      </div>

      <!-- External Domains -->
      <div class="card">
        <h3 class="card-title mb-3"><i data-lucide="external-link"></i> External Domains
          <span class="badge badge-low ml-2">${(as.externalDomains || []).length}</span>
        </h3>
        ${(as.externalDomains || []).length === 0
          ? '<p class="text-muted">No external domains found.</p>'
          : `<ul class="domain-list">
              ${(as.externalDomains || []).map(d => `<li><i data-lucide="globe"></i> <span>${escHtml(d)}</span></li>`).join('')}
            </ul>`
        }
      </div>
    </div>

    <div class="two-col-grid mb-4">
      <!-- External Scripts -->
      <div class="card">
        <h3 class="card-title mb-3"><i data-lucide="code-2"></i> External Scripts
          <span class="badge badge-warning ml-2">${(as.externalScripts || []).length}</span>
        </h3>
        ${(as.externalScripts || []).length === 0
          ? '<p class="text-muted">No external scripts found.</p>'
          : `<ul class="url-list">
              ${(as.externalScripts || []).map(s => `<li class="truncate" title="${escHtml(s)}">
                <i data-lucide="file-code"></i> <span>${escHtml(s)}</span>
              </li>`).join('')}
            </ul>`
        }
      </div>

      <!-- Exposed Endpoints -->
      <div class="card">
        <h3 class="card-title mb-3"><i data-lucide="waypoints"></i> Exposed Endpoints
          <span class="badge badge-low ml-2">${(as.endpoints || []).length}</span>
        </h3>
        ${(as.endpoints || []).length === 0
          ? '<p class="text-muted">No notable endpoints found.</p>'
          : `<ul class="url-list">
              ${(as.endpoints || []).map(e => `<li class="truncate" title="${escHtml(e.url || e)}">
                ${e.method ? `<span class="method-badge method-${(e.method||'GET').toLowerCase()}">${escHtml(e.method)}</span>` : ''}
                <span>${escHtml(e.url || e)}</span>
              </li>`).join('')}
            </ul>`
        }
      </div>
    </div>
    `}
  `;

  if (typeof lucide !== 'undefined') lucide.createIcons();

  container.querySelector('[data-nav="new-scan"]')?.addEventListener('click', e => {
    e.preventDefault();
    document.querySelector('[data-page="new-scan"]')?.click();
  });
}
