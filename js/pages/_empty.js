// _empty.js - Shared "no scan selected" view used by assessment pages
export function renderNoScan(container, { icon, title, subtitle, message }) {
  container.innerHTML = `
    <div class="page-header"><div><h1 class="page-title"><i data-lucide="${icon}"></i> ${title}</h1>${subtitle ? `<p class="page-subtitle">${subtitle}</p>` : ''}</div></div>
    <div class="card empty-state">
      <i data-lucide="scan-search"></i>
      <h3>No completed scan selected</h3>
      <p>${message}</p>
      <div class="mt-3">
        <a href="#" class="btn btn-primary" data-nav="new-scan"><i data-lucide="play"></i> New Scan</a>
        <a href="#" class="btn btn-secondary" data-nav="scan-history"><i data-lucide="history"></i> Scan History</a>
      </div>
    </div>`;
  if (typeof lucide !== 'undefined') lucide.createIcons();
  container.querySelectorAll('[data-nav]').forEach(el => el.addEventListener('click', event => {
    event.preventDefault();
    document.querySelector(`[data-page="${el.dataset.nav}"]`)?.click();
  }));
}
