/**
 * WebGuard – Router  (js/router.js)
 * Manages SPA routing via data-page attributes.
 */

let currentPage = 'overview';
const listeners = [];

/**
 * Initialise click listeners on all sidebar nav items.
 */
export function initRouter() {
  document.querySelectorAll('.nav-item[data-page]').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      navigateTo(item.dataset.page);
    });
  });
}

/**
 * Navigate to a named page.
 * Updates the active nav highlight and fires a 'pagechange' event.
 * @param {string} page - the data-page value to navigate to
 */
export function navigateTo(page) {
  currentPage = page;

  // Update active nav item
  document.querySelectorAll('.nav-item[data-page]').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
  });

  // Notify subscribers in listeners array
  listeners.forEach(fn => {
    try { fn(page); } catch (_) { /* ignore */ }
  });

  // Dispatch event for app.js to handle page rendering
  document.dispatchEvent(new CustomEvent('pagechange', { detail: { page } }));
}

/**
 * Returns the current page identifier.
 * @returns {string}
 */
export function getCurrentPage() {
  return currentPage;
}

/**
 * Subscribe to page navigation changes.
 * @param {function(string): void} fn
 * @returns {function(): void} unsubscribe
 */
export function onNavigate(fn) {
  listeners.push(fn);
  return () => {
    const idx = listeners.indexOf(fn);
    if (idx !== -1) listeners.splice(idx, 1);
  };
}
