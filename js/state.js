/**
 * WebGuard – State Management  (js/state.js)
 * Central pub/sub state store.
 */

/** @type {Record<string, any[]>} */
const subscribers = {};

/** @type {Record<string, any>} */
const defaultState = {
  // Current scan
  activeScan: null,       // { id, url, mode, status, progress, startedAt }
  currentScan: null,      // most recently completed scan
  scanResults: null,      // full results object for the most recent scan
  scans: [],              // list of historical scan summaries
  viewScanId: null,       // explicitly selected historical scan

  // Settings
  settings: {
    theme: 'dark',
    crawlLimit: 250,
    timeout: 10000,
    concurrency: 3,
    retentionDays: 90,
    pagesInsightsKey: '',
    nvdApiKey: '',
  },

  // UI state
  currentPage: 'overview',
  sidebarOpen: false,
  loading: false,
  error: null,
};

/** Live mutable state (deep clone of defaults) */
let state = structuredClone(defaultState);

// ─────────────────────────────────────────────────────────────

/**
 * Returns a shallow copy of the current state.
 * @returns {Record<string, any>}
 */
export function getState() {
  return { ...state };
}

/**
 * Merges partial state into the store and notifies subscribers.
 * @param {Record<string, any>} partial
 */
export function setState(partial) {
  const prev = { ...state };
  state = { ...state, ...partial };

  const changedKeys = Object.keys(partial);

  // Notify key-specific subscribers
  changedKeys.forEach(key => {
    if (subscribers[key]) {
      subscribers[key].forEach(fn => {
        try { fn(state[key], prev[key]); } catch (err) {
          console.error('[state] subscriber error for key', key, err);
        }
      });
    }
  });

  // Notify wildcard subscribers
  if (subscribers['*']) {
    subscribers['*'].forEach(fn => {
      try { fn(state, prev, changedKeys); } catch (err) {
        console.error('[state] wildcard subscriber error', err);
      }
    });
  }

  // Dispatch DOM event so non-module code can react
  document.dispatchEvent(
    new CustomEvent('statechange', {
      detail: { state: { ...state }, changedKeys },
    })
  );
}

/**
 * Subscribe to changes on a specific state key (or '*' for any change).
 * @param {string} key
 * @param {function} fn  - called with (newValue, oldValue) or (newState, prevState, changedKeys) for '*'
 * @returns {function(): void} unsubscribe
 */
export function subscribe(key, fn) {
  if (!subscribers[key]) subscribers[key] = [];
  subscribers[key].push(fn);

  return function unsubscribe() {
    const idx = subscribers[key].indexOf(fn);
    if (idx !== -1) subscribers[key].splice(idx, 1);
  };
}

/**
 * Resets the entire state back to defaults.
 * Useful for testing or a full app reset.
 */
export function resetState() {
  state = structuredClone(defaultState);

  // Notify all subscribers of the reset
  Object.keys(subscribers).forEach(key => {
    subscribers[key].forEach(fn => {
      try { fn(state[key], undefined); } catch (_) { /* ignore */ }
    });
  });

  document.dispatchEvent(
    new CustomEvent('statechange', {
      detail: { state: { ...state }, changedKeys: Object.keys(state), reset: true },
    })
  );
}
