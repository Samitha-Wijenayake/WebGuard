/**
 * WebGuard – Storage Layer  (js/storage.js)
 * IndexedDB for scans/reports + localStorage for settings.
 * Falls back to in-memory when IndexedDB is unavailable.
 */

const DB_NAME    = 'WebGuardDB';
const DB_VERSION = 1;
const SETTINGS_KEY = 'webguard_settings';

// ─── Default Settings ─────────────────────────────────────────
const DEFAULT_SETTINGS = {
  theme: 'dark',
  crawlLimit: 100,
  settingsVersion: 2,
  timeout: 10000,
  concurrency: 3,
  retentionDays: 90,
  pagesInsightsKey: '',
  nvdApiKey: '',
};

// ─── In-memory fallback ───────────────────────────────────────
const memStore = {
  scans: new Map(),
  reports: new Map(),
};
let useMemFallback = false;

/** @type {IDBDatabase|null} */
let db = null;

// ─── Helpers ─────────────────────────────────────────────────

/**
 * Wraps an IDBRequest in a Promise.
 * @template T
 * @param {IDBRequest<T>} request
 * @returns {Promise<T>}
 */
function promisifyRequest(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror   = () => reject(request.error);
  });
}

/**
 * Returns the named object store in readwrite or readonly mode.
 * @param {string} storeName
 * @param {'readwrite'|'readonly'} mode
 * @returns {IDBObjectStore}
 */
function getStore(storeName, mode = 'readonly') {
  const tx = db.transaction(storeName, mode);
  return tx.objectStore(storeName);
}

// ─── Initialisation ───────────────────────────────────────────

/**
 * Opens / upgrades the IndexedDB database.
 * Falls back to in-memory on failure.
 * @returns {Promise<void>}
 */
export async function initStorage() {
  if (typeof indexedDB === 'undefined') {
    console.warn('[storage] IndexedDB not available – using in-memory fallback.');
    useMemFallback = true;
    purgeOldScans(loadSettings().retentionDays).catch(() => {});
    return;
  }

  return new Promise((resolve) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = (event) => {
      /** @type {IDBDatabase} */
      const idb = event.target.result;

      if (!idb.objectStoreNames.contains('scans')) {
        const scanStore = idb.createObjectStore('scans', { keyPath: 'id' });
        scanStore.createIndex('by_created', 'createdAt', { unique: false });
        scanStore.createIndex('by_url', 'url', { unique: false });
      }

      if (!idb.objectStoreNames.contains('reports')) {
        const reportStore = idb.createObjectStore('reports', { keyPath: 'id' });
        reportStore.createIndex('by_scan', 'scanId', { unique: false });
        reportStore.createIndex('by_created', 'createdAt', { unique: false });
      }
    };

    req.onsuccess = (event) => {
      db = event.target.result;

      db.onerror = (e) => {
        console.error('[storage] Database error:', e.target.error);
      };

      purgeOldScans(loadSettings().retentionDays).catch((error) => console.warn('[storage] Retention cleanup failed:', error));
      resolve();
    };

    req.onerror = () => {
      console.warn('[storage] Failed to open IndexedDB – using in-memory fallback.', req.error);
      useMemFallback = true;
      resolve();
    };

    req.onblocked = () => {
      console.warn('[storage] IndexedDB open blocked (another tab may need to be closed).');
    };
  });
}

// ─── Scans CRUD ───────────────────────────────────────────────

/**
 * Saves a scan record (insert or update).
 * @param {Object} scan - must have an `id` string property
 * @returns {Promise<void>}
 */
export async function saveScan(scan) {
  if (!scan || !scan.id) throw new Error('scan.id is required');

  if (useMemFallback) {
    memStore.scans.set(scan.id, { ...scan });
    return;
  }

  const store = getStore('scans', 'readwrite');
  await promisifyRequest(store.put(scan));
}

/**
 * Retrieves a scan by id.
 * @param {string} id
 * @returns {Promise<Object|undefined>}
 */
export async function getScan(id) {
  if (useMemFallback) return memStore.scans.get(id);
  const store = getStore('scans', 'readonly');
  return promisifyRequest(store.get(id));
}

/**
 * Returns all scans, sorted newest first.
 * @returns {Promise<Object[]>}
 */
export async function getAllScans() {
  if (useMemFallback) {
    return [...memStore.scans.values()].sort(
      (a, b) => new Date(b.startTime || b.createdAt) - new Date(a.startTime || a.createdAt)
    );
  }

  const store = getStore('scans', 'readonly');
  const all = await promisifyRequest(store.getAll());
  return all.sort((a, b) => new Date(b.startTime || b.createdAt) - new Date(a.startTime || a.createdAt));
}

/**
 * Deletes a scan by id.
 * @param {string} id
 * @returns {Promise<void>}
 */
export async function deleteScan(id) {
  if (useMemFallback) { memStore.scans.delete(id); return; }
  const store = getStore('scans', 'readwrite');
  await promisifyRequest(store.delete(id));
}

/**
 * Deletes scans older than retentionDays.
 * @param {number} retentionDays
 * @returns {Promise<number>} number of records deleted
 */
export async function purgeOldScans(retentionDays = 90) {
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  const all = await getAllScans();
  let count = 0;

  for (const scan of all) {
    if (new Date(scan.startTime || scan.createdAt).getTime() < cutoff) {
      await deleteScan(scan.id);
      count++;
    }
  }

  return count;
}

// ─── Reports CRUD ─────────────────────────────────────────────

/**
 * Saves a report record (insert or update).
 * @param {Object} report - must have an `id` string property
 * @returns {Promise<void>}
 */
export async function saveReport(report) {
  if (!report || !report.id) throw new Error('report.id is required');

  if (useMemFallback) {
    memStore.reports.set(report.id, { ...report });
    return;
  }

  const store = getStore('reports', 'readwrite');
  await promisifyRequest(store.put(report));
}

/**
 * Retrieves a report by id.
 * @param {string} id
 * @returns {Promise<Object|undefined>}
 */
export async function getReport(id) {
  if (useMemFallback) return memStore.reports.get(id);
  const store = getStore('reports', 'readonly');
  return promisifyRequest(store.get(id));
}

/**
 * Returns all reports, sorted newest first.
 * @returns {Promise<Object[]>}
 */
export async function getAllReports() {
  if (useMemFallback) {
    return [...memStore.reports.values()].sort(
      (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
    );
  }

  const store = getStore('reports', 'readonly');
  const all = await promisifyRequest(store.getAll());
  return all.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

/**
 * Returns reports for a given scan id.
 * @param {string} scanId
 * @returns {Promise<Object[]>}
 */
export async function getReportsByScan(scanId) {
  const all = await getAllReports();
  return all.filter(r => r.scanId === scanId);
}

/**
 * Deletes a report by id.
 * @param {string} id
 * @returns {Promise<void>}
 */
export async function deleteReport(id) {
  if (useMemFallback) { memStore.reports.delete(id); return; }
  const store = getStore('reports', 'readwrite');
  await promisifyRequest(store.delete(id));
}

// ─── Settings ─────────────────────────────────────────────────

/**
 * Loads settings from localStorage, merged with defaults.
 * @returns {Object}
 */
export function loadSettings() {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const parsed = JSON.parse(raw);
    // v2: the default crawl limit moved from 250 to 100 pages. Settings saved before
    // that still carry the old default, so migrate it unless the user changed it.
    if (!parsed.settingsVersion) {
      if (Number(parsed.crawlLimit) === 250) parsed.crawlLimit = DEFAULT_SETTINGS.crawlLimit;
      parsed.settingsVersion = DEFAULT_SETTINGS.settingsVersion;
    }
    return { ...DEFAULT_SETTINGS, ...parsed };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

/**
 * Persists settings to localStorage.
 * @param {Object} settings
 */
export function saveSettings(settings) {
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
  } catch (err) {
    console.error('[storage] Failed to save settings:', err);
  }
}

/**
 * Removes all settings from localStorage (restores defaults on next load).
 */
export function clearSettings() {
  try {
    localStorage.removeItem(SETTINGS_KEY);
  } catch (_) { /* ignore */ }
}

// ─── Export ───────────────────────────────────────────────────

/**
 * Bundles all data into an export payload.
 * @returns {Promise<{ scans: Object[], reports: Object[], settings: Object, exportedAt: string }>}
 */
export async function exportData() {
  const [scans, reports] = await Promise.all([getAllScans(), getAllReports()]);
  const settings = loadSettings();

  return {
    scans,
    reports,
    settings,
    exportedAt: new Date().toISOString(),
  };
}

/**
 * Clears all stored data (scans, reports, settings).
 * @returns {Promise<void>}
 */
export async function clearAllData() {
  clearSettings();

  if (useMemFallback) {
    memStore.scans.clear();
    memStore.reports.clear();
    return;
  }

  await Promise.all([
    promisifyRequest(getStore('scans',   'readwrite').clear()),
    promisifyRequest(getStore('reports', 'readwrite').clear()),
  ]);
}
