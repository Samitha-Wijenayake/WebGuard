/**
 * Where the frontend sends scan requests.
 *
 * When the app is opened from the local server (node server.js), the API lives on the
 * same origin, so a relative path is used. Anywhere else (e.g. the Vercel deployment),
 * requests go to the deployed Render API.
 *
 * Set RENDER_API_URL to your Render service URL (no trailing slash).
 */
export const RENDER_API_URL = 'https://webguard-8hnb.onrender.com';

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

// Same origin when served by server.js itself (locally or on Render); otherwise the Render API.
const servedByApi = LOCAL_HOSTS.has(window.location.hostname) || window.location.origin === RENDER_API_URL;

export const API_BASE = servedByApi ? '' : RENDER_API_URL;
