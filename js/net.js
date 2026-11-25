/**
 * Talks to the WebGuard server (local or deployed on Render), which fetches targets
 * outside the browser CORS sandbox.
 */
import { API_BASE } from './config.js';

export async function proxyFetch(url, options = {}) {
  const params = new URLSearchParams({
    url,
    method: options.method || 'GET',
    timeout: String(options.timeout || 15000),
    maxBytes: String(options.maxBytes ?? 400000),
  });

  let response;
  try {
    response = await fetch(`${API_BASE}/api/fetch?${params}`, { signal: options.signal });
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Scan cancelled');
    throw new Error(API_BASE
      ? `Cannot reach the WebGuard scanner service at ${API_BASE}. It may be starting up — try again in a moment.`
      : 'Cannot reach the WebGuard scanner service. Start it with: node server.js');
  }

  const data = await response.json().catch(() => null);
  if (!response.ok || !data || data.error) {
    const message = data?.error || 'The scanner service could not fetch this target.';
    if (response.status === 404 && !data) {
      throw new Error('WebGuard is not being served by its scanner. Start it with: node server.js');
    }
    throw new Error(message);
  }
  return data;
}
