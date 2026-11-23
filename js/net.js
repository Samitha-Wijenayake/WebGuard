/**
 * Talks to the local WebGuard server, which fetches targets outside the browser CORS sandbox.
 */

export async function proxyFetch(url, options = {}) {
  const params = new URLSearchParams({
    url,
    method: options.method || 'GET',
    timeout: String(options.timeout || 15000),
    maxBytes: String(options.maxBytes ?? 400000),
  });

  let response;
  try {
    response = await fetch(`/api/fetch?${params}`, { signal: options.signal });
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Scan cancelled');
    throw new Error('Cannot reach the WebGuard scanner service. Start it with: node server.js');
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
