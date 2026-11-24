import { proxyFetch } from '../net.js';

const TRACKERS = [
  ['google-analytics.com', 'Google Analytics'],
  ['googletagmanager.com', 'Google Tag Manager'],
  ['doubleclick.net', 'DoubleClick'],
  ['facebook.net', 'Facebook'],
  ['facebook.com', 'Facebook'],
  ['hotjar.com', 'Hotjar'],
  ['segment.com', 'Segment'],
  ['mixpanel.com', 'Mixpanel'],
  ['clarity.ms', 'Microsoft Clarity'],
  ['adservice.google', 'Google Ads'],
];

const LIBRARIES = [
  [/jquery[.-]?(\d+\.\d+\.\d+)?/i, 'jQuery'],
  [/react(?:\.production|\.development)?(?:\.min)?\.js/i, 'React'],
  [/vue(?:\.min)?\.js/i, 'Vue'],
  [/angular(?:\.min)?\.js/i, 'AngularJS'],
  [/bootstrap(?:\.min)?\.(?:js|css)/i, 'Bootstrap'],
  [/lodash(?:\.min)?\.js/i, 'Lodash'],
];

function finding(partial) {
  return {
    severity: 'info',
    status: 'info',
    evidence: '',
    impact: '',
    remediation: '',
    references: [],
    confidence: 'confirmed',
    ...partial,
  };
}

function parseDocument(html) {
  if (!html || typeof DOMParser === 'undefined') return null;
  return new DOMParser().parseFromString(html, 'text/html');
}

function cookieFindings(headerValue, isHttps) {
  const raw = String(headerValue || '').trim();
  if (!raw) {
    return [finding({
      title: 'No cookies set on the landing response',
      status: 'passed',
      evidence: 'The landing response did not include a Set-Cookie header.',
      impact: 'There are no session cookies to assess on this response.',
      remediation: 'No action required for this response.',
    })];
  }
  return raw.split('\n').filter(Boolean).map((cookie) => {
    const name = cookie.split('=')[0].trim();
    const attrs = cookie.split(';').slice(1).map(part => part.trim().toLowerCase());
    const has = (flag) => attrs.some(attr => attr === flag || attr.startsWith(`${flag}=`));
    const gaps = [];
    if (!has('httponly')) gaps.push('HttpOnly');
    if (isHttps && !has('secure')) gaps.push('Secure');
    if (!has('samesite')) gaps.push('SameSite');
    return finding({
      title: gaps.length ? `Cookie ${name} is missing ${gaps.join(', ')}` : `Cookie ${name} has the expected flags`,
      severity: gaps.includes('HttpOnly') || gaps.includes('Secure') ? 'medium' : 'info',
      status: gaps.length ? 'warning' : 'passed',
      evidence: cookie.slice(0, 300),
      impact: gaps.length
        ? 'Missing cookie flags make session cookies easier to steal or send from another site.'
        : 'The cookie includes the flags checked by this assessment.',
      remediation: gaps.length
        ? `Set ${gaps.join(', ')} on this cookie. Prefer SameSite=Lax or Strict.`
        : 'No action required.',
    });
  });
}

export async function analyze(url, fetchedData, options = {}) {
  const finalUrl = fetchedData.finalUrl || url;
  const isHttps = finalUrl.startsWith('https://');
  const headers = fetchedData.headers || {};
  const doc = parseDocument(fetchedData.text || '');
  const pageUrl = new URL(finalUrl);
  const resources = [];
  const forms = [];
  let title = '';
  let description = '';
  let viewport = false;
  let h1 = 0;
  let images = 0;
  let imagesMissingAlt = 0;

  if (doc) {
    title = doc.querySelector('title')?.textContent?.trim() || '';
    description = doc.querySelector('meta[name="description"]')?.getAttribute('content') || '';
    viewport = !!doc.querySelector('meta[name="viewport"]');
    h1 = doc.querySelectorAll('h1').length;
    doc.querySelectorAll('img').forEach((img) => {
      images += 1;
      if (!img.getAttribute('alt') && img.getAttribute('alt') !== '') imagesMissingAlt += 1;
    });
    doc.querySelectorAll('script[src], link[href], img[src], iframe[src], form[action]').forEach((el) => {
      const raw = el.getAttribute('src') || el.getAttribute('href') || el.getAttribute('action') || '';
      try { resources.push({ url: new URL(raw, finalUrl).href, tag: el.tagName.toLowerCase(), integrity: el.getAttribute('integrity') || '' }); } catch { /* ignore bad urls */ }
    });
    doc.querySelectorAll('form').forEach((form) => {
      const fields = [...form.querySelectorAll('input, textarea, select')].map(field => field.getAttribute('type') || field.tagName.toLowerCase());
      forms.push({
        action: form.getAttribute('action') || finalUrl,
        method: (form.getAttribute('method') || 'get').toLowerCase(),
        fields,
      });
    });
  }

  const external = [...new Set(resources.map(item => {
    try { return new URL(item.url).hostname; } catch { return ''; }
  }).filter(host => host && host !== pageUrl.hostname))];

  const trackers = TRACKERS.filter(([domain]) => external.some(host => host.includes(domain)) || (fetchedData.text || '').includes(domain))
    .map(([, name]) => name)
    .filter((name, index, list) => list.indexOf(name) === index);

  const libraries = [];
  resources.filter(item => item.tag === 'script').forEach((item) => {
    for (const [pattern, name] of LIBRARIES) {
      const match = item.url.match(pattern);
      if (match) libraries.push({ name, version: match[1] || 'unknown', url: item.url });
    }
  });
  const serverHeader = headers.server || '';
  const poweredBy = headers['x-powered-by'] || '';
  const generator = doc?.querySelector('meta[name="generator"]')?.getAttribute('content') || '';
  const technologies = [serverHeader, poweredBy, generator].map(item => item.trim()).filter(Boolean);

  const mixed = isHttps ? resources.filter(item => item.url.startsWith('http://')) : [];
  const externalScripts = resources.filter(item => item.tag === 'script' && (() => { try { return new URL(item.url).origin !== pageUrl.origin; } catch { return false; } })());
  const missingSri = externalScripts.filter(item => !item.integrity);

  // Site-level resources are fetched once per scan (on the landing page) rather than for every page.
  const siteLevel = options.siteLevel !== false;
  let robots = null;
  let securityTxt = null;
  if (siteLevel) {
    try {
      robots = await proxyFetch(new URL('/robots.txt', pageUrl.origin).href, { method: 'GET', timeout: options.timeout, signal: options.signal, maxBytes: 80000 });
    } catch { robots = null; }
    try {
      securityTxt = await proxyFetch(new URL('/.well-known/security.txt', pageUrl.origin).href, { method: 'GET', timeout: options.timeout, signal: options.signal, maxBytes: 80000 });
    } catch { securityTxt = null; }
  }

  const checks = [
    checkResult('cookies', 'Cookie Security', 'Session Security', cookieFindings(headers['set-cookie'], isHttps)),
    checkResult('cors', 'CORS Headers', 'Browser Security', corsFindings(headers)),
    checkResult('forms', 'Forms and Input', 'Application Security', formFindings(forms)),
    checkResult('mixed-content', 'Mixed Content', 'Transport Security', mixedFindings(mixed, isHttps)),
    checkResult('libraries', 'JavaScript Libraries', 'Vulnerability Intelligence', libraryFindings(libraries)),
    checkResult('technology', 'Technology Signals', 'Attack Surface', technologyFindings(technologies)),
    ...(siteLevel ? [checkResult('security-txt', 'security.txt', 'Disclosure', securityTxtFindings(securityTxt))] : []),
    checkResult('redirects', 'Redirect Behaviour', 'Transport Security', redirectFindings(fetchedData.redirectChain || [], isHttps)),
    checkResult('cache-security', 'Cache Headers', 'HTTP Security Headers', cacheFindings(headers)),
    checkResult('sri', 'Subresource Integrity', 'Application Security', sriFindings(externalScripts, missingSri)),
    ...(siteLevel ? [checkResult('robots-sitemap', 'Robots and Sitemap', 'Attack Surface', robotsFindings(robots))] : []),
    checkResult('privacy-trackers', 'Privacy and Trackers', 'Privacy', trackerFindings(trackers, external)),
  ];

  return {
    checks,
    attackSurface: {
      domain: pageUrl.hostname,
      ip: '',
      server: serverHeader,
      externalDomains: external.slice(0, 40),
      subdomains: [],
      technologies,
      externalScripts: externalScripts.map(item => item.url),
      endpoints: resources.slice(0, 40).map(item => item.url),
    },
    quality: { title, description, viewport, h1, images, imagesMissingAlt },
    privacy: { trackers, externalDomains: external.slice(0, 40), cookieHeader: headers['set-cookie'] || '' },
    vulnIntel: { libraries, cves: [] },
    forms,
  };
}

function checkResult(id, name, category, findings) {
  const list = findings.length ? findings : [finding({ title: `${name} completed`, status: 'passed', evidence: 'No issues were recorded.', impact: 'No issue was identified by this check.', remediation: 'No action required.' })];
  const rank = { failed: 3, warning: 2, passed: 0, info: 0, 'not-testable': 0 };
  const status = list.some(item => item.status === 'failed') ? 'failed' : list.some(item => item.status === 'warning') ? 'warning' : 'passed';
  void rank;
  return {
    id,
    name,
    category,
    status,
    severity: status === 'failed' ? 'high' : status === 'warning' ? 'medium' : 'info',
    score: status === 'passed' ? 8 : status === 'warning' ? 5 : 2,
    testable: true,
    findings: list,
    summary: list[0].title,
    limitation: '',
  };
}

function corsFindings(headers) {
  const value = headers['access-control-allow-origin'];
  if (!value) {
    return [finding({
      title: 'No cross-origin read policy on the landing page',
      status: 'passed',
      evidence: 'Access-Control-Allow-Origin was not present on the landing response.',
      impact: 'Other websites cannot read this response from browser JavaScript.',
      remediation: 'Keep CORS disabled unless a specific origin needs access.',
    })];
  }
  const wildcard = value.trim() === '*';
  return [finding({
    title: wildcard ? 'CORS allows any origin' : `CORS allows ${value}`,
    severity: wildcard ? 'medium' : 'info',
    status: wildcard ? 'warning' : 'info',
    evidence: `Access-Control-Allow-Origin: ${value}`,
    impact: wildcard
      ? 'Any website can read this response if the browser exposes it.'
      : 'A specific origin is allowed to read this response.',
    remediation: wildcard
      ? 'Replace * with an explicit allow-list of trusted origins, and do not combine * with credentials.'
      : 'Confirm this origin is intended to read the response.',
  })];
}

function formFindings(forms) {
  if (!forms.length) {
    return [finding({ title: 'No forms on the landing page', status: 'passed', evidence: 'The landing HTML contains no form elements.', impact: 'There is no form on this page to submit or inspect.', remediation: 'No action required.' })];
  }
  return forms.slice(0, 12).map((form, index) => {
    const hasPassword = form.fields.some(field => field === 'password');
    const insecure = hasPassword && form.method === 'get';
    return finding({
      title: insecure ? `Form ${index + 1} sends a password with GET` : `Form ${index + 1} uses ${form.method.toUpperCase()}`,
      severity: insecure ? 'high' : 'info',
      status: insecure ? 'failed' : 'passed',
      evidence: `method=${form.method} action=${form.action} fields=${form.fields.join(', ') || 'none'}`,
      impact: insecure ? 'GET places passwords in the URL, history, and logs.' : 'The form was inspected only. It was not submitted.',
      remediation: insecure ? 'Submit credentials with POST over HTTPS and do not place secrets in query strings.' : 'Keep credential forms on HTTPS and use POST.',
    });
  });
}

function mixedFindings(mixed, isHttps) {
  if (!isHttps) {
    return [finding({ title: 'Mixed content does not apply to HTTP pages', status: 'info', evidence: 'The page itself is HTTP.', impact: 'The whole page is unencrypted.', remediation: 'Serve the site over HTTPS.' })];
  }
  if (!mixed.length) {
    return [finding({ title: 'No HTTP subresources in the landing HTML', status: 'passed', evidence: 'Script, style, image, and frame URLs in the landing HTML use HTTPS or relative paths.', impact: 'This page does not pull active or passive content over HTTP from the HTML that was inspected.', remediation: 'No action required.' })];
  }
  return [finding({
    title: `${mixed.length} HTTP subresource${mixed.length === 1 ? '' : 's'} on an HTTPS page`,
    severity: 'medium',
    status: 'warning',
    evidence: mixed.slice(0, 8).map(item => item.url).join('\n'),
    impact: 'Browsers may block or expose these resources, and HTTP content can be modified in transit.',
    remediation: 'Load every script, style, image, and frame over HTTPS.',
  })];
}

function libraryFindings(libraries) {
  if (!libraries.length) {
    return [finding({ title: 'No common library filename detected', status: 'info', evidence: 'Script URLs did not match the built-in library patterns.', impact: 'No version-based conclusion is drawn.', remediation: 'Review dependencies in your own package manifest.' })];
  }
  return libraries.map(lib => finding({
    title: `${lib.name} referenced (${lib.version})`,
    status: 'info',
    evidence: lib.url,
    impact: 'Known library names help you check for published vulnerabilities.',
    remediation: 'Compare this version with the vendor advisory and upgrade unsupported releases.',
  }));
}

function technologyFindings(technologies) {
  if (!technologies.length) {
    return [finding({ title: 'No server or generator banner disclosed', status: 'passed', evidence: 'Server, X-Powered-By, and generator metadata were absent.', impact: 'The landing response does not advertise the stack in those fields.', remediation: 'Keep product banners disabled on public responses.' })];
  }
  return [finding({
    title: 'Technology banner disclosed',
    severity: 'low',
    status: 'warning',
    evidence: technologies.join('\n'),
    impact: 'Version banners make it easier to match the site to published vulnerabilities.',
    remediation: 'Remove or genericise Server and X-Powered-By on public responses.',
  })];
}

function securityTxtFindings(result) {
  const ok = result && result.status === 200 && /contact:/i.test(result.body || '');
  return [finding({
    title: ok ? 'security.txt is published' : 'security.txt was not found',
    severity: ok ? 'info' : 'low',
    status: ok ? 'passed' : 'warning',
    evidence: result ? `HTTP ${result.status} ${result.finalUrl}` : 'The request did not complete.',
    impact: ok ? 'Researchers have a documented contact path.' : 'There is no machine-readable contact for security reports.',
    remediation: ok ? 'Keep the expiry and contact fields current.' : 'Publish /.well-known/security.txt with a Contact and Expires field.',
    references: ['https://securitytxt.org/'],
  })];
}

function redirectFindings(chain, isHttps) {
  const hops = chain.filter(Boolean);
  const insecure = hops.some(hop => hop.startsWith('http://'));
  if (hops.length <= 1) {
    return [finding({ title: 'Landing URL did not redirect', status: 'passed', evidence: hops[0] || '', impact: 'The requested URL was the final URL.', remediation: 'No action required.' })];
  }
  return [finding({
    title: insecure ? 'Redirect chain includes HTTP' : `Redirect chain has ${hops.length - 1} hop(s)`,
    severity: insecure && isHttps ? 'medium' : 'info',
    status: insecure ? 'warning' : 'passed',
    evidence: hops.join(' → '),
    impact: insecure ? 'An HTTP hop can be intercepted before the browser reaches HTTPS.' : 'The redirect chain stayed on HTTPS.',
    remediation: insecure ? 'Redirect HTTP directly to the final HTTPS URL.' : 'Keep redirect chains short.',
  })];
}

function cacheFindings(headers) {
  const cache = headers['cache-control'] || '';
  const sensitive = /no-store|private/i.test(cache);
  if (!cache) {
    return [finding({ title: 'Cache-Control is not set', severity: 'low', status: 'warning', evidence: 'No Cache-Control header on the landing response.', impact: 'Shared caches may store the page longer than you intend.', remediation: 'Set Cache-Control. Use no-store on personalised responses.' })];
  }
  return [finding({
    title: sensitive ? 'Cache-Control restricts shared caching' : 'Cache-Control is present',
    status: 'passed',
    evidence: `Cache-Control: ${cache}`,
    impact: 'The response tells caches how it may be stored.',
    remediation: 'Use no-store for authenticated or personalised responses.',
  })];
}

function sriFindings(externalScripts, missingSri) {
  if (!externalScripts.length) {
    return [finding({ title: 'No external scripts on the landing page', status: 'passed', evidence: 'All scripts are inline or same-origin.', impact: 'There is no third-party script URL that needs an integrity hash.', remediation: 'No action required.' })];
  }
  if (!missingSri.length) {
    return [finding({ title: 'External scripts include integrity hashes', status: 'passed', evidence: `${externalScripts.length} external script(s) declare integrity.`, impact: 'The browser can reject a script whose bytes do not match the hash.', remediation: 'Update the hash when the script file changes.' })];
  }
  return [finding({
    title: `${missingSri.length} external script(s) have no integrity hash`,
    severity: 'low',
    status: 'warning',
    evidence: missingSri.slice(0, 8).map(item => item.url).join('\n'),
    impact: 'A compromised third-party host can change the script without the page noticing.',
    remediation: 'Add a Subresource Integrity hash, or host a pinned copy yourself.',
  })];
}

function robotsFindings(result) {
  if (!result || result.status !== 200) {
    return [finding({ title: 'robots.txt was not available', status: 'info', severity: 'info', evidence: result ? `HTTP ${result.status}` : 'Request failed', impact: 'Crawlers receive no site-specific rules.', remediation: 'Publish robots.txt if you need to direct crawlers. Do not rely on it to hide sensitive URLs.' })];
  }
  const body = result.body || '';
  const sensitive = /^\s*(disallow|allow):\s*.*(admin|backup|\.git|\.env|config)/im.test(body);
  return [finding({
    title: sensitive ? 'robots.txt names sensitive paths' : 'robots.txt is published',
    severity: sensitive ? 'low' : 'info',
    status: sensitive ? 'warning' : 'passed',
    evidence: body.slice(0, 500),
    impact: sensitive ? 'Disallow entries advertise paths that are not access control.' : 'Crawler rules are public, which is expected.',
    remediation: sensitive ? 'Remove secret paths from robots.txt and protect them with authentication.' : 'Review the rules when the site structure changes.',
  })];
}

function trackerFindings(trackers, external) {
  if (!trackers.length) {
    return [finding({ title: 'No common tracker hosts in the landing HTML', status: 'passed', evidence: external.slice(0, 10).join('\n') || 'No external hosts.', impact: 'This page does not reference the tracker list built into WebGuard.', remediation: 'Review new third-party scripts before adding them.' })];
  }
  return [finding({
    title: `${trackers.length} tracker host pattern(s) found`,
    severity: 'low',
    status: 'warning',
    evidence: trackers.join(', '),
    impact: 'These services can receive visitor identifiers from the page.',
    remediation: 'Load trackers only after a recorded consent choice, and document them in your privacy notice.',
  })];
}
