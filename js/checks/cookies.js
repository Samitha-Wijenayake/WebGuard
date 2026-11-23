/**
 * Cookie Security Check
 * Inspects accessible cookies for security attributes.
 * Explains limitations: HttpOnly cookies are invisible to JS by design.
 */

function parseCookieString(cookieStr) {
  return cookieStr.split(';').map(pair => {
    const [name, ...rest] = pair.trim().split('=');
    return { name: name?.trim(), value: rest.join('=').trim() };
  }).filter(c => c.name);
}

function parseSetCookieHeader(header) {
  const parts = header.split(';').map(s => s.trim());
  const [nameValue, ...attrs] = parts;
  const [name, ...valParts] = nameValue.split('=');
  const cookie = {
    name: name?.trim(),
    value: valParts.join('=').trim(),
    secure: false,
    httpOnly: false,
    sameSite: null,
    path: null,
    domain: null,
    expires: null
  };
  for (const attr of attrs) {
    const lower = attr.toLowerCase();
    if (lower === 'secure') cookie.secure = true;
    else if (lower === 'httponly') cookie.httpOnly = true;
    else if (lower.startsWith('samesite=')) cookie.sameSite = attr.split('=')[1]?.trim();
    else if (lower.startsWith('path=')) cookie.path = attr.split('=')[1]?.trim();
    else if (lower.startsWith('domain=')) cookie.domain = attr.split('=')[1]?.trim();
    else if (lower.startsWith('expires=')) cookie.expires = attr.split('=').slice(1).join('=').trim();
    else if (lower.startsWith('max-age=')) cookie.maxAge = parseInt(attr.split('=')[1], 10);
  }
  return cookie;
}

function maskCookieValue(value) {
  if (!value || value.length <= 4) return '****';
  return value.substring(0, 4) + '*'.repeat(Math.min(value.length - 4, 8));
}

function evaluateCookie(cookie, fromSetCookie = false) {
  const issues = [];
  const isSensitiveName = /(?:session|sess|auth|token|jwt|sid|id|user|pass|key|secret)/i.test(cookie.name || '');

  if (fromSetCookie) {
    if (!cookie.secure) {
      issues.push({ attr: 'Secure', severity: isSensitiveName ? 'high' : 'medium', desc: 'Missing Secure flag – cookie sent over HTTP' });
    }
    if (!cookie.httpOnly) {
      issues.push({ attr: 'HttpOnly', severity: isSensitiveName ? 'high' : 'medium', desc: 'Missing HttpOnly flag – accessible to JavaScript (XSS risk)' });
    }
    if (!cookie.sameSite) {
      issues.push({ attr: 'SameSite', severity: 'medium', desc: 'Missing SameSite attribute – vulnerable to CSRF' });
    } else if (cookie.sameSite.toLowerCase() === 'none' && !cookie.secure) {
      issues.push({ attr: 'SameSite=None without Secure', severity: 'high', desc: 'SameSite=None requires Secure flag' });
    }
  }
  return issues;
}

export async function check(url, fetchedData) {
  const { headers: fetchedHeaders, cookies: passedCookies } = fetchedData || {};
  const findings = [];

  // Normalize headers
  const headers = {};
  if (fetchedHeaders && typeof fetchedHeaders === 'object') {
    for (const [k, v] of Object.entries(fetchedHeaders)) {
      headers[k.toLowerCase()] = v;
    }
  }

  let setCookieHeaders = [];
  if (headers['set-cookie']) {
    const raw = headers['set-cookie'];
    setCookieHeaders = Array.isArray(raw) ? raw : [raw];
  }

  // Try document.cookie (only works same-origin, will be empty for cross-origin)
  let documentCookies = [];
  try {
    if (typeof document !== 'undefined' && document.cookie) {
      documentCookies = parseCookieString(document.cookie);
    }
  } catch (_) {}

  const hasSetCookie = setCookieHeaders.length > 0;
  const hasDocCookies = documentCookies.length > 0;
  const hasPassedCookies = passedCookies && passedCookies.length > 0;

  // Always explain HttpOnly limitation
  findings.push({
    title: 'HttpOnly cookies not visible to JavaScript',
    severity: 'info',
    status: 'info',
    evidence: 'document.cookie only returns cookies WITHOUT the HttpOnly flag. HttpOnly cookies are intentionally hidden from JavaScript for security. The absence of cookies here does NOT mean no HttpOnly cookies exist.',
    impact: 'This is expected browser security behavior, not a vulnerability.',
    remediation: 'Inspect Set-Cookie headers server-side or via browser DevTools (Application > Cookies) to see all cookies.',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies'],
    confidence: 'confirmed'
  });

  // Evaluate Set-Cookie headers if accessible
  if (hasSetCookie) {
    for (const rawHeader of setCookieHeaders) {
      const cookie = parseSetCookieHeader(rawHeader);
      const issues = evaluateCookie(cookie, true);
      const maskedValue = maskCookieValue(cookie.value);

      if (issues.length === 0) {
        findings.push({
          title: `Cookie "${cookie.name}" has secure attributes`,
          severity: 'info',
          status: 'passed',
          evidence: `Set-Cookie: ${cookie.name}=${maskedValue}; Secure=${cookie.secure}; HttpOnly=${cookie.httpOnly}; SameSite=${cookie.sameSite || 'not set'}`,
          impact: 'Cookie is properly secured.',
          remediation: 'No action required.',
          references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies'],
          confidence: 'confirmed'
        });
      } else {
        const maxSeverity = issues.reduce((m, i) => {
          const o = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
          return o[i.severity] > o[m] ? i.severity : m;
        }, 'info');
        findings.push({
          title: `Cookie "${cookie.name}" is missing security attributes`,
          severity: maxSeverity,
          status: 'failed',
          evidence: `Set-Cookie: ${cookie.name}=${maskedValue}\nIssues:\n${issues.map(i => `- [${i.attr}] ${i.desc}`).join('\n')}`,
          impact: 'Missing security attributes expose the cookie to theft via XSS, network interception, or CSRF.',
          remediation: `Set the following flags on cookie "${cookie.name}": ${issues.map(i => i.attr).join(', ')}`,
          references: [
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies',
            'https://owasp.org/www-community/controls/SecureCookieAttribute'
          ],
          confidence: 'confirmed'
        });
      }
    }
  }

  // Evaluate document.cookie entries
  if (hasDocCookies) {
    findings.push({
      title: `${documentCookies.length} cookie(s) visible via document.cookie (non-HttpOnly)`,
      severity: documentCookies.length > 0 ? 'warning' : 'info',
      status: documentCookies.length > 0 ? 'warning' : 'info',
      evidence: `Cookies: ${documentCookies.map(c => c.name).join(', ')}`,
      impact: 'Cookies visible to JavaScript could be stolen if XSS is present on the page.',
      remediation: 'Review these cookies; if they are session or auth cookies, add the HttpOnly flag.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies'],
      confidence: 'confirmed'
    });
  }

  // Evaluate passed cookies from the scanner context
  if (hasPassedCookies) {
    for (const cookie of passedCookies) {
      const issues = evaluateCookie(cookie, true);
      if (issues.length > 0) {
        findings.push({
          title: `Cookie "${cookie.name}" security issues`,
          severity: issues[0].severity,
          status: 'warning',
          evidence: issues.map(i => `- [${i.attr}] ${i.desc}`).join('\n'),
          impact: 'Insecure cookie attributes increase attack surface.',
          remediation: `Add missing flags to cookie "${cookie.name}": ${issues.map(i => i.attr).join(', ')}`,
          references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies'],
          confidence: 'confirmed'
        });
      }
    }
  }

  // If nothing testable at all
  if (!hasSetCookie && !hasDocCookies && !hasPassedCookies) {
    findings.push({
      title: 'No cookie data accessible for analysis',
      severity: 'info',
      status: 'not-testable',
      evidence: 'Set-Cookie headers were not accessible (CORS) and no cookies were present in document.cookie (likely cross-origin context or no cookies set).',
      impact: 'Cannot evaluate cookie security attributes.',
      remediation: 'Use browser DevTools (Application > Cookies) or a server-side tool to inspect all cookies and their flags.',
      references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies',
        'https://owasp.org/www-community/controls/SecureCookieAttribute'
      ],
      confidence: 'confirmed'
    });
  }

  const failed = findings.filter(f => f.status === 'failed');
  const warnings = findings.filter(f => f.status === 'warning');
  const overallStatus = !hasSetCookie && !hasDocCookies && !hasPassedCookies
    ? 'not-testable'
    : failed.length > 0 ? 'failed' : warnings.length > 0 ? 'warning' : 'passed';

  const score = overallStatus === 'not-testable' ? 0
    : overallStatus === 'passed' ? 8
    : overallStatus === 'warning' ? 5
    : Math.max(0, 8 - failed.length * 2);

  return {
    id: 'cookies',
    name: 'Cookie Security',
    category: 'Session Management',
    description: 'Checks cookie security attributes (Secure, HttpOnly, SameSite) using Set-Cookie headers and document.cookie, with clear limitations explained.',
    status: overallStatus,
    severity: failed.length > 0 ? 'high' : warnings.length > 0 ? 'medium' : 'info',
    score,
    findings,
    summary: overallStatus === 'not-testable'
      ? 'Cookie data not accessible from browser context. Use DevTools for inspection.'
      : `Found ${setCookieHeaders.length} Set-Cookie header(s) and ${documentCookies.length} document.cookie entry(s). ${failed.length} issue(s) detected.`,
    details: 'Cookie security analysis is severely limited from a browser-based scanner. HttpOnly cookies are invisible to JavaScript by design. Set-Cookie headers are only readable if the server sends CORS headers permitting it. For complete cookie auditing, use server-side tools or browser DevTools.',
    testable: hasSetCookie || hasDocCookies || hasPassedCookies,
    limitation: 'HttpOnly cookies are invisible to JavaScript (by design). Set-Cookie headers require CORS access. document.cookie only works for same-origin cookies.'
  };
}
