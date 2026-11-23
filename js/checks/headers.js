/**
 * Security Headers Check
 * Attempts to read response headers and evaluates the presence and strength
 * of security-related HTTP headers.
 */

const HEADERS_TO_CHECK = [
  'strict-transport-security',
  'content-security-policy',
  'x-content-type-options',
  'x-frame-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
];

function evaluateHSTS(value) {
  const findings = [];
  const maxAgeMatch = value.match(/max-age=(\d+)/i);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  const hasIncludeSubDomains = /includeSubDomains/i.test(value);
  const hasPreload = /preload/i.test(value);

  if (maxAge < 31536000) {
    findings.push({
      issue: `max-age too short (${maxAge}s, recommended ≥ 31536000s / 1 year)`,
      severity: 'medium'
    });
  }
  if (!hasIncludeSubDomains) {
    findings.push({ issue: 'includeSubDomains not set – subdomains can still be accessed over HTTP', severity: 'low' });
  }
  if (!hasPreload) {
    findings.push({ issue: 'preload not set – site not eligible for browser HSTS preload list', severity: 'info' });
  }
  return findings;
}

function evaluateCSPHeader(value) {
  const issues = [];
  if (/'unsafe-inline'/.test(value)) issues.push({ issue: "'unsafe-inline' allows inline scripts/styles, undermining XSS protection", severity: 'high' });
  if (/'unsafe-eval'/.test(value)) issues.push({ issue: "'unsafe-eval' allows eval(), a common XSS vector", severity: 'high' });
  if (/script-src[^;]*\*/.test(value)) issues.push({ issue: 'Wildcard (*) in script-src allows scripts from any domain', severity: 'critical' });
  if (!/default-src/.test(value)) issues.push({ issue: 'Missing default-src – no fallback policy', severity: 'medium' });
  if (!/object-src/.test(value)) issues.push({ issue: 'Missing object-src – plugins/Flash not restricted', severity: 'medium' });
  if (!/base-uri/.test(value)) issues.push({ issue: 'Missing base-uri – base tag injection possible', severity: 'low' });
  return issues;
}

function evaluateReferrerPolicy(value) {
  const permissive = ['unsafe-url', 'no-referrer-when-downgrade', ''];
  const val = value.toLowerCase().trim();
  if (permissive.includes(val) || val === '') {
    return [{ issue: `Referrer-Policy "${value || '(empty)'}" is overly permissive – may leak full URLs`, severity: 'low' }];
  }
  return [];
}

export async function check(url, fetchedData) {
  const { headers: fetchedHeaders } = fetchedData || {};
  const findings = [];
  let score = 0;
  let headersAccessible = false;

  // Normalize fetched headers map
  const headers = {};
  if (fetchedHeaders && typeof fetchedHeaders === 'object') {
    for (const [k, v] of Object.entries(fetchedHeaders)) {
      headers[k.toLowerCase()] = v;
    }
    headersAccessible = Object.keys(headers).length > 0;
  }

  if (!headersAccessible) {
    // Attempt a fresh fetch to try to get headers (may be CORS-blocked)
    try {
      const resp = await fetch(url, {
        method: 'GET',
        mode: 'cors',
        credentials: 'omit',
        signal: AbortSignal.timeout(10000)
      });
      resp.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      headersAccessible = true;
    } catch (e) {
      // CORS blocked or network error
    }
  }

  if (!headersAccessible) {
    return {
      id: 'headers',
      name: 'Security Headers',
      category: 'HTTP Security Headers',
      description: 'Evaluates the presence and configuration of critical HTTP security headers.',
      status: 'not-testable',
      severity: 'info',
      score: 0,
      findings: [{
        title: 'Response headers not accessible (CORS)',
        severity: 'info',
        status: 'not-testable',
        evidence: 'Browser CORS policy prevented reading response headers. Cross-origin requests block header inspection unless the server sends appropriate CORS headers.',
        impact: 'Cannot evaluate security header configuration from the browser.',
        remediation: 'Use a server-side scanner, curl, or a tool like securityheaders.com for a complete header audit.',
        references: [
          'https://securityheaders.com/',
          'https://owasp.org/www-project-secure-headers/'
        ],
        confidence: 'confirmed'
      }],
      summary: 'Response headers could not be read due to browser CORS restrictions. Use securityheaders.com for a full audit.',
      details: 'Browser-based scanners cannot read response headers of cross-origin requests unless the target explicitly allows it via CORS headers. This is a fundamental browser security constraint, not a site issue.',
      testable: false,
      limitation: 'Browser CORS policy blocks access to cross-origin response headers. Use securityheaders.com, curl, or a server-side scanner.'
    };
  }

  // ----- Evaluate each header -----

  // 1. Strict-Transport-Security
  const hsts = headers['strict-transport-security'];
  if (hsts) {
    const issues = evaluateHSTS(hsts);
    if (issues.length === 0) {
      findings.push({
        title: 'Strict-Transport-Security (HSTS) is properly configured',
        severity: 'info',
        status: 'passed',
        evidence: `Strict-Transport-Security: ${hsts}`,
        impact: 'Browsers will enforce HTTPS for the specified duration.',
        remediation: 'No action required.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
        confidence: 'confirmed'
      });
      score += 2;
    } else {
      findings.push({
        title: 'Strict-Transport-Security (HSTS) present but misconfigured',
        severity: issues[0].severity,
        status: 'warning',
        evidence: `Strict-Transport-Security: ${hsts}\nIssues:\n${issues.map(i => '- ' + i.issue).join('\n')}`,
        impact: 'Weak HSTS configuration reduces its effectiveness against MITM and protocol downgrade attacks.',
        remediation: 'Set max-age=31536000; includeSubDomains; preload',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
        confidence: 'confirmed'
      });
      score += 1;
    }
  } else {
    findings.push({
      title: 'Strict-Transport-Security (HSTS) header missing',
      severity: 'medium',
      status: 'failed',
      evidence: 'Header not present in response.',
      impact: 'Without HSTS, browsers may fall back to HTTP connections and are vulnerable to SSL stripping attacks.',
      remediation: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
      confidence: 'confirmed'
    });
  }

  // 2. Content-Security-Policy
  const csp = headers['content-security-policy'];
  if (csp) {
    const issues = evaluateCSPHeader(csp);
    if (issues.length === 0) {
      findings.push({
        title: 'Content-Security-Policy is present and appears strong',
        severity: 'info',
        status: 'passed',
        evidence: `Content-Security-Policy: ${csp.substring(0, 200)}${csp.length > 200 ? '…' : ''}`,
        impact: 'CSP significantly reduces the risk of XSS attacks.',
        remediation: 'No action required.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
        confidence: 'confirmed'
      });
      score += 2;
    } else {
      findings.push({
        title: 'Content-Security-Policy present but contains weak directives',
        severity: issues.reduce((max, i) => {
          const order = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
          return order[i.severity] > order[max] ? i.severity : max;
        }, 'info'),
        status: 'warning',
        evidence: `Content-Security-Policy: ${csp.substring(0, 200)}${csp.length > 200 ? '…' : ''}\nIssues:\n${issues.map(i => '- ' + i.issue).join('\n')}`,
        impact: 'Weak CSP directives may allow XSS or script injection attacks.',
        remediation: 'Remove unsafe-inline/unsafe-eval, replace wildcards with specific origins, add missing directives.',
        references: ['https://content-security-policy.com/', 'https://csp-evaluator.withgoogle.com/'],
        confidence: 'confirmed'
      });
      score += 1;
    }
  } else {
    findings.push({
      title: 'Content-Security-Policy header missing',
      severity: 'high',
      status: 'failed',
      evidence: 'Header not present in response.',
      impact: 'Without CSP, XSS attacks can execute arbitrary scripts in the user\'s browser.',
      remediation: 'Implement a Content-Security-Policy header. Start with: Content-Security-Policy: default-src \'self\'',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP', 'https://content-security-policy.com/'],
      confidence: 'confirmed'
    });
  }

  // 3. X-Content-Type-Options
  const xcto = headers['x-content-type-options'];
  if (xcto && xcto.toLowerCase().trim() === 'nosniff') {
    findings.push({
      title: 'X-Content-Type-Options: nosniff is set',
      severity: 'info',
      status: 'passed',
      evidence: `X-Content-Type-Options: ${xcto}`,
      impact: 'Prevents MIME-type sniffing attacks.',
      remediation: 'No action required.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
      confidence: 'confirmed'
    });
    score += 1;
  } else if (xcto) {
    findings.push({
      title: 'X-Content-Type-Options has incorrect value',
      severity: 'low',
      status: 'warning',
      evidence: `X-Content-Type-Options: ${xcto} (expected "nosniff")`,
      impact: 'Incorrect value does not prevent MIME sniffing.',
      remediation: 'Set header to: X-Content-Type-Options: nosniff',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
      confidence: 'confirmed'
    });
  } else {
    findings.push({
      title: 'X-Content-Type-Options header missing',
      severity: 'low',
      status: 'failed',
      evidence: 'Header not present in response.',
      impact: 'Without this header, browsers may MIME-sniff responses and execute unexpected content types.',
      remediation: 'Add header: X-Content-Type-Options: nosniff',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
      confidence: 'confirmed'
    });
  }

  // 4. X-Frame-Options
  const xfo = headers['x-frame-options'];
  if (xfo) {
    const val = xfo.toUpperCase().trim();
    if (val === 'DENY' || val === 'SAMEORIGIN') {
      findings.push({
        title: 'X-Frame-Options is set correctly',
        severity: 'info',
        status: 'passed',
        evidence: `X-Frame-Options: ${xfo}`,
        impact: 'Prevents clickjacking by restricting framing.',
        remediation: 'No action required. Consider also adding frame-ancestors in CSP.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
        confidence: 'confirmed'
      });
      score += 1;
    } else {
      findings.push({
        title: 'X-Frame-Options has weak or unknown value',
        severity: 'medium',
        status: 'warning',
        evidence: `X-Frame-Options: ${xfo}`,
        impact: 'Unexpected value may not prevent clickjacking in all browsers.',
        remediation: 'Set to DENY or SAMEORIGIN. Prefer CSP frame-ancestors directive.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
        confidence: 'confirmed'
      });
    }
  } else {
    findings.push({
      title: 'X-Frame-Options header missing',
      severity: 'medium',
      status: 'failed',
      evidence: 'Header not present in response.',
      impact: 'Without X-Frame-Options (or CSP frame-ancestors), the site may be vulnerable to clickjacking.',
      remediation: 'Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
      confidence: 'confirmed'
    });
  }

  // 5. Referrer-Policy
  const rp = headers['referrer-policy'];
  if (rp) {
    const issues = evaluateReferrerPolicy(rp);
    if (issues.length === 0) {
      findings.push({
        title: 'Referrer-Policy is configured',
        severity: 'info',
        status: 'passed',
        evidence: `Referrer-Policy: ${rp}`,
        impact: 'Controls how much referrer information is sent with requests.',
        remediation: 'No action required.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
        confidence: 'confirmed'
      });
      score += 1;
    } else {
      findings.push({
        title: 'Referrer-Policy is overly permissive',
        severity: 'low',
        status: 'warning',
        evidence: `Referrer-Policy: ${rp}\n${issues[0].issue}`,
        impact: 'Full URLs (including sensitive query parameters) may be sent as the Referer header to third parties.',
        remediation: 'Set to: strict-origin-when-cross-origin or no-referrer',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
        confidence: 'confirmed'
      });
    }
  } else {
    findings.push({
      title: 'Referrer-Policy header missing',
      severity: 'low',
      status: 'failed',
      evidence: 'Header not present. Browser defaults to no-referrer-when-downgrade in most cases.',
      impact: 'May expose full URL referrer information to third-party sites.',
      remediation: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
      confidence: 'confirmed'
    });
  }

  // 6. Permissions-Policy
  const pp = headers['permissions-policy'];
  if (pp) {
    findings.push({
      title: 'Permissions-Policy header is present',
      severity: 'info',
      status: 'passed',
      evidence: `Permissions-Policy: ${pp.substring(0, 150)}${pp.length > 150 ? '…' : ''}`,
      impact: 'Controls access to browser features like camera, microphone, and geolocation.',
      remediation: 'Review policies and restrict unused features.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'],
      confidence: 'confirmed'
    });
    score += 1;
  } else {
    findings.push({
      title: 'Permissions-Policy header missing',
      severity: 'low',
      status: 'failed',
      evidence: 'Header not present in response.',
      impact: 'Without Permissions-Policy, iframes and third-party scripts may access sensitive browser APIs.',
      remediation: 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'],
      confidence: 'confirmed'
    });
  }

  // 7. Cross-Origin-Opener-Policy
  const coop = headers['cross-origin-opener-policy'];
  if (coop) {
    findings.push({
      title: 'Cross-Origin-Opener-Policy (COOP) is set',
      severity: 'info',
      status: 'passed',
      evidence: `Cross-Origin-Opener-Policy: ${coop}`,
      impact: 'Isolates the browsing context from cross-origin popups, mitigating Spectre-like attacks.',
      remediation: 'No action required.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy'],
      confidence: 'confirmed'
    });
    score += 1;
  } else {
    findings.push({
      title: 'Cross-Origin-Opener-Policy (COOP) header missing',
      severity: 'low',
      status: 'failed',
      evidence: 'Header not present in response.',
      impact: 'Without COOP, the page may be vulnerable to cross-origin information leakage via shared browsing context.',
      remediation: 'Add: Cross-Origin-Opener-Policy: same-origin',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy'],
      confidence: 'confirmed'
    });
  }

  // 8. Cross-Origin-Resource-Policy
  const corp = headers['cross-origin-resource-policy'];
  if (corp) {
    findings.push({
      title: 'Cross-Origin-Resource-Policy (CORP) is set',
      severity: 'info',
      status: 'passed',
      evidence: `Cross-Origin-Resource-Policy: ${corp}`,
      impact: 'Prevents other origins from reading this site\'s resources via no-cors requests.',
      remediation: 'No action required.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy'],
      confidence: 'confirmed'
    });
    score += 1;
  } else {
    findings.push({
      title: 'Cross-Origin-Resource-Policy (CORP) header missing',
      severity: 'low',
      status: 'failed',
      evidence: 'Header not present in response.',
      impact: 'Resources may be embeddable by cross-origin pages via no-cors requests (Spectre side-channel).',
      remediation: 'Add: Cross-Origin-Resource-Policy: same-origin (or same-site)',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy'],
      confidence: 'confirmed'
    });
  }

  // Clamp score to 0-10
  score = Math.min(10, Math.max(0, score));

  const failedCount = findings.filter(f => f.status === 'failed').length;
  const warningCount = findings.filter(f => f.status === 'warning').length;
  let overallStatus = 'passed';
  if (failedCount >= 3) overallStatus = 'failed';
  else if (failedCount > 0 || warningCount > 0) overallStatus = 'warning';

  const criticalOrHigh = findings.filter(f => f.status === 'failed' && (f.severity === 'critical' || f.severity === 'high'));
  const overallSeverity = criticalOrHigh.length > 0 ? criticalOrHigh[0].severity : (failedCount > 0 ? 'medium' : 'info');

  return {
    id: 'headers',
    name: 'Security Headers',
    category: 'HTTP Security Headers',
    description: 'Evaluates the presence and configuration of critical HTTP security response headers including HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, and CORP.',
    status: overallStatus,
    severity: overallSeverity,
    score,
    findings,
    summary: `${failedCount} header(s) missing, ${warningCount} misconfigured. Score: ${score}/10.`,
    details: 'HTTP security headers are a first line of defense against many web attacks. Missing headers like HSTS, CSP, and X-Frame-Options significantly increase attack surface. If headers could not be retrieved due to CORS, this check is marked not-testable.',
    testable: headersAccessible,
    limitation: headersAccessible ? '' : 'Browser CORS policy may have restricted header access. A fresh fetch was attempted but may have failed.'
  };
}
