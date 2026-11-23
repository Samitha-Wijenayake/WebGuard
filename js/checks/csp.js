/**
 * Content Security Policy (CSP) Analysis
 * Parses the CSP header (if accessible) and evaluates strength of directives.
 */

const DANGEROUS_SOURCES = ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'"];
const WILDCARD_PATTERN = /(?:^|\s)\*(?:\s|$)/;

function parseCSP(headerValue) {
  const directives = {};
  const parts = headerValue.split(';').map(s => s.trim()).filter(Boolean);
  for (const part of parts) {
    const tokens = part.split(/\s+/);
    const name = tokens[0].toLowerCase();
    directives[name] = tokens.slice(1);
  }
  return directives;
}

function checkDirective(directives, name) {
  return Object.prototype.hasOwnProperty.call(directives, name);
}

function sourcesFor(directives, name) {
  if (checkDirective(directives, name)) return directives[name];
  if (checkDirective(directives, 'default-src')) return directives['default-src'];
  return null;
}

export async function check(url, fetchedData) {
  const { headers: fetchedHeaders } = fetchedData || {};
  const findings = [];

  // Normalize headers
  const headers = {};
  if (fetchedHeaders && typeof fetchedHeaders === 'object') {
    for (const [k, v] of Object.entries(fetchedHeaders)) {
      headers[k.toLowerCase()] = v;
    }
  }

  let cspValue = headers['content-security-policy'] || null;

  // Try fresh fetch if no headers available
  if (!cspValue && (!fetchedHeaders || Object.keys(headers).length === 0)) {
    try {
      const resp = await fetch(url, {
        method: 'GET',
        mode: 'cors',
        credentials: 'omit',
        signal: AbortSignal.timeout(10000)
      });
      cspValue = resp.headers.get('content-security-policy') || null;
    } catch (e) {
      // CORS blocked
    }
  }

  if (!cspValue && (!fetchedHeaders || Object.keys(headers).length === 0)) {
    return {
      id: 'csp',
      name: 'Content Security Policy (CSP)',
      category: 'HTTP Security Headers',
      description: 'Parses and evaluates the Content-Security-Policy header for XSS protection strength.',
      status: 'not-testable',
      severity: 'info',
      score: 0,
      findings: [{
        title: 'CSP header not accessible (CORS)',
        severity: 'info',
        status: 'not-testable',
        evidence: 'Browser CORS policy prevented reading the Content-Security-Policy header.',
        impact: 'Cannot evaluate CSP configuration.',
        remediation: 'Use https://csp-evaluator.withgoogle.com/ or https://securityheaders.com/ for a full CSP audit.',
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
          'https://csp-evaluator.withgoogle.com/'
        ],
        confidence: 'confirmed'
      }],
      summary: 'CSP header not accessible due to browser CORS restrictions.',
      details: 'The Content-Security-Policy header could not be read because the browser blocked the cross-origin request headers. Use an external tool for CSP analysis.',
      testable: false,
      limitation: 'Browser CORS policy blocks cross-origin header access.'
    };
  }

  if (!cspValue) {
    // Headers accessible but CSP absent
    return {
      id: 'csp',
      name: 'Content Security Policy (CSP)',
      category: 'HTTP Security Headers',
      description: 'Parses and evaluates the Content-Security-Policy header for XSS protection strength.',
      status: 'failed',
      severity: 'high',
      score: 0,
      findings: [{
        title: 'Content-Security-Policy header is absent',
        severity: 'high',
        status: 'failed',
        evidence: 'No Content-Security-Policy header found in HTTP response.',
        impact: 'Without CSP, XSS attacks can inject and execute arbitrary scripts in users\' browsers.',
        remediation: 'Implement a strict Content-Security-Policy. Start with: default-src \'self\'; Use CSP evaluator to refine it.',
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
          'https://csp-evaluator.withgoogle.com/',
          'https://content-security-policy.com/'
        ],
        confidence: 'confirmed'
      }],
      summary: 'No Content-Security-Policy header found. The site lacks XSS protection via CSP.',
      details: 'CSP is a critical defense-in-depth layer against Cross-Site Scripting (XSS). Without it, any injected script can run with full page privileges.',
      testable: true,
      limitation: ''
    };
  }

  // --- Parse and evaluate CSP ---
  const directives = parseCSP(cspValue);
  let score = 10;
  const issues = [];

  // unsafe-inline / unsafe-eval
  for (const [dirName, sources] of Object.entries(directives)) {
    if (!['script-src', 'style-src', 'default-src'].includes(dirName)) continue;
    for (const src of sources) {
      if (src === "'unsafe-inline'") {
        issues.push({
          directive: dirName,
          issue: `'unsafe-inline' in ${dirName} allows inline scripts/styles`,
          severity: 'high',
          remediation: `Remove 'unsafe-inline' from ${dirName}. Use nonces or hashes for inline code.`
        });
        score -= 2;
      }
      if (src === "'unsafe-eval'") {
        issues.push({
          directive: dirName,
          issue: `'unsafe-eval' in ${dirName} allows eval() – common XSS vector`,
          severity: 'high',
          remediation: `Remove 'unsafe-eval' from ${dirName}. Refactor code to avoid eval().`
        });
        score -= 2;
      }
    }
  }

  // Wildcard in script-src
  const scriptSources = sourcesFor(directives, 'script-src') || [];
  if (scriptSources.includes('*') || WILDCARD_PATTERN.test(scriptSources.join(' '))) {
    issues.push({
      directive: 'script-src',
      issue: 'Wildcard (*) in script-src allows scripts from any origin',
      severity: 'critical',
      remediation: 'Replace wildcard with specific trusted domains.'
    });
    score -= 3;
  }

  // Missing default-src
  if (!checkDirective(directives, 'default-src')) {
    issues.push({
      directive: 'default-src',
      issue: 'Missing default-src – no fallback policy for unspecified resource types',
      severity: 'medium',
      remediation: "Add: default-src 'self'"
    });
    score -= 1;
  }

  // Missing object-src (or not restricted)
  const objectSources = sourcesFor(directives, 'object-src') || [];
  if (!checkDirective(directives, 'object-src')) {
    issues.push({
      directive: 'object-src',
      issue: 'Missing object-src – plugins/Flash/PDF not restricted',
      severity: 'medium',
      remediation: "Add: object-src 'none'"
    });
    score -= 1;
  } else if (!objectSources.includes("'none'")) {
    issues.push({
      directive: 'object-src',
      issue: `object-src is not set to 'none' (current: ${objectSources.join(' ')})`,
      severity: 'low',
      remediation: "Set object-src 'none' to block plugin execution."
    });
    score -= 0.5;
  }

  // Missing base-uri
  if (!checkDirective(directives, 'base-uri')) {
    issues.push({
      directive: 'base-uri',
      issue: 'Missing base-uri – base tag injection could redirect relative URLs',
      severity: 'low',
      remediation: "Add: base-uri 'self'"
    });
    score -= 0.5;
  }

  // frame-ancestors
  if (checkDirective(directives, 'frame-ancestors')) {
    const fas = directives['frame-ancestors'];
    if (fas.includes('*')) {
      issues.push({
        directive: 'frame-ancestors',
        issue: 'frame-ancestors * allows any site to iframe this page (clickjacking risk)',
        severity: 'high',
        remediation: "Set frame-ancestors 'none' or 'self'"
      });
      score -= 2;
    } else {
      findings.push({
        title: 'CSP frame-ancestors is configured',
        severity: 'info',
        status: 'passed',
        evidence: `frame-ancestors: ${fas.join(' ')}`,
        impact: 'Restricts which origins can embed this page, preventing clickjacking.',
        remediation: 'No action required.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors'],
        confidence: 'confirmed'
      });
    }
  }

  // Build findings from issues
  for (const issue of issues) {
    findings.push({
      title: `CSP Issue: ${issue.issue}`,
      severity: issue.severity,
      status: issue.severity === 'info' ? 'info' : 'warning',
      evidence: `Directive: ${issue.directive}\nValue: ${(directives[issue.directive] || []).join(' ') || '(inherited from default-src)'}`,
      impact: issue.issue,
      remediation: issue.remediation,
      references: [
        'https://csp-evaluator.withgoogle.com/',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
      ],
      confidence: 'confirmed'
    });
  }

  if (issues.length === 0) {
    findings.push({
      title: 'Content-Security-Policy appears well configured',
      severity: 'info',
      status: 'passed',
      evidence: `Content-Security-Policy: ${cspValue.substring(0, 300)}${cspValue.length > 300 ? '…' : ''}`,
      impact: 'Strong CSP significantly reduces XSS risk.',
      remediation: 'Periodically review CSP as the application evolves.',
      references: ['https://csp-evaluator.withgoogle.com/'],
      confidence: 'confirmed'
    });
  }

  score = Math.min(10, Math.max(0, Math.round(score)));
  const hasHighOrCritical = issues.some(i => i.severity === 'critical' || i.severity === 'high');
  const overallStatus = issues.length === 0 ? 'passed' : hasHighOrCritical ? 'failed' : 'warning';
  const overallSeverity = issues.length === 0 ? 'info' : (issues[0]?.severity || 'medium');

  return {
    id: 'csp',
    name: 'Content Security Policy (CSP)',
    category: 'HTTP Security Headers',
    description: 'Parses and evaluates the Content-Security-Policy header for XSS protection directives, unsafe sources, wildcards, and missing critical policies.',
    status: overallStatus,
    severity: overallSeverity,
    score,
    findings,
    summary: issues.length === 0
      ? 'CSP is present and appears strong.'
      : `CSP present but has ${issues.length} issue(s): ${issues.map(i => i.directive).join(', ')}.`,
    details: `Parsed ${Object.keys(directives).length} CSP directive(s). Evaluated for unsafe sources, wildcards, and missing critical directives. Full policy: ${cspValue.substring(0, 500)}`,
    testable: true,
    limitation: ''
  };
}
