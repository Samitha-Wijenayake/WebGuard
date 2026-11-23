/**
 * CORS Analysis Check
 * Attempts a CORS fetch to inspect Access-Control-Allow-Origin and related headers.
 * Notes what cannot be tested from a browser context.
 */

export async function check(url, fetchedData) {
  const { headers: fetchedHeaders } = fetchedData || {};
  const findings = [];
  let acao = null;
  let acac = null;
  let acam = null;
  let headersAccessible = false;

  // Normalize fetched headers
  const headers = {};
  if (fetchedHeaders && typeof fetchedHeaders === 'object') {
    for (const [k, v] of Object.entries(fetchedHeaders)) {
      headers[k.toLowerCase()] = v;
    }
  }

  acao = headers['access-control-allow-origin'] || null;
  acac = headers['access-control-allow-credentials'] || null;
  acam = headers['access-control-allow-methods'] || null;

  if (Object.keys(headers).length > 0) {
    headersAccessible = true;
  }

  // Attempt fresh fetch if headers not available
  if (!headersAccessible) {
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
      acao = resp.headers.get('access-control-allow-origin');
      acac = resp.headers.get('access-control-allow-credentials');
      acam = resp.headers.get('access-control-allow-methods');
      headersAccessible = true;
    } catch (e) {
      // Could be CORS block or network error
      headersAccessible = false;
    }
  }

  // --- Finding 1: Access-Control-Allow-Origin ---
  if (headersAccessible) {
    if (!acao) {
      findings.push({
        title: 'No Access-Control-Allow-Origin header sent',
        severity: 'info',
        status: 'info',
        evidence: 'No Access-Control-Allow-Origin header in response. This means the site does not expose a CORS policy, which is the default restrictive behavior.',
        impact: 'Cross-origin JavaScript cannot read responses from this site (restrictive – generally good).',
        remediation: 'No action required unless you intentionally expose an API. If exposing an API, set explicit allowed origins.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
        confidence: 'confirmed'
      });
    } else if (acao.trim() === '*') {
      if (acac && acac.toLowerCase() === 'true') {
        // Critical: wildcard + credentials
        findings.push({
          title: 'CRITICAL: Access-Control-Allow-Origin: * with Allow-Credentials: true',
          severity: 'critical',
          status: 'failed',
          evidence: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,
          impact: 'This combination is rejected by browsers (spec-mandated), but if implemented incorrectly server-side, it could allow any origin to send credentialed requests and read responses, leading to full session hijacking.',
          remediation: 'Never combine wildcard ACAO with Allow-Credentials: true. Whitelist specific trusted origins for credentialed requests.',
          references: [
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
            'https://portswigger.net/web-security/cors'
          ],
          confidence: 'confirmed'
        });
      } else {
        findings.push({
          title: 'Access-Control-Allow-Origin is set to wildcard (*)',
          severity: 'medium',
          status: 'warning',
          evidence: `Access-Control-Allow-Origin: *`,
          impact: 'Any website can read unauthenticated responses from this server (no credentials). This is acceptable for public APIs but risky if the response contains data that should be restricted.',
          remediation: 'If this is a public API, wildcard is acceptable. For authenticated endpoints, replace * with a specific origin whitelist.',
          references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
          confidence: 'confirmed'
        });
      }
    } else {
      findings.push({
        title: 'Access-Control-Allow-Origin is set to a specific origin',
        severity: 'info',
        status: 'passed',
        evidence: `Access-Control-Allow-Origin: ${acao}`,
        impact: 'Only the specified origin can read cross-origin responses.',
        remediation: 'Ensure the allowed origin is intentional and not dynamically reflected from the request Origin header without validation.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
        confidence: 'confirmed'
      });
    }
  } else {
    findings.push({
      title: 'CORS headers not accessible (CORS/Network block)',
      severity: 'info',
      status: 'not-testable',
      evidence: 'The browser blocked the cross-origin request or the response was opaque. Response headers could not be read.',
      impact: 'Cannot evaluate CORS configuration from browser context.',
      remediation: 'Use curl or a server-side tool: curl -H "Origin: https://evil.com" -I ' + url,
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
      confidence: 'confirmed'
    });
  }

  // --- Finding 2: Origin reflection ---
  findings.push({
    title: 'Origin reflection testing',
    severity: 'high',
    status: 'not-testable',
    evidence: 'Browser-based testing cannot inject a custom Origin header. The browser always sets the Origin automatically and cannot be overridden. Origin reflection (where the server echoes back any Origin value) is a critical CORS vulnerability that cannot be tested from this context.',
    impact: 'If the server reflects arbitrary Origin values and sets Allow-Credentials: true, any website could perform authenticated CORS requests on behalf of the victim.',
    remediation: 'Test with: curl -H "Origin: https://evil.com" -I <url> and check if Access-Control-Allow-Origin: https://evil.com is returned. Use Burp Suite for comprehensive CORS testing.',
    references: [
      'https://portswigger.net/web-security/cors',
      'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'
    ],
    confidence: 'low'
  });

  // --- Finding 3: Allow-Credentials evaluation ---
  if (headersAccessible && acac) {
    if (acac.toLowerCase() === 'true') {
      findings.push({
        title: 'Access-Control-Allow-Credentials: true is set',
        severity: acao === '*' ? 'critical' : 'medium',
        status: acao === '*' ? 'failed' : 'warning',
        evidence: `Access-Control-Allow-Credentials: ${acac}\nAccess-Control-Allow-Origin: ${acao || '(not set)'}`,
        impact: 'When credentials are allowed, only specific origins (not *) should be whitelisted. If the server reflects arbitrary origins, this enables cross-origin session hijacking.',
        remediation: 'Verify that ACAO is not dynamically reflected. Whitelist only trusted origins.',
        references: ['https://portswigger.net/web-security/cors'],
        confidence: 'confirmed'
      });
    } else {
      findings.push({
        title: 'Access-Control-Allow-Credentials is not set to true',
        severity: 'info',
        status: 'passed',
        evidence: `Access-Control-Allow-Credentials: ${acac}`,
        impact: 'Credentials are not shared in cross-origin requests.',
        remediation: 'No action required.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
        confidence: 'confirmed'
      });
    }
  }

  // --- Finding 4: Allow-Methods ---
  if (headersAccessible && acam) {
    const dangerousMethods = ['PUT', 'DELETE', 'PATCH'];
    const allowedMethods = acam.split(',').map(m => m.trim().toUpperCase());
    const foundDangerous = allowedMethods.filter(m => dangerousMethods.includes(m));
    if (foundDangerous.length > 0) {
      findings.push({
        title: 'CORS allows potentially dangerous HTTP methods',
        severity: 'low',
        status: 'warning',
        evidence: `Access-Control-Allow-Methods: ${acam}`,
        impact: `Allowed methods include: ${foundDangerous.join(', ')}. If combined with credential access and poor origin validation, these could be exploited.`,
        remediation: 'Only expose methods required by cross-origin clients. Restrict with proper origin validation.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
        confidence: 'confirmed'
      });
    }
  }

  // Findings that are always not-testable from browser
  findings.push({
    title: 'Pre-flight (OPTIONS) request behavior',
    severity: 'medium',
    status: 'not-testable',
    evidence: 'Browser automatically sends pre-flight OPTIONS requests for complex cross-origin requests. The behavior cannot be fully analyzed from a browser-based scanner without controlling the Origin header.',
    impact: 'Misconfigured pre-flight handling can bypass CORS restrictions.',
    remediation: 'Test pre-flight responses with: curl -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Method: POST" -I <url>',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#preflighted_requests'],
    confidence: 'low'
  });

  const failed = findings.filter(f => f.status === 'failed');
  const warnings = findings.filter(f => f.status === 'warning');
  const notTestable = findings.filter(f => f.status === 'not-testable');

  let overallStatus = 'passed';
  if (failed.length > 0) overallStatus = 'failed';
  else if (!headersAccessible) overallStatus = 'not-testable';
  else if (warnings.length > 0) overallStatus = 'warning';

  const severity = failed.some(f => f.severity === 'critical') ? 'critical'
    : failed.length > 0 ? 'high'
    : warnings.length > 0 ? 'medium'
    : 'info';

  const score = failed.length > 0 ? Math.max(0, 5 - failed.length * 2)
    : warnings.length > 0 ? 6
    : headersAccessible ? 8
    : 0;

  return {
    id: 'cors',
    name: 'CORS Configuration',
    category: 'Access Control',
    description: 'Analyzes Cross-Origin Resource Sharing headers for misconfiguration, wildcard origins, and credential exposure risks.',
    status: overallStatus,
    severity,
    score,
    findings,
    summary: !headersAccessible
      ? 'CORS headers not accessible from browser. Manual testing required.'
      : failed.length > 0
        ? `CORS misconfiguration detected: ${failed.map(f => f.title).join('; ')}`
        : warnings.length > 0
          ? `CORS configured but with potential concerns. ${notTestable.length} check(s) require external tools.`
          : `CORS configuration appears safe. ${notTestable.length} check(s) require external tools.`,
    details: 'CORS analysis from a browser-based scanner is limited because browsers cannot inject custom Origin headers. Origin reflection vulnerabilities (a critical CORS flaw) cannot be tested here. Use Burp Suite, curl, or dedicated CORS testing tools for comprehensive assessment.',
    testable: headersAccessible,
    limitation: 'Cannot inject custom Origin headers from browser. Origin reflection, pre-flight behavior, and credential-based attacks require server-side or proxy-based testing tools.'
  };
}
