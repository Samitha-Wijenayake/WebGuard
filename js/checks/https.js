/**
 * HTTPS/HTTP Security Check
 * Verifies protocol usage, redirect behavior, and final URL security.
 */

export async function check(url, fetchedData) {
  const { finalUrl, redirectChain } = fetchedData || {};
  const findings = [];
  let score = 0;
  let overallStatus = 'passed';

  const isHttps = url.startsWith('https://');
  const isHttp  = url.startsWith('http://');
  const finalIsHttps = finalUrl ? finalUrl.startsWith('https://') : isHttps;

  // --- Finding 1: Protocol used ---
  if (isHttps) {
    findings.push({
      title: 'Site uses HTTPS',
      severity: 'info',
      status: 'passed',
      evidence: `URL begins with https://`,
      impact: 'Traffic is encrypted in transit.',
      remediation: 'No action required.',
      references: ['https://developer.mozilla.org/en-US/docs/Glossary/HTTPS'],
      confidence: 'confirmed'
    });
    score += 5;
  } else if (isHttp) {
    findings.push({
      title: 'Site uses insecure HTTP',
      severity: 'high',
      status: 'failed',
      evidence: `URL begins with http://`,
      impact: 'Traffic is transmitted in plaintext; susceptible to eavesdropping and MITM attacks.',
      remediation: 'Configure the server to use HTTPS with a valid TLS certificate and redirect all HTTP traffic to HTTPS.',
      references: [
        'https://developer.mozilla.org/en-US/docs/Glossary/HTTPS',
        'https://letsencrypt.org/'
      ],
      confidence: 'confirmed'
    });
    overallStatus = 'failed';
    score = 0;
  }

  // --- Finding 2: HTTP→HTTPS redirect ---
  findings.push({
    title: 'HTTP to HTTPS redirect',
    severity: 'medium',
    status: 'not-testable',
    evidence: 'Browser-based testing cannot reliably initiate plain HTTP requests and follow redirect chains due to CORS and security policies.',
    impact: 'Cannot confirm whether http:// visitors are automatically redirected to https://.',
    remediation: 'Verify redirect with: curl -I http://yourdomain.com | grep -i location. Configure 301 redirect in server config.',
    references: [
      'https://web.dev/redirects/',
      'https://www.ssllabs.com/ssltest/'
    ],
    confidence: 'low'
  });

  // --- Finding 3: Redirect chain analysis ---
  if (redirectChain && redirectChain.length > 0) {
    const hasInsecureHop = redirectChain.some(r => r.startsWith('http://'));
    if (hasInsecureHop) {
      findings.push({
        title: 'Insecure hop detected in redirect chain',
        severity: 'medium',
        status: 'warning',
        evidence: `Redirect chain: ${redirectChain.join(' → ')}`,
        impact: 'An HTTP hop in the redirect chain exposes the redirect to interception.',
        remediation: 'Ensure all redirects go directly from http:// to https:// without intermediate plaintext hops.',
        references: ['https://owasp.org/www-community/attacks/Man-in-the-browser_attack'],
        confidence: 'confirmed'
      });
      overallStatus = overallStatus === 'failed' ? 'failed' : 'warning';
      score = Math.max(0, score - 2);
    } else {
      findings.push({
        title: 'Redirect chain is fully HTTPS',
        severity: 'info',
        status: 'passed',
        evidence: `Redirect chain: ${redirectChain.join(' → ')}`,
        impact: 'All redirect hops use HTTPS.',
        remediation: 'No action required.',
        references: [],
        confidence: 'confirmed'
      });
    }
  }

  // --- Finding 4: Final URL security ---
  if (finalUrl && finalUrl !== url) {
    findings.push({
      title: finalIsHttps ? 'Final URL is HTTPS' : 'Final URL is HTTP',
      severity: finalIsHttps ? 'info' : 'high',
      status: finalIsHttps ? 'passed' : 'failed',
      evidence: `Final URL after redirects: ${finalUrl}`,
      impact: finalIsHttps
        ? 'The page ultimately loaded over a secure connection.'
        : 'The page ultimately loaded over an insecure connection despite any HTTPS input.',
      remediation: finalIsHttps
        ? 'No action required.'
        : 'Fix redirect configuration so the final destination is always HTTPS.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections'],
      confidence: 'confirmed'
    });
    if (!finalIsHttps) {
      overallStatus = 'failed';
      score = 0;
    }
  }

  // --- Finding 5: Mixed content ---
  findings.push({
    title: 'Mixed content detection',
    severity: 'medium',
    status: 'not-testable',
    evidence: 'Detecting mixed content (HTTP sub-resources on an HTTPS page) requires a full controlled page load with network monitoring, which is not possible from a browser extension without page access.',
    impact: 'Mixed content downgrades HTTPS security and may trigger browser warnings.',
    remediation: 'Use browser DevTools > Security tab, or run Lighthouse audit to detect mixed content.',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content',
      'https://web.dev/what-is-mixed-content/'
    ],
    confidence: 'low'
  });

  // Clamp score
  score = Math.min(10, Math.max(0, score));
  if (isHttps && finalIsHttps && overallStatus === 'passed') score = 7; // redirect not tested

  return {
    id: 'https',
    name: 'HTTPS / Protocol Security',
    category: 'Transport Security',
    description: 'Checks whether the site uses HTTPS, inspects redirect behavior, and verifies the final URL is served over a secure connection.',
    status: overallStatus,
    severity: overallStatus === 'failed' ? 'high' : overallStatus === 'warning' ? 'medium' : 'info',
    score,
    findings,
    summary: isHttps
      ? 'Site is served over HTTPS. HTTP→HTTPS redirect and mixed content cannot be verified from the browser.'
      : 'Site uses insecure HTTP. Migrate to HTTPS immediately.',
    details: 'HTTPS encrypts traffic between the client and server using TLS, preventing eavesdropping and man-in-the-middle attacks. HTTP→HTTPS redirects cannot be tested from a browser-based scanner due to CORS and security restrictions. Use SSL Labs or curl for a comprehensive test.',
    testable: true,
    limitation: 'HTTP→HTTPS redirect behavior and mixed content cannot be fully verified from a browser-based context.'
  };
}
