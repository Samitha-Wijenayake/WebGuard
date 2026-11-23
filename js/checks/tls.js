/**
 * TLS Certificate Check
 * Browser JS cannot inspect TLS/certificate details directly.
 * Returns informational findings about what is and is not testable.
 */

export async function check(url, fetchedData) {
  const { finalUrl } = fetchedData || {};
  const isHttps = url.startsWith('https://') || (finalUrl && finalUrl.startsWith('https://'));
  const findings = [];

  // --- Finding 1: Certificate validity (inferred) ---
  if (isHttps) {
    findings.push({
      title: 'TLS certificate is valid (inferred)',
      severity: 'info',
      status: 'passed',
      evidence: 'The page loaded successfully over HTTPS without a certificate error, indicating the browser accepted the certificate as valid.',
      impact: 'Valid certificate confirms the server identity and enables encrypted communication.',
      remediation: 'No action required.',
      references: ['https://letsencrypt.org/', 'https://www.ssllabs.com/ssltest/'],
      confidence: 'likely'
    });
  } else {
    findings.push({
      title: 'No TLS – certificate check not applicable',
      severity: 'high',
      status: 'failed',
      evidence: 'Site does not use HTTPS; no TLS certificate is in use.',
      impact: 'Without TLS, all traffic is unencrypted and no certificate identity is established.',
      remediation: 'Obtain and configure a TLS certificate (e.g., via Let\'s Encrypt) and enforce HTTPS.',
      references: ['https://letsencrypt.org/'],
      confidence: 'confirmed'
    });
  }

  // --- Finding 2: TLS version ---
  findings.push({
    title: 'TLS version detection',
    severity: 'medium',
    status: 'not-testable',
    evidence: 'Browser JavaScript APIs do not expose the negotiated TLS version. Modern browsers enforce TLS 1.2+ and refuse TLS 1.0/1.1, so a successful load is a positive signal.',
    impact: 'TLS 1.0 and 1.1 are deprecated and vulnerable (POODLE, BEAST). TLS 1.3 offers the best security.',
    remediation: 'Use SSL Labs (https://www.ssllabs.com/ssltest/) to verify TLS 1.2 or 1.3 is negotiated and older versions are disabled.',
    references: [
      'https://www.ssllabs.com/ssltest/',
      'https://datatracker.ietf.org/doc/html/rfc8446'
    ],
    confidence: 'low'
  });

  // --- Finding 3: Cipher suite ---
  findings.push({
    title: 'Cipher suite strength',
    severity: 'medium',
    status: 'not-testable',
    evidence: 'JavaScript running in the browser cannot read the negotiated cipher suite. External scanning tools are required.',
    impact: 'Weak cipher suites (RC4, DES, 3DES, export-grade) can allow decryption of captured traffic.',
    remediation: 'Run SSL Labs or testssl.sh to check for weak/export cipher suites and disable them on the server.',
    references: [
      'https://www.ssllabs.com/ssltest/',
      'https://testssl.sh/'
    ],
    confidence: 'low'
  });

  // --- Finding 4: Certificate expiry ---
  findings.push({
    title: 'Certificate expiry date',
    severity: 'high',
    status: 'not-testable',
    evidence: 'Browser JS cannot read the certificate expiry date. If the certificate were expired, the browser would have blocked the page load.',
    impact: 'An expired certificate causes browser warnings and blocks users.',
    remediation: 'Use SSL Labs or run: echo | openssl s_client -connect yourdomain.com:443 2>/dev/null | openssl x509 -noout -dates',
    references: ['https://www.ssllabs.com/ssltest/'],
    confidence: 'low'
  });

  // --- Finding 5: Certificate issuer / chain ---
  findings.push({
    title: 'Certificate issuer and chain of trust',
    severity: 'medium',
    status: 'not-testable',
    evidence: 'JavaScript cannot access issuer name, intermediate chain, or root CA details.',
    impact: 'An incomplete or untrusted certificate chain causes browser errors.',
    remediation: 'Verify the full chain at SSL Labs. Ensure intermediate certificates are served by the web server.',
    references: ['https://www.ssllabs.com/ssltest/'],
    confidence: 'low'
  });

  // --- Finding 6: OCSP / Certificate Revocation ---
  findings.push({
    title: 'Certificate revocation (OCSP/CRL)',
    severity: 'medium',
    status: 'not-testable',
    evidence: 'OCSP stapling and CRL status cannot be inspected from browser JavaScript.',
    impact: 'Without revocation checking, compromised certificates may still be trusted.',
    remediation: 'Enable OCSP stapling on your web server. Verify with SSL Labs.',
    references: ['https://www.ssllabs.com/ssltest/'],
    confidence: 'low'
  });

  const score = isHttps ? 5 : 0; // partial credit – we know cert is accepted but can't verify details

  return {
    id: 'tls',
    name: 'TLS Certificate',
    category: 'Transport Security',
    description: 'Assesses TLS certificate validity, version, cipher suite strength, and revocation status. Most sub-checks require external tools because browsers do not expose TLS internals to JavaScript.',
    status: isHttps ? 'info' : 'failed',
    severity: isHttps ? 'info' : 'high',
    score,
    findings,
    summary: isHttps
      ? 'Certificate appears valid (page loaded over HTTPS). Detailed TLS inspection requires external tools such as SSL Labs.'
      : 'Site does not use HTTPS; TLS certificate check not applicable.',
    details: 'Browser JavaScript cannot access TLS session details such as protocol version, cipher suite, certificate expiry, issuer, or revocation status. A successful HTTPS page load indicates the browser accepted the certificate, but that is the only confirmation available here. Use SSL Labs (https://www.ssllabs.com/ssltest/) for a full TLS audit.',
    testable: false,
    limitation: 'Browser JavaScript APIs do not expose TLS session metadata. Only page-load success/failure can be inferred. Use SSL Labs or testssl.sh for complete TLS analysis.'
  };
}
