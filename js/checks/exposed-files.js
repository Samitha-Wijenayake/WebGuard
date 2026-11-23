/**
 * WebGuard Check: Exposed Sensitive Files
 * Checks common sensitive file paths for unintended exposure.
 */

import { proxyFetch } from '../net.js';

const SENSITIVE_PATHS = [
  // Critical - credentials / source control
  { path: '/.env',                  label: 'Environment file',          severity: 'critical', category: 'env' },
  { path: '/.env.local',            label: 'Local env file',            severity: 'critical', category: 'env' },
  { path: '/.env.production',       label: 'Production env file',       severity: 'critical', category: 'env' },
  { path: '/.git/HEAD',             label: 'Git HEAD reference',        severity: 'critical', category: 'git' },
  { path: '/.git/config',           label: 'Git config file',           severity: 'critical', category: 'git' },
  // High - backup / database
  { path: '/backup.zip',            label: 'Backup archive (zip)',       severity: 'high',     category: 'backup' },
  { path: '/backup.tar.gz',         label: 'Backup archive (tar.gz)',    severity: 'high',     category: 'backup' },
  { path: '/db.sql',                label: 'SQL database dump',          severity: 'critical', category: 'backup' },
  { path: '/database.sql',          label: 'SQL database dump',          severity: 'critical', category: 'backup' },
  // High - config
  { path: '/config.json',           label: 'JSON config file',           severity: 'high',     category: 'config' },
  { path: '/config.php',            label: 'PHP config file',            severity: 'high',     category: 'config' },
  { path: '/wp-config.php.bak',     label: 'WordPress config backup',    severity: 'critical', category: 'config' },
  { path: '/phpinfo.php',           label: 'PHP info page',              severity: 'high',     category: 'config' },
  // High - debug / logs
  { path: '/debug',                 label: 'Debug endpoint',             severity: 'high',     category: 'debug' },
  { path: '/debug.log',             label: 'Debug log file',             severity: 'high',     category: 'debug' },
  { path: '/error.log',             label: 'Error log file',             severity: 'high',     category: 'debug' },
  // Medium - server info
  { path: '/server-status',         label: 'Apache server-status',       severity: 'medium',   category: 'server' },
  { path: '/server-info',           label: 'Apache server-info',         severity: 'medium',   category: 'server' },
  // Medium - admin
  { path: '/admin',                 label: 'Admin panel',                severity: 'medium',   category: 'admin' },
  { path: '/phpmyadmin',            label: 'phpMyAdmin',                 severity: 'high',     category: 'admin' },
  { path: '/.htaccess',             label: 'Apache .htaccess',           severity: 'medium',   category: 'config' },
  // Info - package manifests
  { path: '/package.json',          label: 'Node.js package manifest',   severity: 'low',      category: 'package' },
  { path: '/composer.json',         label: 'PHP Composer manifest',      severity: 'low',      category: 'package' },
  // Info - robots (reference only)
  { path: '/robots.txt',            label: 'robots.txt',                 severity: 'info',     category: 'info' },
];

function maskPath(path) {
  return path; // paths themselves are not sensitive to show
}

function getOrigin(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return url;
  }
}

export async function check(url, fetchedData) {
  const origin = getOrigin(fetchedData.finalUrl || url);
  const findings = [];
  const checkedPaths = [];
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let accessControlledCount = 0;

  const checkPath = async (item) => {
    const targetUrl = `${origin}${item.path}`;
    try {
      const res = await proxyFetch(targetUrl, { method: 'HEAD', timeout: 8000, maxBytes: 0 });

      const status = res.status;
      const contentType = res.headers?.['content-type'] || '';
      const contentLength = res.headers?.['content-length'] || 'unknown';
      let finding = null;
      const looksLikeHtml = /text\/html|application\/xhtml/i.test(contentType);
      const expectsFile = /\.[a-z0-9]+$/i.test(item.path);

      if ((status === 200 || status === 206) && !(looksLikeHtml && expectsFile)) {

        finding = {
          title: `Potentially exposed: ${item.label} (${item.path})`,
          severity: item.severity,
          status: item.severity === 'info' ? 'info' : (item.severity === 'low' ? 'warning' : 'failed'),
          evidence: `HTTP ${status} at ${targetUrl} | Content-Type: ${contentType} | Size: ${contentLength} bytes`,
          impact: getImpact(item),
          remediation: getRemediation(item),
          references: getReferences(item),
          confidence: 'confirmed',
        };

        if (item.severity === 'critical') criticalCount++;
        else if (item.severity === 'high') highCount++;
        else if (item.severity === 'medium') mediumCount++;

        checkedPaths.push({ path: item.path, status: 'exposed', httpStatus: status, severity: item.severity });
      } else if (status === 403 || status === 401) {
        // Exists but access controlled
        accessControlledCount++;
        checkedPaths.push({ path: item.path, status: 'access-controlled', httpStatus: status });
        // Only add finding for high/critical access-controlled files (they exist but are protected)
        if (item.severity === 'critical' || item.severity === 'high') {
          finding = {
            title: `${item.label} exists but access is controlled (${item.path})`,
            severity: 'info',
            status: 'info',
            evidence: `HTTP ${status} at ${targetUrl} — file/path exists but server returned access denied`,
            impact: 'File exists on server. If access control is misconfigured, it could be exposed.',
            remediation: 'Confirm the file is intentionally present. Consider removing sensitive files entirely rather than relying on access controls.',
            references: getReferences(item),
            confidence: 'confirmed',
          };
        }
      } else {
        // 404, 410, 5xx — not found or server error
        checkedPaths.push({ path: item.path, status: 'not-found', httpStatus: status });
      }

      return finding;
    } catch (err) {
      // Network error, CORS block, timeout — cannot determine
      checkedPaths.push({ path: item.path, status: 'unknown', error: err.message });
      return null;
    }
  };

  // Run checks in controlled batches (5 at a time to avoid overwhelming)
  const BATCH_SIZE = 5;
  for (let i = 0; i < SENSITIVE_PATHS.length; i += BATCH_SIZE) {
    const batch = SENSITIVE_PATHS.slice(i, i + BATCH_SIZE);
    const results = await Promise.all(batch.map(checkPath));
    for (const f of results) {
      if (f) findings.push(f);
    }
  }

  // Determine overall status and score
  let status = 'passed';
  let score = 10;

  if (criticalCount > 0) {
    status = 'failed';
    score = Math.max(0, 10 - criticalCount * 4 - highCount * 2);
  } else if (highCount > 0) {
    status = 'failed';
    score = Math.max(2, 10 - highCount * 2 - mediumCount);
  } else if (mediumCount > 0) {
    status = 'warning';
    score = Math.max(5, 10 - mediumCount);
  } else if (findings.length > 0) {
    status = 'info';
    score = 8;
  }

  const unknownCount = checkedPaths.filter(p => p.status === 'unknown').length;
  if (unknownCount === SENSITIVE_PATHS.length) {
    status = 'not-testable';
    score = 0;
    findings.push({
      title: 'Sensitive file paths could not be requested',
      severity: 'info',
      status: 'not-testable',
      evidence: 'The local scanner service did not complete the path requests.',
      impact: 'No conclusion is drawn about exposed files.',
      remediation: 'Run WebGuard with node server.js and scan again.',
      references: [],
      confidence: 'confirmed',
    });
  }

  score = Math.round(score);

  const exposedCount = checkedPaths.filter(p => p.status === 'exposed').length;

  return {
    id: 'exposed-files',
    name: 'Exposed Sensitive Files',
    category: 'Information Disclosure',
    description: 'Checks for common sensitive file paths that may be unintentionally exposed (e.g., .env, .git/HEAD, backup files, debug logs, config files).',
    status,
    severity: criticalCount > 0 ? 'critical' : highCount > 0 ? 'high' : mediumCount > 0 ? 'medium' : 'low',
    score,
    findings,
    summary: exposedCount > 0
      ? `${exposedCount} potentially exposed file(s) found (${criticalCount} critical, ${highCount} high, ${mediumCount} medium). ${accessControlledCount} path(s) exist but are access-controlled.`
      : `No sensitive files appear to be directly accessible. ${accessControlledCount} path(s) exist but are access-controlled.`,
    details: `Checked ${SENSITIVE_PATHS.length} common sensitive paths using HEAD requests. ` +
      `Results: ${exposedCount} exposed, ${accessControlledCount} access-controlled, ` +
      `${checkedPaths.filter(p => p.status === 'not-found').length} not found, ` +
      `${checkedPaths.filter(p => p.status === 'unknown').length} indeterminate (CORS/network).`,
    testable: true,
    limitation: 'HEAD requests may be blocked by CORS in browser context, making some results indeterminate. Only HTTP status codes are checked — file contents are never read. False positives may occur if server returns 200 for all paths (soft 404s).',
  };
}

function getImpact(item) {
  const impacts = {
    env:    'Environment files often contain database credentials, API keys, and application secrets.',
    git:    'Git repository access can expose full source code history, credentials in commit history, and application logic.',
    backup: 'Backup files may contain complete database contents including user data, passwords, and sensitive information.',
    config: 'Configuration files can expose database credentials, API keys, internal service addresses, and security settings.',
    debug:  'Debug and error logs may contain stack traces, internal paths, database queries, and sensitive data values.',
    server: 'Server status pages can expose internal server state, connected clients, and infrastructure details.',
    admin:  'Admin interfaces are prime targets for brute-force attacks and exploitation if left exposed.',
    package:'Package manifests expose dependency names and versions, aiding targeted vulnerability research.',
    info:   'Informational only — this file type is typically intentionally public.',
  };
  return impacts[item.category] || 'May expose sensitive information.';
}

function getRemediation(item) {
  const remediations = {
    env:    'Remove .env files from web root. Use server-side environment variable injection. Add .env to .gitignore.',
    git:    'Block .git directory access in web server config (deny access to /.git/ in nginx/Apache). Never deploy with .git in web root.',
    backup: 'Remove backup files from web-accessible directories. Store backups in non-public locations.',
    config: 'Move configuration files outside web root or restrict access via web server rules.',
    debug:  'Disable debug mode in production. Remove or rotate log files. Restrict log file access.',
    server: 'Disable server-status and server-info modules or restrict to localhost/admin IPs.',
    admin:  'Restrict admin interface access by IP, use strong authentication, and consider non-standard paths.',
    package:'Consider blocking package.json access or ensure it does not contain sensitive scripts/configurations.',
    info:   'Review robots.txt entries to ensure they do not reveal sensitive path structures.',
  };
  return remediations[item.category] || 'Remove or restrict access to this file.';
}

function getReferences(item) {
  const base = ['https://owasp.org/www-project-web-security-testing-guide/'];
  if (item.category === 'git') base.push('https://pentester.land/blog/source-code-disclosure-via-exposed-git-folder/');
  if (item.category === 'env') base.push('https://www.hackerone.com/knowledge-center/environment-variable-security');
  return base;
}
