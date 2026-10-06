import { fetchSafe, readTextCapped, resolveUrl } from '../utils/fetchSafe.js';

const MAX_SCRIPTS = 15; // avoid hammering huge apps; covers the common bundle count

// Known secret prefixes/shapes. Kept intentionally narrow (real vendor
// formats) to minimize false positives vs. a generic high-entropy scan.
const SECRET_PATTERNS = [
  { name: 'AWS Access Key ID', re: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'Stripe Live Secret Key', re: /sk_live_[0-9a-zA-Z]{20,}/g, severity: 'critical' },
  { name: 'Stripe Test Secret Key', re: /sk_test_[0-9a-zA-Z]{20,}/g, severity: 'medium' },
  { name: 'Google API Key', re: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high' },
  { name: 'GitHub Personal Access Token', re: /gh[pousr]_[0-9A-Za-z]{36,}/g, severity: 'critical' },
  { name: 'Slack Token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/g, severity: 'high' },
  { name: 'SendGrid API Key', re: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g, severity: 'high' },
  { name: 'Private Key Block', re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: 'critical' },
];

const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

function redact(value) {
  if (value.length <= 12) return '****';
  return `${value.slice(0, 6)}…${value.slice(-4)}`;
}

function decodeJwtPayload(token) {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
    const json = Buffer.from(padded, 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function extractScriptUrls(html, baseUrl) {
  const urls = new Set();
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html))) {
    const abs = resolveUrl(m[1], baseUrl);
    if (abs) urls.add(abs);
  }
  return [...urls].slice(0, MAX_SCRIPTS);
}

function scanTextForSecrets(text, sourceUrl, findings) {
  for (const pattern of SECRET_PATTERNS) {
    const matches = text.match(pattern.re);
    if (matches) {
      for (const match of new Set(matches)) {
        findings.push({
          check: 'secrets',
          severity: pattern.severity,
          title: `Posible ${pattern.name} expuesta`,
          detail: `Encontrado en ${sourceUrl}: ${redact(match)}`,
        });
      }
    }
  }

  const jwts = text.match(JWT_RE) || [];
  for (const jwt of new Set(jwts)) {
    const payload = decodeJwtPayload(jwt);
    if (payload?.role === 'service_role') {
      findings.push({
        check: 'secrets',
        severity: 'critical',
        title: 'Supabase service_role key expuesta en el cliente',
        detail: `Esta llave se salta Row Level Security por completo. Encontrada en ${sourceUrl}: ${redact(jwt)}`,
      });
    }
  }
}

export async function scanForSecrets(url) {
  const findings = [];
  let res;
  try {
    res = await fetchSafe(url);
  } catch (err) {
    findings.push({
      check: 'secrets',
      severity: 'info',
      title: 'No se pudo descargar el HTML principal',
      detail: `${url}: ${err.message}`,
    });
    return findings;
  }

  const html = await readTextCapped(res);
  scanTextForSecrets(html, url, findings);

  const scriptUrls = extractScriptUrls(html, url);
  for (const scriptUrl of scriptUrls) {
    try {
      const scriptRes = await fetchSafe(scriptUrl, { timeoutMs: 10000 });
      if (!scriptRes.ok) continue;
      const js = await readTextCapped(scriptRes);
      scanTextForSecrets(js, scriptUrl, findings);
    } catch {
      // Un bundle que no carga no detiene el escaneo de los demás.
    }
  }

  return findings;
}
