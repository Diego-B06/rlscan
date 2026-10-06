import { fetchSafe } from '../utils/fetchSafe.js';

const EXPECTED_HEADERS = [
  {
    key: 'strict-transport-security',
    name: 'Strict-Transport-Security (HSTS)',
    severity: 'medium',
    why: 'Sin esto, un atacante en la misma red puede forzar al navegador a usar HTTP en vez de HTTPS.',
  },
  {
    key: 'content-security-policy',
    name: 'Content-Security-Policy',
    severity: 'high',
    why: 'Sin CSP, un XSS inyectado puede ejecutar JS arbitrario sin restricciones.',
  },
  {
    key: 'x-content-type-options',
    name: 'X-Content-Type-Options',
    severity: 'low',
    why: 'Sin "nosniff", el navegador puede interpretar un archivo subido por un usuario como script.',
  },
  {
    key: 'x-frame-options',
    name: 'X-Frame-Options',
    severity: 'medium',
    why: 'Sin esto, el sitio puede embeberse en un iframe ajeno (clickjacking).',
  },
  {
    key: 'referrer-policy',
    name: 'Referrer-Policy',
    severity: 'low',
    why: 'Sin esto, URLs internas (con tokens en query params, por ejemplo) pueden filtrarse a sitios externos vía el header Referer.',
  },
];

export async function checkHeaders(url) {
  const findings = [];
  let res;
  try {
    res = await fetchSafe(url);
  } catch (err) {
    findings.push({
      check: 'headers',
      severity: 'info',
      title: 'No se pudo conectar al sitio',
      detail: `${url}: ${err.message}`,
    });
    return findings;
  }

  if (!res.ok) {
    findings.push({
      check: 'headers',
      severity: 'info',
      title: `El sitio respondió ${res.status}`,
      detail: `No se evaluaron cabeceras porque la respuesta no fue 2xx (${res.status} ${res.statusText}).`,
    });
  }

  for (const h of EXPECTED_HEADERS) {
    if (!res.headers.get(h.key)) {
      findings.push({
        check: 'headers',
        severity: h.severity,
        title: `Falta cabecera: ${h.name}`,
        detail: h.why,
      });
    }
  }

  return findings;
}
