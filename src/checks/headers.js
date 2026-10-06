import { fetchText } from '../utils/fetchSafe.js';

const EXPECTED_HEADERS = [
  {
    key: 'strict-transport-security',
    name: 'Strict-Transport-Security (HSTS)',
    severity: 'medium',
    why: 'Sin esto, un atacante en la misma red puede forzar al navegador a usar HTTP en vez de HTTPS.',
    httpsOnly: true, // HSTS solo tiene sentido sobre HTTPS
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
    // CSP con frame-ancestors cumple la misma función (y es lo moderno).
    satisfiedBy: (headers) => /frame-ancestors/i.test(headers.get('content-security-policy') || ''),
  },
  {
    key: 'referrer-policy',
    name: 'Referrer-Policy',
    severity: 'low',
    why: 'Sin esto, URLs internas (con tokens en query params, por ejemplo) pueden filtrarse a sitios externos vía el header Referer.',
  },
];

/**
 * @returns {Promise<{findings: object[], reachable: boolean, html: string|null, finalUrl: string|null}>}
 * La página principal se descarga una sola vez y se reutiliza para el escaneo de secretos.
 */
export async function checkHeaders(url) {
  const findings = [];
  let res;
  try {
    res = await fetchText(url);
  } catch (err) {
    return {
      findings: [{ check: 'headers', severity: 'error', title: 'No se pudo conectar al sitio', detail: `${url}: ${err.message}` }],
      reachable: false,
      html: null,
      finalUrl: null,
    };
  }

  if (!res.ok) {
    findings.push({
      check: 'headers',
      severity: 'info',
      title: `El sitio respondió ${res.status}`,
      detail: `Las cabeceras se evaluaron sobre esa respuesta (${res.status} ${res.statusText}), que puede diferir de la de una página normal.`,
    });
  }

  const isHttps = new URL(res.url).protocol === 'https:';
  for (const h of EXPECTED_HEADERS) {
    if (h.httpsOnly && !isHttps) continue;
    if (res.headers.get(h.key)) continue;
    if (h.satisfiedBy?.(res.headers)) continue;
    findings.push({
      check: 'headers',
      severity: h.severity,
      title: `Falta cabecera: ${h.name}`,
      detail: h.why,
    });
  }

  return { findings, reachable: true, html: res.text, finalUrl: res.url };
}
