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
    // Medio y no alto: casi ninguna app en Vercel tiene CSP, y como "alto" hacía
    // que --fail-on-high fallara en prácticamente cualquier sitio.
    severity: 'medium',
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

function explainStatus(res) {
  const h = res.headers;
  const s = res.status;
  const url = res.url;
  const vercelChallenge = /challenge|deny/i.test(h.get('x-vercel-mitigated') || '');
  const cfChallenge = /challenge/i.test(h.get('cf-mitigated') || '');
  const vercelError = h.get('x-vercel-error');
  if (vercelChallenge || cfChallenge) {
    return `${url} devolvió un desafío de protección contra bots (${vercelChallenge ? 'Vercel Firewall / Attack Challenge' : 'Cloudflare'}). ` +
      'rlscan no puede resolverlo, así que ni las cabeceras, ni los bundles JS, ni las rutas se evaluaron. ' +
      'Desactiva el desafío temporalmente o agrega una regla de bypass para tu escaneo y vuelve a correrlo.';
  }
  if (s === 401 || s === 403) {
    return `${url} respondió ${s} ${res.statusText}: el sitio (o un WAF / protección contra bots / login) bloqueó la petición. ` +
      'Nada del sitio real se evaluó. Si escaneaste varias veces seguidas, puede ser un bloqueo temporal por frecuencia.';
  }
  if (s === 404) {
    return `${url} respondió 404${vercelError ? ` (${vercelError})` : ''}: la página o el deployment no existe. Revisa la URL.`;
  }
  if (s === 429) return `${url} respondió 429: límite de peticiones. Espera un momento y vuelve a intentar.`;
  if (s >= 500) return `${url} respondió ${s} ${res.statusText}: error del servidor. Nada del sitio real se evaluó.`;
  return `${url} respondió ${s} ${res.statusText}. Nada del sitio real se evaluó.`;
}

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
    // Una página de bloqueo, de error o de "deployment no encontrado" no es el sitio: evaluar sus
    // cabeceras y no encontrar secretos en ella daría un "aprobado" falso. Escaneo incompleto (exit 2).
    return {
      findings: [{ check: 'headers', severity: 'error', title: `El sitio respondió ${res.status}: no se pudo escanear`, detail: explainStatus(res) }],
      reachable: false,
      blockedStatus: res.status,
      html: null,
      finalUrl: res.url,
    };
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
