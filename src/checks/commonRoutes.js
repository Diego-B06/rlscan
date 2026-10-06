import { randomBytes } from 'node:crypto';
import { fetchText } from '../utils/fetchSafe.js';

// Cada ruta lleva un validador de CONTENIDO: un 200 por sí solo no prueba nada
// (los SPAs con fallback responden 200 + index.html a cualquier ruta).
const looksLikeHtml = (res) => /text\/html/i.test(res.headers.get('content-type') || '') || /^\s*<(!doctype|html)/i.test(res.text);

const COMMON_PATHS = [
  { path: '/.env', severity: 'critical', valid: (r) => /^\s*[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(r.text) && !looksLikeHtml(r) },
  { path: '/.env.local', severity: 'critical', valid: (r) => /^\s*[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(r.text) && !looksLikeHtml(r) },
  { path: '/.env.production', severity: 'critical', valid: (r) => /^\s*[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(r.text) && !looksLikeHtml(r) },
  { path: '/.git/config', severity: 'critical', valid: (r) => /\[(core|remote|branch)\b/.test(r.text) && !looksLikeHtml(r) },
  { path: '/.vercel/output/config.json', severity: 'medium', valid: (r) => /"(version|routes)"\s*:/.test(r.text) && !looksLikeHtml(r) },
  { path: '/wp-config.php', severity: 'critical', valid: (r) => /DB_(NAME|USER|PASSWORD)/.test(r.text) },
  // Endpoints de debug/admin: no hay firma de contenido única; exigimos que NO sea el fallback HTML.
  { path: '/api/debug', severity: 'medium', valid: (r) => !looksLikeHtml(r) },
  { path: '/api/admin', severity: 'medium', valid: (r) => !looksLikeHtml(r) },
  { path: '/api/internal', severity: 'medium', valid: (r) => !looksLikeHtml(r) },
  { path: '/api/_internal', severity: 'medium', valid: (r) => !looksLikeHtml(r) },
];

export async function checkCommonRoutes(baseUrl) {
  const findings = [];
  const base = baseUrl.replace(/\/$/, '');

  // Línea base: una ruta que seguro no existe. Si responde 200, el sitio tiene fallback
  // y ningún "200" es una señal por sí mismo; solo cuenta el contenido validado.
  let fallback = false;
  let baselineText = null;
  try {
    const probe = await fetchText(`${base}/__rlscan_${randomBytes(6).toString('hex')}`, { timeoutMs: 5000 });
    if (probe.status === 200) {
      fallback = true;
      baselineText = probe.text;
    }
  } catch {
    // sin línea base: seguimos, la validación de contenido protege igual
  }

  const checks = COMMON_PATHS.map(async ({ path, severity, valid }) => {
    try {
      const res = await fetchText(`${base}${path}`, { timeoutMs: 5000 });
      if (res.status !== 200) return;
      if (fallback && res.text === baselineText) return; // misma página de fallback
      if (!valid(res)) return;
      findings.push({
        check: 'routes',
        severity,
        title: `Ruta expuesta: ${path}`,
        detail: `${base}${path} respondió 200 con contenido que coincide con lo esperado. Revisa y retira el archivo/endpoint.`,
      });
    } catch {
      // timeout o error de red en una ruta suelta: no es un hallazgo
    }
  });

  await Promise.all(checks);

  if (fallback) {
    findings.push({
      check: 'routes',
      severity: 'info',
      title: 'El sitio responde 200 a rutas inexistentes (fallback de SPA)',
      detail: 'Normal en SPAs. Las rutas sensibles se validaron por contenido para evitar falsos positivos.',
    });
  }
  return findings;
}
