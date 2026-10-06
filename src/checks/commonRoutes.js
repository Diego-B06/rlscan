import { fetchSafe } from '../utils/fetchSafe.js';

// Rutas que no deberían responder 200 en producción. No es una lista
// exhaustiva de pentesting — es un chequeo rápido de errores comunes
// de despliegue en Vercel/Next.js.
const COMMON_PATHS = [
  '/.env',
  '/.env.local',
  '/.env.production',
  '/.git/config',
  '/api/debug',
  '/api/admin',
  '/api/internal',
  '/api/_internal',
  '/.vercel/output/config.json',
  '/wp-config.php', // casi nunca aplica, pero es gratis revisarlo
];

export async function checkCommonRoutes(baseUrl) {
  const findings = [];
  const base = baseUrl.replace(/\/$/, '');

  const checks = COMMON_PATHS.map(async (path) => {
    try {
      const res = await fetchSafe(`${base}${path}`, { timeoutMs: 5000 });
      if (res.status === 200) {
        findings.push({
          check: 'routes',
          severity: path.includes('.env') || path.includes('.git') ? 'critical' : 'medium',
          title: `Ruta expuesta: ${path}`,
          detail: `${base}${path} respondió 200. Confirma manualmente que no filtra información sensible.`,
        });
      }
    } catch {
      // timeout o error de red: se ignora, no es un hallazgo
    }
  });

  await Promise.all(checks);
  return findings;
}
