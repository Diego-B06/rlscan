const SEVERITY_ORDER = ['error', 'critical', 'high', 'medium', 'low', 'info'];

const COLORS = {
  error: '\x1b[41m\x1b[97m',
  critical: '\x1b[41m\x1b[97m', // fondo rojo, texto blanco
  high: '\x1b[31m', // rojo
  medium: '\x1b[33m', // amarillo
  low: '\x1b[36m', // cian
  info: '\x1b[90m', // gris
};

const LABELS = {
  error: 'ERROR',
  critical: 'CRÍTICO',
  high: 'ALTO',
  medium: 'MEDIO',
  low: 'BAJO',
  info: 'INFO',
};

// Sin colores si no es una terminal, si NO_COLOR está definido o con --no-color.
function useColor(noColor) {
  return !noColor && !process.env.NO_COLOR && Boolean(process.stdout.isTTY);
}

export function summarize(findings) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return counts;
}

export function printReport(findings, { json = false, noColor = false, meta = {} } = {}) {
  if (json) {
    console.log(JSON.stringify({ ...meta, summary: summarize(findings), findings }, null, 2));
    return;
  }

  const c = useColor(noColor);
  const paint = (sev, s) => (c ? `${COLORS[sev]}${s}\x1b[0m` : s);
  const bold = (s) => (c ? `\x1b[1m${s}\x1b[0m` : s);

  if (findings.length === 0) {
    console.log(paint('low', 'No se encontraron hallazgos con los checks disponibles.'));
    console.log('Esto no significa que el sistema esté 100% seguro — significa que estos checks puntuales no encontraron nada.');
    return;
  }

  for (const sev of SEVERITY_ORDER) {
    const items = findings.filter((f) => f.severity === sev);
    if (items.length === 0) continue;
    console.log(`\n${paint(sev, bold(` ${LABELS[sev]} (${items.length}) `))}`);
    for (const item of items) {
      console.log(`  ${bold('•')} ${item.title}`);
      if (item.detail) console.log(`    ${item.detail}`);
    }
  }

  const counts = summarize(findings);
  const line = SEVERITY_ORDER.filter((s) => s !== 'error' || counts.error)
    .map((s) => `${LABELS[s]}: ${counts[s]}`)
    .join('  ');
  console.log(`\n${bold('Resumen')} — ${line}`);
}

/**
 * Códigos de salida:
 *   0  sin hallazgos bloqueantes (o sin --fail-on-high)
 *   1  --fail-on-high y hay hallazgos CRÍTICOS o ALTOS
 *   2  no se pudo completar el escaneo (sitio inalcanzable, argumentos inválidos, llave rechazada)
 */
export function exitCodeFor(findings, { failOnHigh = false } = {}) {
  if (findings.some((f) => f.severity === 'error')) return 2;
  if (failOnHigh && findings.some((f) => f.severity === 'critical' || f.severity === 'high')) return 1;
  return 0;
}
