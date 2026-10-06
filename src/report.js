const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

const COLORS = {
  critical: '\x1b[41m\x1b[97m', // fondo rojo, texto blanco
  high: '\x1b[31m', // rojo
  medium: '\x1b[33m', // amarillo
  low: '\x1b[36m', // cian
  info: '\x1b[90m', // gris
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

const LABELS = {
  critical: 'CRÍTICO',
  high: 'ALTO',
  medium: 'MEDIO',
  low: 'BAJO',
  info: 'INFO',
};

export function printReport(findings, { json = false } = {}) {
  if (json) {
    console.log(JSON.stringify({ findings }, null, 2));
    return;
  }

  if (findings.length === 0) {
    console.log(`${COLORS.low}No se encontraron hallazgos con los checks disponibles.${RESET}`);
    console.log('Esto no significa que el sistema esté 100% seguro — significa que estos checks puntuales no encontraron nada.');
    return;
  }

  const grouped = SEVERITY_ORDER.map((sev) => ({
    sev,
    items: findings.filter((f) => f.severity === sev),
  })).filter((g) => g.items.length > 0);

  for (const { sev, items } of grouped) {
    console.log(`\n${COLORS[sev]}${BOLD} ${LABELS[sev]} (${items.length}) ${RESET}`);
    for (const item of items) {
      console.log(`  ${BOLD}•${RESET} ${item.title}`);
      if (item.detail) console.log(`    ${item.detail}`);
    }
  }

  const counts = SEVERITY_ORDER.map((sev) => `${LABELS[sev]}: ${findings.filter((f) => f.severity === sev).length}`).join('  ');
  console.log(`\n${BOLD}Resumen${RESET} — ${counts}`);
}

export function exitCodeFor(findings) {
  const hasBlocking = findings.some((f) => f.severity === 'critical' || f.severity === 'high');
  return hasBlocking ? 1 : 0;
}
