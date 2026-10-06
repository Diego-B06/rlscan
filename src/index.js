import { Command } from 'commander';
import { checkHeaders } from './checks/headers.js';
import { scanForSecrets } from './checks/secrets.js';
import { checkSupabaseRLS } from './checks/supabase.js';
import { checkCommonRoutes } from './checks/commonRoutes.js';
import { printReport, exitCodeFor } from './report.js';

const DISCLAIMER = `
rlscan solo debe correrse contra aplicaciones que te pertenecen o que
tienes autorización explícita para evaluar. Todos los checks son de solo
lectura: cabeceras HTTP públicas, archivos JS que el sitio ya le sirve a
cualquier visitante, y lecturas vía la anon key pública de Supabase (la
misma que tu app ya expone en el navegador). Esta herramienta no explota
nada ni modifica datos.
`.trim();

export async function run(argv) {
  const program = new Command();

  program
    .name('rlscan')
    .description('Escáner de seguridad de solo lectura para apps en Vercel + Supabase/Firebase.')
    .argument('<url>', 'URL de la app desplegada (ej. https://mi-app.vercel.app)')
    .option('--supabase-url <url>', 'URL del proyecto de Supabase (ej. https://xyzcompany.supabase.co)')
    .option('--supabase-anon-key <key>', 'Anon/public key de Supabase (nunca uses la service_role key aquí)')
    .option('--no-routes', 'Omite el chequeo de rutas comunes expuestas (.env, /api/debug, etc.)')
    .option('--json', 'Imprime el resultado en JSON en vez de reporte coloreado')
    .option('--fail-on-high', 'Sale con código distinto de 0 si hay hallazgos CRÍTICOS o ALTOS (útil en CI)')
    .addHelpText('after', `\n${DISCLAIMER}`)
    .parse(argv);

  const opts = program.opts();
  const [url] = program.args;

  if (!opts.json) {
    console.log(DISCLAIMER);
    console.log(`\nEscaneando ${url} ...\n`);
  }

  const findings = [];

  const [headerFindings, secretFindings, routeFindings] = await Promise.all([
    checkHeaders(url),
    scanForSecrets(url),
    opts.routes === false ? Promise.resolve([]) : checkCommonRoutes(url),
  ]);
  findings.push(...headerFindings, ...secretFindings, ...routeFindings);

  if (opts.supabaseUrl && opts.supabaseAnonKey) {
    const supabaseFindings = await checkSupabaseRLS(opts.supabaseUrl, opts.supabaseAnonKey);
    findings.push(...supabaseFindings);
  } else if (opts.supabaseUrl || opts.supabaseAnonKey) {
    findings.push({
      check: 'supabase',
      severity: 'info',
      title: 'Chequeo de Supabase omitido',
      detail: 'Pasa --supabase-url y --supabase-anon-key juntos para habilitar el chequeo de RLS.',
    });
  }

  printReport(findings, { json: opts.json });

  if (opts.failOnHigh) {
    process.exitCode = exitCodeFor(findings);
  }
}
