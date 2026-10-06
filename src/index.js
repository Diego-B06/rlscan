import { readFileSync } from 'node:fs';
import { Command } from 'commander';
import { checkHeaders } from './checks/headers.js';
import { scanForSecrets } from './checks/secrets.js';
import { checkSupabaseRLS, decodeKeyRole } from './checks/supabase.js';
import { checkCommonRoutes } from './checks/commonRoutes.js';
import { printReport, exitCodeFor } from './report.js';
import { normalizeTargetUrl } from './utils/fetchSafe.js';

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const DISCLAIMER = `
rlscan solo debe correrse contra aplicaciones que te pertenecen o que
tienes autorización explícita para evaluar. Todos los checks son de solo
lectura: cabeceras HTTP públicas, archivos JS que el sitio ya le sirve a
cualquier visitante, y lecturas vía la anon key pública de Supabase (la
misma que tu app ya expone en el navegador). Esta herramienta no explota
nada ni modifica datos.

Códigos de salida: 0 = ok · 1 = hallazgos críticos/altos (con --fail-on-high)
· 2 = no se pudo completar el escaneo.
`.trim();

function fail(message, json) {
  const finding = { check: 'scan', severity: 'error', title: 'No se pudo iniciar el escaneo', detail: message };
  printReport([finding], { json, meta: { tool: 'rlscan', version } });
  process.exitCode = 2;
}

export async function run(argv) {
  const program = new Command();

  program
    .name('rlscan')
    .version(version)
    .description('Escáner de seguridad de solo lectura para apps en Vercel + Supabase/Firebase.')
    .argument('<url>', 'URL de la app desplegada (ej. https://mi-app.vercel.app)')
    .option('--supabase-url <url>', 'URL del proyecto de Supabase (ej. https://xyzcompany.supabase.co)')
    .option('--supabase-anon-key <key>', 'Anon/public key de Supabase (nunca uses la service_role key aquí)')
    .option('--supabase-tables <lista>', 'Tablas a probar, separadas por coma (omite el listado automático)')
    .option('--max-files <n>', 'Máximo de archivos JS a escanear en busca de secretos', (v) => parseInt(v, 10), 80)
    .option('--no-routes', 'Omite el chequeo de rutas comunes expuestas (.env, /api/debug, etc.)')
    .option('--json', 'Imprime el resultado en JSON en vez de reporte coloreado')
    .option('--no-color', 'Desactiva los colores')
    .option('--fail-on-high', 'Sale con código 1 si hay hallazgos CRÍTICOS o ALTOS (útil en CI)')
    .addHelpText('after', `\n${DISCLAIMER}`)
    .parse(argv);

  const opts = program.opts();
  const target = normalizeTargetUrl(program.args[0]);
  if (target.error) return fail(target.error, opts.json);
  const url = target.url;

  // Salvaguarda: la service_role se salta RLS y daría falsos positivos (además de ser una llave secreta).
  if (opts.supabaseAnonKey && decodeKeyRole(opts.supabaseAnonKey) === 'service_role') {
    return fail(
      'La llave pasada en --supabase-anon-key es una service_role/secret key. Rechazada: ' +
        'se salta Row Level Security y no debe usarse ni compartirse. Usa la anon/publishable key y rota la que pegaste.',
      opts.json,
    );
  }

  if (!opts.json) {
    console.log(DISCLAIMER);
    console.log(`\nEscaneando ${url} ${target.assumedHttps ? '(se asumió https://) ' : ''}...\n`);
  }

  // 1) La página principal se baja una sola vez: cabeceras + HTML reutilizado para secretos.
  const headerResult = await checkHeaders(url);
  if (!headerResult.reachable) {
    // Sitio inalcanzable: no tiene sentido seguir, y NO debe parecer "aprobado".
    printReport(headerResult.findings, { json: opts.json, noColor: opts.color === false, meta: { tool: 'rlscan', version, target: url } });
    process.exitCode = 2;
    return;
  }

  const findings = [...headerResult.findings];

  const [secretResult, routeFindings] = await Promise.all([
    scanForSecrets(headerResult.finalUrl || url, { html: headerResult.html, maxFiles: opts.maxFiles }),
    opts.routes === false ? Promise.resolve([]) : checkCommonRoutes(headerResult.finalUrl || url),
  ]);
  findings.push(...secretResult.findings, ...routeFindings);

  if (opts.supabaseUrl && opts.supabaseAnonKey) {
    const tables = opts.supabaseTables ? opts.supabaseTables.split(',').map((t) => t.trim()).filter(Boolean) : null;
    findings.push(...(await checkSupabaseRLS(opts.supabaseUrl, opts.supabaseAnonKey, { tables })));
  } else if (opts.supabaseUrl || opts.supabaseAnonKey) {
    findings.push({
      check: 'supabase',
      severity: 'info',
      title: 'Chequeo de Supabase omitido',
      detail: 'Pasa --supabase-url y --supabase-anon-key juntos para habilitar el chequeo de RLS.',
    });
  }

  printReport(findings, { json: opts.json, noColor: opts.color === false, meta: { tool: 'rlscan', version, target: url } });
  process.exitCode = exitCodeFor(findings, { failOnHigh: opts.failOnHigh });
}
