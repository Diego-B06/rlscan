import { readFileSync } from 'node:fs';
import { Command, Option, InvalidArgumentError } from 'commander';
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

function positiveInt(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) throw new InvalidArgumentError('debe ser un entero positivo.');
  return n;
}

export async function run(argv) {
  const program = new Command();

  program
    .name('rlscan')
    .version(version)
    .description('Escáner de seguridad de solo lectura para apps en Vercel + Supabase.')
    .argument('<url>', 'URL de la app desplegada (ej. https://mi-app.vercel.app)')
    .addOption(new Option('--supabase-url <url>', 'URL del proyecto de Supabase (ej. https://xyzcompany.supabase.co)').env('SUPABASE_URL'))
    .addOption(
      new Option('--supabase-anon-key <key>', 'Anon/publishable key de Supabase (nunca uses la service_role key aquí)').env('SUPABASE_ANON_KEY'),
    )
    .option('--supabase-tables <lista>', 'Tablas a probar, separadas por coma (omite el listado automático)')
    .option('--no-supabase-autodetect', 'No revisar RLS con el proyecto y la anon key detectados en los bundles del sitio')
    .option('--max-files <n>', 'Máximo de archivos JS a escanear en busca de secretos', positiveInt, 80)
    .option('--no-routes', 'Omite el chequeo de rutas comunes expuestas (.env, /api/debug, etc.)')
    .option('--json', 'Imprime el resultado en JSON en vez de reporte coloreado')
    .option('--no-color', 'Desactiva los colores')
    .option('--fail-on-high', 'Sale con código 1 si hay hallazgos CRÍTICOS o ALTOS (útil en CI)')
    .addHelpText('after', `\n${DISCLAIMER}`)
    .exitOverride();

  try {
    program.parse(argv);
  } catch (err) {
    // --help / --version terminan bien; cualquier error de argumentos es "no se pudo escanear" (2),
    // nunca 1, que en CI significa "hay hallazgos".
    process.exitCode = err.code === 'commander.helpDisplayed' || err.code === 'commander.version' ? 0 : 2;
    return;
  }

  const opts = program.opts();
  const target = normalizeTargetUrl(program.args[0]);
  if (target.error) return fail(target.error, opts.json);
  const url = target.url;

  let supabaseUrl = null;
  if (opts.supabaseUrl) {
    const sb = normalizeTargetUrl(opts.supabaseUrl);
    if (sb.error) return fail(`--supabase-url: ${sb.error}`, opts.json);
    supabaseUrl = sb.url;
  }

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
  const findings = [...headerResult.findings];
  let detected = null;

  if (headerResult.reachable) {
    const [secretResult, routeFindings] = await Promise.all([
      scanForSecrets(headerResult.finalUrl || url, { html: headerResult.html, maxFiles: opts.maxFiles }),
      opts.routes === false ? Promise.resolve([]) : checkCommonRoutes(headerResult.finalUrl || url),
    ]);
    findings.push(...secretResult.findings, ...routeFindings);
    detected = secretResult.supabase;
  }
  // Sitio inalcanzable o bloqueado: el hallazgo "error" ya garantiza exit 2 (nunca parece aprobado).
  // Si el usuario pidió Supabase explícitamente, se revisa igual: no depende del sitio.

  const tables = opts.supabaseTables ? opts.supabaseTables.split(',').map((t) => t.trim()).filter(Boolean) : null;
  const codeTables = detected?.tables || [];

  if (supabaseUrl && opts.supabaseAnonKey) {
    findings.push(...(await checkSupabaseRLS(supabaseUrl, opts.supabaseAnonKey, { tables, fallbackTables: codeTables })));
  } else if (supabaseUrl || opts.supabaseAnonKey) {
    const src = (k, flag, env) => (program.getOptionValueSource(k) === 'env' ? `la variable de entorno ${env}` : flag);
    const given = supabaseUrl ? src('supabaseUrl', '--supabase-url', 'SUPABASE_URL') : src('supabaseAnonKey', '--supabase-anon-key', 'SUPABASE_ANON_KEY');
    const missing = supabaseUrl ? '--supabase-anon-key (o SUPABASE_ANON_KEY)' : '--supabase-url (o SUPABASE_URL)';
    // Pedido a mano a medias = error de uso (exit 2). Si viene solo de una variable de entorno
    // suelta (p. ej. SUPABASE_URL en el shell de desarrollo), solo se avisa.
    const fromCli = ['supabaseUrl', 'supabaseAnonKey'].some((k) => program.getOptionValueSource(k) === 'cli');
    findings.push({
      check: 'supabase',
      severity: fromCli ? 'error' : 'info',
      title: 'Chequeo de Supabase incompleto',
      detail: `Se recibió ${given}, pero falta ${missing}. Se necesitan las dos para revisar RLS.`,
    });
  } else if (opts.supabaseAutodetect !== false && detected?.url && detected.anonKey) {
    findings.push({
      check: 'supabase',
      severity: 'info',
      title: `Supabase detectado en los bundles: ${detected.url}`,
      detail:
        'Se revisó su RLS con la anon key pública que el propio sitio entrega a cada visitante' +
        `${detected.projects > 1 ? ` (se encontraron ${detected.projects} proyectos; se usó el que tiene llave)` : ''}. ` +
        'Desactívalo con --no-supabase-autodetect.',
    });
    findings.push(...(await checkSupabaseRLS(detected.url, detected.anonKey, { tables, fallbackTables: codeTables, autodetected: true })));
  } else if (detected?.url) {
    findings.push({
      check: 'supabase',
      severity: 'info',
      title: `Supabase detectado en los bundles (${detected.url}), sin anon key identificable`,
      detail: 'Pasa --supabase-url y --supabase-anon-key para revisar su RLS.',
    });
  }

  printReport(findings, { json: opts.json, noColor: opts.color === false, meta: { tool: 'rlscan', version, target: url } });
  process.exitCode = exitCodeFor(findings, { failOnHigh: opts.failOnHigh });
}
