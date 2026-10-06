import { fetchText } from '../utils/fetchSafe.js';

const MAX_TABLES = 50; // tope para que un esquema enorme no se vuelva cientos de peticiones
const CONCURRENCY = 5;

const SENSITIVE_NAME_KEYWORDS = [
  'user', 'usuario', 'account', 'cuenta', 'profile', 'perfil', 'payment', 'pago', 'order', 'pedido',
  'admin', 'token', 'secret', 'email', 'correo', 'password', 'session', 'subscription', 'invoice',
  'factura', 'credit', 'card', 'tarjeta', 'address', 'direccion', 'phone', 'telefono', 'client',
  'cliente', 'customer', 'paciente', 'patient', 'employee', 'empleado',
];
// Columnas que, de estar presentes en filas legibles por anon, escalan el hallazgo a crítico.
const SENSITIVE_COLUMNS = /^(e?-?mail|correo|phone|telefono|tel|password|passwd|hash|token|secret|api_?key|address|direccion|dni|curp|rfc|ssn|card|iban|birth|birthday|nacimiento)/i;

function baseOf(supabaseUrl) {
  return supabaseUrl.replace(/\/$/, '');
}

export function decodeKeyRole(key) {
  if (/^sb_secret_/.test(key)) return 'service_role';
  if (/^sb_publishable_/.test(key)) return 'anon';
  try {
    const payload = key.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const json = Buffer.from(payload + '='.repeat((4 - (payload.length % 4)) % 4), 'base64').toString('utf8');
    return JSON.parse(json).role || null;
  } catch {
    return null;
  }
}

function authHeaders(anonKey) {
  const h = { apikey: anonKey };
  // Las llaves nuevas (sb_publishable_) no son JWT: no van en Authorization.
  if (!/^sb_/.test(anonKey)) h.Authorization = `Bearer ${anonKey}`;
  return h;
}

async function listTables(supabaseUrl, anonKey) {
  try {
    const res = await fetchText(`${baseOf(supabaseUrl)}/rest/v1/`, {
      headers: { ...authHeaders(anonKey), Accept: 'application/openapi+json' },
    });
    if (!res.ok) return { tables: [], status: res.status };
    const spec = JSON.parse(res.text);
    const all = Object.keys(spec.paths || {})
      .map((p) => p.replace(/^\//, ''))
      .filter((p) => p && !p.startsWith('rpc/')); // funciones, no tablas
    return { tables: all, status: 200 };
  } catch (err) {
    return { tables: [], status: 0, error: err.message };
  }
}

/** @returns {{table, state: 'exposed'|'empty'|'blocked'|'error', columns?: string[], status?: number}} */
async function probeTable(supabaseUrl, anonKey, table) {
  try {
    const res = await fetchText(`${baseOf(supabaseUrl)}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, {
      headers: authHeaders(anonKey),
      maxBytes: 200_000,
    });
    if (res.status === 401 || res.status === 403) return { table, state: 'blocked', status: res.status };
    if (!res.ok) return { table, state: 'error', status: res.status };
    const body = JSON.parse(res.text || '[]');
    if (Array.isArray(body) && body.length > 0) {
      return { table, state: 'exposed', columns: Object.keys(body[0] || {}) }; // solo nombres de columnas, nunca valores
    }
    return { table, state: 'empty' };
  } catch {
    return { table, state: 'error', status: 0 };
  }
}

async function mapWithConcurrency(items, limit, worker) {
  const results = [];
  let i = 0;
  async function next() {
    while (i < items.length) {
      const idx = i++;
      results[idx] = await worker(items[idx]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, next));
  return results;
}

function severityFor(table, columns) {
  if (columns.some((c) => SENSITIVE_COLUMNS.test(c))) return 'critical';
  const lower = table.toLowerCase();
  return SENSITIVE_NAME_KEYWORDS.some((kw) => lower.includes(kw)) ? 'critical' : 'medium';
}

/**
 * Comprueba qué tablas devuelven filas a un cliente anónimo usando solo la anon key pública.
 * Solo lee (GET ... limit=1) y nunca registra valores, solo nombres de tabla y de columna.
 */
export async function checkSupabaseRLS(supabaseUrl, anonKey, { tables: explicitTables = null } = {}) {
  const findings = [];
  let tables = explicitTables;

  if (!tables || tables.length === 0) {
    const listed = await listTables(supabaseUrl, anonKey);
    tables = listed.tables;
    if (tables.length === 0) {
      findings.push({
        check: 'supabase',
        severity: 'medium',
        title: 'No se pudieron listar las tablas de Supabase',
        detail:
          `${listed.error ? `Error: ${listed.error}. ` : listed.status ? `/rest/v1/ respondió ${listed.status}. ` : ''}` +
          'Esto NO significa que no haya tablas expuestas: el esquema puede no ser público para la anon key, ' +
          'o la URL/llave son incorrectas. Pasa los nombres a revisar con --supabase-tables tabla1,tabla2.',
      });
      return findings;
    }
  }

  let truncated = false;
  if (tables.length > MAX_TABLES) {
    tables = tables.slice(0, MAX_TABLES);
    truncated = true;
  }

  const results = await mapWithConcurrency(tables, CONCURRENCY, (t) => probeTable(supabaseUrl, anonKey, t));

  for (const r of results.filter((x) => x.state === 'exposed')) {
    findings.push({
      check: 'supabase',
      severity: severityFor(r.table, r.columns),
      title: `Tabla "${r.table}" devuelve filas a un cliente anónimo`,
      detail: `Con solo la anon key pública se leen datos de esta tabla (columnas: ${r.columns.slice(0, 8).join(', ')}${r.columns.length > 8 ? '…' : ''}). ` +
        'Si no es pública a propósito, revisa sus políticas de Row Level Security.',
    });
  }

  const blocked = results.filter((x) => x.state === 'blocked');
  if (blocked.length === results.length) {
    findings.push({
      check: 'supabase',
      severity: 'medium',
      title: 'Todas las tablas respondieron 401/403: la llave podría ser inválida',
      detail: 'Si la anon key es incorrecta o expiró, el escaneo no puede evaluar nada y el resultado "sin hallazgos" no sería confiable. Verifica la llave.',
    });
  }

  const empty = results.filter((x) => x.state === 'empty').map((x) => x.table);
  if (empty.length > 0) {
    findings.push({
      check: 'supabase',
      severity: 'info',
      title: `${empty.length} tabla(s) respondieron vacías: no se puede verificar su RLS`,
      detail: `Con la anon key, una tabla protegida por RLS y una tabla vacía sin RLS se ven igual (lista vacía). ` +
        `Revísalas en el panel de Supabase: ${empty.slice(0, 10).join(', ')}${empty.length > 10 ? '…' : ''}.`,
    });
  }

  if (truncated) {
    findings.push({
      check: 'supabase',
      severity: 'info',
      title: `Solo se probaron las primeras ${MAX_TABLES} tablas`,
      detail: 'Usa --supabase-tables para revisar tablas específicas.',
    });
  }

  return findings;
}
