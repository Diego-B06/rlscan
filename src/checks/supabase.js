import { fetchText } from '../utils/fetchSafe.js';

const MAX_TABLES = 50; // tope para que un esquema enorme no se vuelva cientos de peticiones
const MAX_BUCKETS = 20;
const CONCURRENCY = 5;

const SENSITIVE_NAME_KEYWORDS = [
  'user', 'usuario', 'account', 'cuenta', 'profile', 'perfil', 'payment', 'pago', 'order', 'pedido',
  'admin', 'token', 'secret', 'email', 'correo', 'password', 'session', 'subscription', 'invoice',
  'factura', 'credit', 'card', 'tarjeta', 'address', 'direccion', 'phone', 'telefono', 'client',
  'cliente', 'customer', 'paciente', 'patient', 'employee', 'empleado',
];

// Palabras que, como PALABRA dentro del nombre de una columna (customer_email, billingAddress),
// escalan el hallazgo a crítico. Se compara por palabras para no marcar "telemetry" o "cardinality".
const SENSITIVE_COLUMN_WORDS = new Set([
  'email', 'emails', 'mail', 'correo', 'phone', 'telefono', 'tel', 'celular', 'mobile', 'whatsapp',
  'password', 'passwd', 'pwd', 'contrasena', 'hash', 'token', 'secret', 'apikey', 'address', 'direccion',
  'domicilio', 'dni', 'curp', 'rfc', 'ssn', 'nss', 'card', 'tarjeta', 'iban', 'clabe', 'birth', 'birthday',
  'birthdate', 'dob', 'nacimiento', 'salary', 'salario',
]);
const SENSITIVE_COLUMN_PHRASES = ['api_key', 'credit_card', 'e_mail'];

function words(name) {
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

export function isSensitiveColumn(name) {
  const w = words(name);
  const joined = w.join('_');
  return w.some((x) => SENSITIVE_COLUMN_WORDS.has(x)) || SENSITIVE_COLUMN_PHRASES.some((p) => joined.includes(p));
}

function isSensitiveTableName(table) {
  const lower = table.toLowerCase();
  return SENSITIVE_NAME_KEYWORDS.some((kw) => lower.includes(kw));
}

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

async function listSchema(supabaseUrl, anonKey) {
  try {
    const res = await fetchText(`${baseOf(supabaseUrl)}/rest/v1/`, {
      headers: { ...authHeaders(anonKey), Accept: 'application/openapi+json' },
    });
    if (!res.ok) return { tables: [], rpcs: [], status: res.status };
    const spec = JSON.parse(res.text);
    const paths = Object.keys(spec.paths || {}).map((p) => p.replace(/^\//, '')).filter(Boolean);
    return {
      tables: paths.filter((p) => !p.startsWith('rpc/')),
      rpcs: paths.filter((p) => p.startsWith('rpc/')).map((p) => p.slice(4)),
      status: 200,
    };
  } catch (err) {
    return { tables: [], rpcs: [], status: 0, error: err.message };
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
    if (!Array.isArray(body)) return { table, state: 'error', status: res.status };
    if (body.length > 0) {
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
  if (columns.some(isSensitiveColumn)) return 'critical';
  return isSensitiveTableName(table) ? 'critical' : 'medium';
}

const list = (arr, n = 10) => `${arr.slice(0, n).join(', ')}${arr.length > n ? '…' : ''}`;

/**
 * Storage: ¿anon puede listar buckets y los archivos dentro? Solo lectura: GET de buckets y
 * POST a /object/list (es una consulta de listado, no escribe). Nunca imprime nombres de archivos.
 */
async function checkStorage(supabaseUrl, anonKey) {
  const findings = [];
  const base = baseOf(supabaseUrl);
  let buckets;
  try {
    const res = await fetchText(`${base}/storage/v1/bucket`, { headers: authHeaders(anonKey), maxBytes: 500_000 });
    if (!res.ok) return findings; // lo normal: anon no puede listar buckets
    buckets = JSON.parse(res.text || '[]');
  } catch {
    return findings;
  }
  if (!Array.isArray(buckets) || buckets.length === 0) return findings;

  findings.push({
    check: 'supabase',
    severity: 'medium',
    title: `Un cliente anónimo puede listar los ${buckets.length} bucket(s) de Storage`,
    detail:
      `Buckets: ${list(buckets.map((b) => `${b.name || b.id}${b.public ? ' (público)' : ''}`))}. ` +
      'Revisa las políticas de RLS de storage.buckets si no quieres revelar esta información.',
  });

  const results = await mapWithConcurrency(buckets.slice(0, MAX_BUCKETS), CONCURRENCY, async (b) => {
    const id = b.id || b.name;
    try {
      const res = await fetchText(`${base}/storage/v1/object/list/${encodeURIComponent(id)}`, {
        method: 'POST',
        headers: { ...authHeaders(anonKey), 'Content-Type': 'application/json' },
        body: JSON.stringify({ prefix: '', limit: 1, offset: 0 }),
        maxBytes: 200_000,
      });
      if (!res.ok) return null;
      const items = JSON.parse(res.text || '[]');
      return Array.isArray(items) && items.length > 0 ? b : null;
    } catch {
      return null;
    }
  });

  for (const b of results.filter(Boolean)) {
    const name = b.name || b.id;
    findings.push({
      check: 'supabase',
      severity: b.public ? 'medium' : 'high',
      title: `Bucket "${name}" permite a un cliente anónimo listar sus archivos`,
      detail: b.public
        ? 'Es un bucket público: además de descargar por URL, cualquiera puede enumerar todos sus archivos. Restringe el listado en las políticas de storage.objects.'
        : 'Es un bucket PRIVADO, pero las políticas de storage.objects dejan que anon liste (y probablemente descargue) sus archivos. Revísalas.',
    });
  }
  return findings;
}

/**
 * Comprueba qué tablas devuelven filas a un cliente anónimo usando solo la anon key pública.
 * Solo lee (GET ... limit=1) y nunca registra valores, solo nombres de tabla y de columna.
 *
 * Si no se puede evaluar nada, el resultado es severidad "error" (exit 2) cuando el chequeo se
 * pidió explícitamente, para que un escaneo fallido nunca parezca aprobado. En modo autodetectado
 * baja a "medium": el usuario no pidió este chequeo y no debe romper su escaneo.
 */
export async function checkSupabaseRLS(supabaseUrl, anonKey, { tables: explicitTables = null, autodetected = false } = {}) {
  const findings = [];
  const failSeverity = autodetected ? 'medium' : 'error';
  let tables = explicitTables;
  let rpcs = [];

  if (!tables || tables.length === 0) {
    const listed = await listSchema(supabaseUrl, anonKey);
    tables = listed.tables;
    rpcs = listed.rpcs;
    if (tables.length === 0) {
      findings.push({
        check: 'supabase',
        severity: failSeverity,
        title: 'No se pudieron listar las tablas de Supabase',
        detail:
          `${listed.error ? `Error: ${listed.error}. ` : listed.status ? `/rest/v1/ respondió ${listed.status}. ` : ''}` +
          'Esto NO significa que no haya tablas expuestas: el esquema puede no ser público para la anon key, ' +
          'o la URL/llave son incorrectas. Pasa los nombres a revisar con --supabase-tables tabla1,tabla2.',
      });
      findings.push(...(await checkStorage(supabaseUrl, anonKey)));
      return findings;
    }
  }

  let truncated = false;
  if (tables.length > MAX_TABLES) {
    // Las de nombre sensible primero, para que el tope no deje fuera justo las importantes.
    tables = [...tables].sort((a, b) => Number(isSensitiveTableName(b)) - Number(isSensitiveTableName(a))).slice(0, MAX_TABLES);
    truncated = true;
  }

  const results = await mapWithConcurrency(tables, CONCURRENCY, (t) => probeTable(supabaseUrl, anonKey, t));

  for (const r of results.filter((x) => x.state === 'exposed')) {
    findings.push({
      check: 'supabase',
      severity: severityFor(r.table, r.columns),
      title: `Tabla "${r.table}" devuelve filas a un cliente anónimo`,
      detail: `Con solo la anon key pública se leen datos de esta tabla (columnas: ${list(r.columns, 8)}). ` +
        'Si no es pública a propósito, revisa sus políticas de Row Level Security.',
    });
  }

  const blocked = results.filter((x) => x.state === 'blocked');
  const errored = results.filter((x) => x.state === 'error');
  const evaluated = results.length - blocked.length - errored.length;

  if (evaluated === 0) {
    findings.push({
      check: 'supabase',
      severity: failSeverity,
      title: 'No se pudo evaluar ninguna tabla de Supabase',
      detail:
        (blocked.length ? `${blocked.length} respondieron 401/403 (¿anon key inválida o expirada?). ` : '') +
        (errored.length ? `${errored.length} fallaron (error del servidor, respuesta inválida o timeout). ` : '') +
        'Sin ninguna tabla evaluada, "sin hallazgos" no sería un resultado confiable.',
    });
  } else if (errored.length > 0) {
    findings.push({
      check: 'supabase',
      severity: 'medium',
      title: `${errored.length} tabla(s) no se pudieron evaluar`,
      detail: `Fallaron con error del servidor, respuesta inválida o timeout: ${list(errored.map((x) => `${x.table}${x.status ? ` (${x.status})` : ''}`))}. Su RLS queda sin verificar.`,
    });
  }

  const empty = results.filter((x) => x.state === 'empty').map((x) => x.table);
  if (empty.length > 0) {
    findings.push({
      check: 'supabase',
      severity: 'info',
      title: `${empty.length} tabla(s) respondieron vacías: no se puede verificar su RLS`,
      detail: `Con la anon key, una tabla protegida por RLS y una tabla vacía sin RLS se ven igual (lista vacía). ` +
        `Revísalas en el panel de Supabase: ${list(empty)}.`,
    });
  }

  if (rpcs.length > 0) {
    findings.push({
      check: 'supabase',
      severity: 'info',
      title: `${rpcs.length} función(es) RPC visibles para un cliente anónimo (no se invocaron)`,
      detail: `${list(rpcs)}. Si alguna es SECURITY DEFINER, se ejecuta saltándose RLS: verifica que no expongan ` +
        'ni modifiquen datos, o revoca EXECUTE para anon.',
    });
  }

  if (truncated) {
    findings.push({
      check: 'supabase',
      severity: 'info',
      title: `Solo se probaron ${MAX_TABLES} tablas (primero las de nombre sensible)`,
      detail: 'Usa --supabase-tables para revisar tablas específicas.',
    });
  }

  findings.push(...(await checkStorage(supabaseUrl, anonKey)));
  return findings;
}
