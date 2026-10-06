import { fetchSafe, readTextCapped } from '../utils/fetchSafe.js';

const MAX_TABLES = 50; // cap so a huge schema doesn't turn into hundreds of requests
const CONCURRENCY = 5;

const SENSITIVE_KEYWORDS = [
  'user', 'account', 'profile', 'payment', 'order', 'admin', 'token',
  'secret', 'email', 'password', 'session', 'subscription', 'invoice',
  'credit', 'card', 'address', 'phone', 'client', 'customer',
];

function severityForTable(tableName) {
  const lower = tableName.toLowerCase();
  return SENSITIVE_KEYWORDS.some((kw) => lower.includes(kw)) ? 'critical' : 'medium';
}

async function listTables(supabaseUrl, anonKey) {
  const res = await fetchSafe(`${supabaseUrl.replace(/\/$/, '')}/rest/v1/`, {
    headers: { apikey: anonKey, Accept: 'application/openapi+json' },
  });
  if (!res.ok) return [];
  const text = await readTextCapped(res);
  try {
    const spec = JSON.parse(text);
    return Object.keys(spec.paths || {})
      .map((p) => p.replace(/^\//, ''))
      .filter(Boolean)
      .slice(0, MAX_TABLES);
  } catch {
    return [];
  }
}

async function probeTable(supabaseUrl, anonKey, table) {
  const url = `${supabaseUrl.replace(/\/$/, '')}/rest/v1/${table}?select=*&limit=1`;
  try {
    const res = await fetchSafe(url, {
      headers: { apikey: anonKey, Authorization: `Bearer ${anonKey}` },
    });
    if (res.status === 401 || res.status === 403) return null; // protegida, bien
    if (!res.ok) return null;
    const text = await readTextCapped(res, 200_000);
    const body = JSON.parse(text || '[]');
    if (Array.isArray(body) && body.length > 0) {
      return table;
    }
    return null;
  } catch {
    return null;
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

/**
 * Checks whether Supabase tables return rows to an anonymous client with
 * no Authorization beyond the public anon key. This only calls the same
 * public REST endpoint any browser using the app already calls — it never
 * needs or accepts the service_role key.
 */
export async function checkSupabaseRLS(supabaseUrl, anonKey) {
  const findings = [];
  const tables = await listTables(supabaseUrl, anonKey);

  if (tables.length === 0) {
    findings.push({
      check: 'supabase',
      severity: 'info',
      title: 'No se encontraron tablas expuestas vía PostgREST',
      detail: 'Puede ser que el proyecto no exponga tablas públicamente, o que la URL/anon key no sean correctas.',
    });
    return findings;
  }

  const exposed = await mapWithConcurrency(tables, CONCURRENCY, (t) => probeTable(supabaseUrl, anonKey, t));

  for (const table of exposed.filter(Boolean)) {
    findings.push({
      check: 'supabase',
      severity: severityForTable(table),
      title: `Tabla "${table}" devuelve filas sin autenticación explícita`,
      detail: 'Un cliente anónimo con solo la anon key pública puede leer datos de esta tabla. Revisa las políticas de Row Level Security.',
    });
  }

  return findings;
}
