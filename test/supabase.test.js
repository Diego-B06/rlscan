import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkSupabaseRLS, decodeKeyRole } from '../src/checks/supabase.js';
import { startServer, send, fakeJwt } from './helpers.js';

/** PostgREST simulado: customers (filas, sin RLS), orders (RLS bloquea => []), secret (401), products (público), vacia (sin RLS, vacía). */
function postgrest({ specStatus = 200, tableStatus = {} } = {}) {
  const data = {
    customers: [{ id: 1, email: 'a@x.com', phone: '555' }],
    orders_protected: [],
    products: [{ id: 1, name: 'Camisa', price: 1 }],
    invoices_empty: [],
  };
  return startServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/rest/v1/') {
      if (specStatus !== 200) return send(res, specStatus, '');
      const paths = Object.fromEntries(['/', ...Object.keys(data).map((t) => `/${t}`), '/rpc/mi_funcion'].map((p) => [p, {}]));
      return send(res, 200, JSON.stringify({ paths }), { 'Content-Type': 'application/json' });
    }
    const table = u.pathname.replace('/rest/v1/', '');
    if (tableStatus[table]) return send(res, tableStatus[table], '');
    return send(res, 200, JSON.stringify(data[table] ?? []), { 'Content-Type': 'application/json' });
  });
}
const KEY = fakeJwt('anon');

test('supabase: marca customers (crítico por columnas), products (medio); no marca RLS bien configurado ni vacías', async () => {
  const srv = await postgrest();
  const f = await checkSupabaseRLS(srv.url, KEY);
  const byTable = Object.fromEntries(f.filter((x) => x.title.startsWith('Tabla')).map((x) => [x.title.match(/"(.+?)"/)[1], x.severity]));
  assert.deepEqual(byTable, { customers: 'critical', products: 'medium' });
  assert.ok(!JSON.stringify(f).includes('a@x.com'), 'nunca se imprimen valores');
  const empty = f.find((x) => x.severity === 'info');
  assert.match(empty.detail, /invoices_empty/);
  assert.match(empty.detail, /orders_protected/);
  assert.ok(!JSON.stringify(f).includes('rpc/'), 'las funciones rpc no se prueban como tablas');
  await srv.close();
});

test('supabase: spec bloqueado => advertencia honesta (no "no hay tablas") y --supabase-tables funciona', async () => {
  const srv = await postgrest({ specStatus: 401 });
  const warn = await checkSupabaseRLS(srv.url, KEY);
  assert.equal(warn[0].severity, 'medium');
  assert.match(warn[0].detail, /NO significa/);
  assert.match(warn[0].detail, /--supabase-tables/);
  const manual = await checkSupabaseRLS(srv.url, KEY, { tables: ['customers'] });
  assert.ok(manual.some((x) => x.title.includes('customers')));
  await srv.close();
});

test('supabase: todas las tablas 401 => avisa que la llave puede ser inválida', async () => {
  const srv = await postgrest({ tableStatus: { customers: 401, orders_protected: 401, products: 401, invoices_empty: 401 } });
  const f = await checkSupabaseRLS(srv.url, KEY);
  assert.ok(f.some((x) => /inválida/i.test(x.title)));
  await srv.close();
});

test('decodeKeyRole detecta service_role (JWT y sb_secret_) y anon', () => {
  assert.equal(decodeKeyRole(fakeJwt('service_role')), 'service_role');
  assert.equal(decodeKeyRole('sb_secret_abc'), 'service_role');
  assert.equal(decodeKeyRole(fakeJwt('anon')), 'anon');
  assert.equal(decodeKeyRole('sb_publishable_abc'), 'anon');
  assert.equal(decodeKeyRole('basura'), null);
});
