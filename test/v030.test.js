import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkSupabaseRLS, isSensitiveColumn } from '../src/checks/supabase.js';
import { scanForSecrets } from '../src/checks/secrets.js';
import { checkCommonRoutes } from '../src/checks/commonRoutes.js';
import { startServer, send, fakeJwt } from './helpers.js';

const KEY = fakeJwt('anon');
const js = { 'Content-Type': 'application/javascript' };
const html = { 'Content-Type': 'text/html' };

// ---------- Supabase ----------

test('columnas sensibles: se comparan por palabra', () => {
  for (const c of ['email', 'customer_email', 'billingAddress', 'contact_phone', 'api_key', 'apiKey', 'password_hash', 'fecha_nacimiento', 'CURP'])
    assert.ok(isSensitiveColumn(c), c);
  for (const c of ['telemetry', 'cardinality', 'id', 'created_at', 'name', 'mailbox_size_total', 'hashtag'])
    assert.ok(!isSensitiveColumn(c), c);
});

function rest(handler) {
  return startServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname.startsWith('/storage/')) return send(res, 400, '');
    return handler(u, req, res);
  });
}

test('supabase: si TODAS las tablas fallan ya no es silencio: error (explícito) / medio (autodetectado)', async () => {
  const srv = await rest((u, req, res) => {
    if (u.pathname === '/rest/v1/') return send(res, 200, JSON.stringify({ paths: { '/a': {}, '/b': {} } }));
    return send(res, 500, 'boom');
  });
  const f = await checkSupabaseRLS(srv.url, KEY);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'error');
  assert.match(f[0].title, /ninguna tabla/);
  const auto = await checkSupabaseRLS(srv.url, KEY, { autodetected: true });
  assert.equal(auto[0].severity, 'medium');
  await srv.close();
});

test('supabase: respuesta que no es arreglo cuenta como fallo, no como "vacía"', async () => {
  const srv = await rest((u, req, res) => send(res, 200, '{"oops":true}'));
  const f = await checkSupabaseRLS(srv.url, KEY, { tables: ['x'] });
  assert.equal(f[0].severity, 'error');
  await srv.close();
});

test('supabase: fallos parciales se listan en medio', async () => {
  const srv = await rest((u, req, res) => {
    if (u.pathname === '/rest/v1/ok') return send(res, 200, '[]');
    return send(res, 502, '');
  });
  const f = await checkSupabaseRLS(srv.url, KEY, { tables: ['ok', 'rota'] });
  const m = f.find((x) => x.severity === 'medium');
  assert.match(m.title, /1 tabla/);
  assert.match(m.detail, /rota \(502\)/);
  assert.ok(!f.some((x) => x.severity === 'error'));
  await srv.close();
});

test('supabase: con más de 50 tablas se prueban primero las de nombre sensible', async () => {
  const probed = [];
  const names = [...Array.from({ length: 60 }, (_, i) => `t${i}`), 'customers'];
  const srv = await rest((u, req, res) => {
    if (u.pathname === '/rest/v1/') return send(res, 200, JSON.stringify({ paths: Object.fromEntries(names.map((n) => [`/${n}`, {}])) }));
    probed.push(u.pathname.split('/').pop());
    return send(res, 200, '[]');
  });
  await checkSupabaseRLS(srv.url, KEY);
  assert.equal(probed.length, 50);
  assert.ok(probed.includes('customers'));
  await srv.close();
});

test('supabase: lista funciones RPC sin invocarlas', async () => {
  const calls = [];
  const srv = await rest((u, req, res) => {
    calls.push(u.pathname);
    if (u.pathname === '/rest/v1/') return send(res, 200, JSON.stringify({ paths: { '/t': {}, '/rpc/borrar_todo': {} } }));
    return send(res, 200, '[]');
  });
  const f = await checkSupabaseRLS(srv.url, KEY);
  assert.ok(f.some((x) => x.severity === 'info' && x.detail.includes('borrar_todo')));
  assert.ok(!calls.some((c) => c.includes('rpc')), 'nunca se llama a una RPC');
  await srv.close();
});

test('supabase storage: buckets listables y bucket privado enumerable (alto); nunca nombres de archivo', async () => {
  const methods = [];
  const srv = await startServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname.startsWith('/storage/')) methods.push(req.method);
    if (u.pathname === '/storage/v1/bucket')
      return send(res, 200, JSON.stringify([{ id: 'avatars', name: 'avatars', public: true }, { id: 'facturas', name: 'facturas', public: false }, { id: 'vacio', name: 'vacio', public: false }]));
    if (u.pathname === '/storage/v1/object/list/facturas') return send(res, 200, JSON.stringify([{ name: 'factura-cliente-123.pdf' }]));
    if (u.pathname === '/storage/v1/object/list/avatars') return send(res, 200, JSON.stringify([{ name: 'yo.png' }]));
    if (u.pathname.startsWith('/storage/v1/object/list/')) return send(res, 200, '[]');
    return send(res, 200, '[]');
  });
  const f = await checkSupabaseRLS(srv.url, KEY, { tables: ['t'] });
  const s = f.filter((x) => /bucket/i.test(x.title));
  assert.ok(s.some((x) => x.severity === 'medium' && /listar los 3 bucket/.test(x.title)));
  assert.ok(s.some((x) => x.severity === 'high' && x.title.includes('"facturas"')));
  assert.ok(s.some((x) => x.severity === 'medium' && x.title.includes('"avatars"')));
  assert.ok(!s.some((x) => x.title.includes('"vacio"')));
  assert.ok(!JSON.stringify(f).includes('factura-cliente-123'), 'no imprime nombres de archivos');
  assert.ok(methods.every((m) => m === 'GET' || m === 'POST'));
  await srv.close();
});

// ---------- Secretos ----------

function site(routes, page) {
  return startServer((req, res) => {
    if (req.url === '/') return send(res, 200, page, html);
    const r = routes[req.url];
    if (r == null) return send(res, 404, '');
    return typeof r === 'function' ? r(req, res) : send(res, 200, r, js);
  });
}

test('secretos: source map referenciado se reporta y su código original se escanea', async () => {
  const map = JSON.stringify({ version: 3, mappings: 'AAAA', sources: ['src/db.ts'], sourcesContent: ['const url = "postgres://app:Sup3rS3cr3t@db.prod-cluster.net:5432/app"'] });
  const srv = await site({ '/app.js': 'console.log(1)\n//# sourceMappingURL=app.js.map', '/app.js.map': map }, '<script src="/app.js"></script>');
  const { findings } = await scanForSecrets(srv.url);
  assert.ok(findings.some((f) => f.severity === 'medium' && /Source maps públicos: 1/.test(f.title)));
  const db = findings.find((f) => f.title.includes('Cadena de conexión'));
  assert.equal(db.severity, 'critical');
  assert.match(db.detail, /app\.js\.map/);
  assert.ok(!db.detail.includes('Sup3rS3cr3t'));
  await srv.close();
});

test('secretos: source map "oculto" (sin comentario) también se encuentra; fallback HTML no cuenta', async () => {
  const map = JSON.stringify({ version: 3, mappings: 'AAAA', sourcesContent: ['x'] });
  const srv = await site({ '/a.js': 'a()', '/a.js.map': map, '/b.js': 'b()', '/b.js.map': (q, r) => send(r, 200, '<html>spa</html>', html) }, '<script src="/a.js"></script><script src="/b.js"></script>');
  const { findings } = await scanForSecrets(srv.url);
  assert.ok(findings.some((f) => /Source maps públicos: 1/.test(f.title) && f.detail.includes('/a.js.map')));
  assert.ok(!findings.some((f) => /no se pudieron descargar/.test(f.title)), 'un .map adivinado que no existe no es un fallo');
  await srv.close();
});

test('secretos: source map en línea (data:base64)', async () => {
  const map = Buffer.from(JSON.stringify({ version: 3, mappings: 'A', sourcesContent: ['k="AKIAIOSFODNN7EXAMPLE"'] })).toString('base64');
  const srv = await site({ '/a.js': `x()\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,${map}` }, '<script src="/a.js"></script>');
  const { findings } = await scanForSecrets(srv.url);
  assert.ok(findings.some((f) => f.title.includes('AWS') && f.detail.includes('en línea')));
  assert.ok(findings.some((f) => /Source maps públicos/.test(f.title)));
  await srv.close();
});

test('secretos: patrones nuevos y placeholders ignorados', async () => {
  const code = [
    'const g="GOCSPX-' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4' + '";',
    'const r="re_' + 'Ab12Cd34' + '_' + 'Ef56Gh78Ij90Kl12Mn34' + '";',
    'const m="key-' + '0123456789abcdef0123456789abcdef' + '";',
    'const t="SK' + '0123456789abcdef0123456789abcdef' + '";',
    'const p1="postgres://user:password@localhost:5432/db";',
    'const p2="postgresql://u:${PASS}@host/db";',
    'const p3="mongodb+srv://admin:<password>@cluster0.mongodb.net/app";',
    'const id="re_validate_somethinglongidentifierxx";',
  ].join('\n');
  const srv = await site({ '/a.js': code }, '<script src="/a.js"></script>');
  const titles = (await scanForSecrets(srv.url)).findings.map((f) => f.title);
  for (const name of ['Google OAuth', 'Resend', 'Mailgun', 'Twilio']) assert.ok(titles.some((t) => t.includes(name)), name);
  assert.ok(!titles.some((t) => t.includes('Cadena de conexión')), 'placeholders no son hallazgos');
  assert.equal(titles.filter((t) => t.includes('Resend')).length, 1, 'un identificador re_... no es una llave');
  await srv.close();
});

test('secretos: bundles que no se pudieron descargar se reportan (escaneo parcial)', async () => {
  const srv = await site({ '/ok.js': 'x()' }, '<script src="/ok.js"></script><script src="/roto.js"></script>');
  const { findings } = await scanForSecrets(srv.url);
  const f = findings.find((x) => /no se pudieron descargar/.test(x.title));
  assert.ok(f);
  assert.match(f.detail, /roto\.js/);
  await srv.close();
});

test('secretos: detecta el proyecto de Supabase y su anon key; nunca usa la service_role', async () => {
  const ref = 'abcdefghijklmnopqrst';
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const anon = `${b64({ alg: 'HS256' })}.${b64({ iss: 'supabase', ref, role: 'anon' })}.${'s'.repeat(43)}`;
  const srv = await site({ '/a.js': `createClient("https://${ref}.supabase.co","${anon}")` }, '<script src="/a.js"></script>');
  const { supabase } = await scanForSecrets(srv.url);
  assert.deepEqual(supabase, { url: `https://${ref}.supabase.co`, anonKey: anon, projects: 1, tables: [] });
  await srv.close();

  const srv2 = await site({ '/a.js': `createClient("https://${ref}.supabase.co","${fakeJwt('service_role')}")` }, '<script src="/a.js"></script>');
  const r2 = await scanForSecrets(srv2.url);
  assert.equal(r2.supabase.anonKey, null);
  assert.ok(r2.findings.some((f) => f.severity === 'critical' && f.title.includes('service_role')));
  await srv2.close();
});

// ---------- Rutas ----------

test('rutas: un catch-all de /api/* que responde 200 JSON no genera falsos medios', async () => {
  const srv = await startServer((req, res) =>
    req.url.startsWith('/api/') ? send(res, 200, JSON.stringify({ error: 'not found', path: req.url }), { 'Content-Type': 'application/json' }) : send(res, 404, ''),
  );
  const f = await checkCommonRoutes(srv.url);
  assert.ok(!f.some((x) => x.severity === 'medium'));
  assert.ok(f.some((x) => x.severity === 'info' && /api/.test(x.title)));
  await srv.close();
});

test('rutas: sin catch-all de API, un /api/debug real sigue detectándose', async () => {
  const srv = await startServer((req, res) => (req.url === '/api/debug' ? send(res, 200, '{"env":"prod"}') : send(res, 404, '')));
  const f = await checkCommonRoutes(srv.url);
  assert.ok(f.some((x) => x.severity === 'medium' && x.title.includes('/api/debug')));
  await srv.close();
});
