import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { checkSupabaseRLS } from '../src/checks/supabase.js';
import { scanForSecrets } from '../src/checks/secrets.js';
import { startServer, send } from './helpers.js';

const BIN = new URL('../bin/rlscan.js', import.meta.url).pathname;
const PUB = 'sb_publishable_' + 'A'.repeat(24);
function cli(args, env = {}) {
  return new Promise((resolve) => {
    const clean = { ...process.env, NO_COLOR: '1' };
    delete clean.SUPABASE_URL;
    delete clean.SUPABASE_ANON_KEY;
    const p = spawn(process.execPath, [BIN, ...args], { env: { ...clean, ...env } });
    let out = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (out += d));
    p.on('close', (code) => resolve({ code, out }));
  });
}

/** Supabase "nuevo": el esquema exige secret key; pedidos expuesta, contacto vacía, el resto no existe. */
function newSupabase() {
  return startServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/rest/v1/') return send(res, 401, JSON.stringify({ message: 'Secret API key required', hint: 'Only secret API keys can be used for this endpoint.' }));
    if (u.pathname === '/rest/v1/pedidos') return send(res, 200, JSON.stringify([{ id: 1, guia: 'X', estado: 'ok' }]));
    if (u.pathname === '/rest/v1/contacto') return send(res, 200, '[]');
    if (u.pathname.startsWith('/rest/v1/')) return send(res, 404, JSON.stringify({ code: 'PGRST205' }));
    if (u.pathname === '/storage/v1/bucket') return send(res, 200, '[]');
    return send(res, 404, '');
  });
}

test('sitio 403 (WAF/bots) => exit 2 aunque no haya --fail-on-high', async () => {
  const srv = await startServer((req, res) => send(res, 403, '<html>Forbidden</html>', { 'Content-Type': 'text/html' }));
  const r = await cli([srv.url]);
  assert.equal(r.code, 2);
  assert.match(r.out, /respondió 403: no se pudo escanear/);
  assert.ok(!/Falta cabecera/.test(r.out), 'no evalúa cabeceras de una página de bloqueo');
  await srv.close();
});

test('sitio 403 + Supabase explícito => Supabase se revisa igual, exit 2', async () => {
  const site = await startServer((req, res) => send(res, 403, 'no'));
  const sb = await newSupabase();
  const r = await cli([site.url, '--supabase-url', sb.url, '--supabase-anon-key', PUB, '--supabase-tables', 'pedidos', '--json']);
  assert.equal(r.code, 2);
  const j = JSON.parse(r.out);
  assert.ok(j.findings.some((f) => f.severity === 'critical' && f.title.includes('pedidos')));
  await site.close();
  await sb.close();
});

test('supabase: "Secret API key required" se explica (no dice que la llave esté mal)', async () => {
  const sb = await newSupabase();
  const f = await checkSupabaseRLS(sb.url, PUB);
  assert.equal(f[0].severity, 'error');
  assert.match(f[0].detail, /Secret API key required/);
  assert.match(f[0].detail, /la llave es válida/);
  await sb.close();
});

test('supabase: sin esquema, usa las tablas encontradas en el código', async () => {
  const sb = await newSupabase();
  const f = await checkSupabaseRLS(sb.url, PUB, { fallbackTables: ['pedidos', 'contacto'] });
  assert.ok(f.some((x) => x.severity === 'info' && /encontradas en el código/.test(x.title)));
  assert.ok(f.some((x) => x.severity === 'critical' && x.title.includes('pedidos')));
  assert.ok(!f.some((x) => x.severity === 'error'));
  await sb.close();
});

test('supabase: tabla inexistente es INFO "no existe", no MEDIO "no se pudo evaluar"', async () => {
  const sb = await newSupabase();
  const f = await checkSupabaseRLS(sb.url, PUB, { tables: ['pedidos', 'usuarios'] });
  assert.ok(f.some((x) => x.severity === 'info' && /1 tabla\(s\) no existen/.test(x.title) && x.detail.includes('usuarios')));
  assert.ok(!f.some((x) => /no se pudieron evaluar/.test(x.title)));
  const all = await checkSupabaseRLS(sb.url, PUB, { tables: ['usuarios', 'users'] });
  assert.equal(all[0].severity, 'error');
  assert.match(all[0].title, /Ninguna de las tablas/);
  await sb.close();
});

test('secretos: extrae tablas del código (/rest/v1/x y .from("x")), ignora storage.from y Array.from', async () => {
  const code = [
    'fetch(`${SUPABASE_URL}/rest/v1/pedidos?guia=eq.1`)',
    'fetch(URL + "/rest/v1/rpc/mi_funcion")',
    'await sb.from("clientes").select("*")',
    'supabase.storage.from("avatars").list()',
    'const a = Array.from("abc")',
  ].join('\n');
  const srv = await startServer((req, res) => (req.url === '/' ? send(res, 200, `<script>${code}</script>`, { 'Content-Type': 'text/html' }) : send(res, 404, '')));
  const { supabase } = await scanForSecrets(srv.url);
  assert.deepEqual(supabase.tables.sort(), ['clientes', 'pedidos']);
  assert.equal(supabase.url, null);
  await srv.close();
});

test('CLI: aviso de configuración incompleta dice de dónde vino cada valor', async () => {
  const srv = await startServer((req, res) => send(res, 200, '<html></html>', { 'Content-Type': 'text/html' }));
  const r = await cli([srv.url, '--no-routes'], { SUPABASE_URL: srv.url });
  assert.equal(r.code, 0);
  assert.match(r.out, /Se recibió la variable de entorno SUPABASE_URL, pero falta --supabase-anon-key/);
  const r2 = await cli([srv.url, '--no-routes', '--supabase-anon-key', PUB]);
  assert.equal(r2.code, 2);
  assert.match(r2.out, /Se recibió --supabase-anon-key, pero falta --supabase-url/);
  await srv.close();
});
