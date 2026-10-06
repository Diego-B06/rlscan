import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { startServer, send, fakeJwt } from './helpers.js';

const BIN = new URL('../bin/rlscan.js', import.meta.url).pathname;
function cli(args) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, NO_COLOR: '1' } });
    let out = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (out += d));
    p.on('close', (code) => resolve({ code, out }));
  });
}

test('CLI: sitio inalcanzable => exit 2, también con --fail-on-high (antes salía 0)', async () => {
  for (const extra of [[], ['--fail-on-high']]) {
    const r = await cli(['http://127.0.0.1:1', ...extra]);
    assert.equal(r.code, 2);
    assert.match(r.out, /No se pudo conectar/);
  }
});

test('CLI: URL inválida => exit 2', async () => {
  assert.equal((await cli(['ftp://x.com'])).code, 2);
});

test('CLI: --fail-on-high => 1 con hallazgos graves y 0 sin la bandera', async () => {
  const srv = await startServer((req, res) => send(res, 200, '<html></html>', { 'Content-Type': 'text/html' }));
  assert.equal((await cli([srv.url, '--no-routes', '--fail-on-high'])).code, 1); // falta CSP (alto)
  assert.equal((await cli([srv.url, '--no-routes'])).code, 0);
  await srv.close();
});

test('CLI: sitio con todas las cabeceras y sin hallazgos => exit 0 incluso con --fail-on-high', async () => {
  const good = {
    'Content-Type': 'text/html',
    'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  };
  const srv = await startServer((req, res) => (req.url === '/' ? send(res, 200, '<html>ok</html>', good) : send(res, 404, '')));
  const r = await cli([srv.url, '--fail-on-high']);
  assert.equal(r.code, 0);
  await srv.close();
});

test('CLI: --json es JSON válido con summary y findings', async () => {
  const srv = await startServer((req, res) => send(res, 200, '<html></html>', { 'Content-Type': 'text/html' }));
  const r = await cli([srv.url, '--no-routes', '--json']);
  const j = JSON.parse(r.out);
  assert.equal(j.tool, 'rlscan');
  assert.ok(Array.isArray(j.findings) && j.summary.high >= 1);
  await srv.close();
});

test('CLI: rechaza una service_role pasada como --supabase-anon-key (exit 2, sin enviarla)', async () => {
  const srv = await startServer((req, res) => send(res, 200, '<html></html>'));
  const key = fakeJwt('service_role');
  const r = await cli([srv.url, '--supabase-url', srv.url, '--supabase-anon-key', key]);
  assert.equal(r.code, 2);
  assert.match(r.out, /service_role/);
  assert.ok(!r.out.includes(key), 'la llave no se imprime');
  await srv.close();
});

test('CLI: URL sin esquema se asume https y falla con gracia', async () => {
  const r = await cli(['localhost:1']);
  assert.equal(r.code, 2);
  assert.match(r.out, /se asumió https/);
});
