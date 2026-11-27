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
  const srv = await startServer((req, res) =>
    req.url === '/.env' ? send(res, 200, 'DB_PASSWORD=x\n') : send(res, 200, '<html></html>', { 'Content-Type': 'text/html' }),
  );
  assert.equal((await cli([srv.url, '--fail-on-high'])).code, 1); // .env expuesto (crítico)
  assert.equal((await cli([srv.url])).code, 0);
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
  assert.ok(Array.isArray(j.findings) && j.summary.medium >= 1); // falta CSP (medio)
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

test('CLI: sin CSP ya no es "alto": --fail-on-high no falla solo por eso', async () => {
  const srv = await startServer((req, res) => send(res, 200, '<html></html>', { 'Content-Type': 'text/html' }));
  assert.equal((await cli([srv.url, '--no-routes', '--fail-on-high'])).code, 0);
  await srv.close();
});

test('CLI: --max-files inválido => exit 2 (antes NaN quitaba el tope)', async () => {
  for (const v of ['abc', '0', '-3', '1.5']) {
    const r = await cli(['http://127.0.0.1:1', '--max-files', v]);
    assert.equal(r.code, 2, `--max-files ${v}`);
    assert.match(r.out, /entero positivo/);
  }
});

test('CLI: --help y --version salen con 0', async () => {
  assert.equal((await cli(['--version'])).code, 0);
  assert.equal((await cli(['--help'])).code, 0);
});

test('CLI: --supabase-url sin llave => exit 2; por variable de entorno suelta solo avisa', async () => {
  const srv = await startServer((req, res) => send(res, 200, '<html></html>', { 'Content-Type': 'text/html' }));
  assert.equal((await cli([srv.url, '--no-routes', '--supabase-url', srv.url])).code, 2);
  const p = await new Promise((resolve) => {
    const c = spawn(process.execPath, [BIN, srv.url, '--no-routes', '--json'], { env: { ...process.env, SUPABASE_URL: srv.url, SUPABASE_ANON_KEY: '' } });
    let out = '';
    c.stdout.on('data', (d) => (out += d));
    c.on('close', (code) => resolve({ code, out }));
  });
  assert.equal(p.code, 0);
  assert.ok(JSON.parse(p.out).findings.some((f) => f.check === 'supabase' && f.severity === 'info'));
  await srv.close();
});

test('CLI: la llave puede venir de SUPABASE_URL / SUPABASE_ANON_KEY', async () => {
  const srv = await startServer((req, res) => {
    if (req.url.startsWith('/rest/v1/')) {
      if (req.url === '/rest/v1/') return send(res, 200, JSON.stringify({ paths: { '/customers': {} } }));
      return send(res, 200, JSON.stringify([{ id: 1, email: 'a@x.com' }]));
    }
    if (req.url.startsWith('/storage/')) return send(res, 400, '');
    return send(res, 200, '<html></html>', { 'Content-Type': 'text/html' });
  });
  const r = await new Promise((resolve) => {
    const c = spawn(process.execPath, [BIN, srv.url, '--no-routes', '--json', '--fail-on-high'], {
      env: { ...process.env, SUPABASE_URL: srv.url, SUPABASE_ANON_KEY: fakeJwt('anon') },
    });
    let out = '';
    c.stdout.on('data', (d) => (out += d));
    c.on('close', (code) => resolve({ code, out }));
  });
  assert.equal(r.code, 1);
  assert.ok(JSON.parse(r.out).findings.some((f) => f.severity === 'critical' && f.title.includes('customers')));
  await srv.close();
});
