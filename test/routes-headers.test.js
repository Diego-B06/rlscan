import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkCommonRoutes } from '../src/checks/commonRoutes.js';
import { checkHeaders } from '../src/checks/headers.js';
import { startServer, send } from './helpers.js';

test('rutas: un SPA que responde 200 a todo NO genera falsos críticos', async () => {
  const srv = await startServer((req, res) => send(res, 200, '<html><div id=root></div></html>', { 'Content-Type': 'text/html' }));
  const f = await checkCommonRoutes(srv.url);
  assert.equal(f.filter((x) => x.severity === 'critical' || x.severity === 'medium').length, 0);
  assert.ok(f.some((x) => x.severity === 'info' && /fallback/i.test(x.title)));
  await srv.close();
});

test('rutas: archivos realmente expuestos SÍ se detectan', async () => {
  const files = {
    '/.env': 'DATABASE_URL=postgres://u:p@h/db\nSTRIPE=x\n',
    '/.git/config': '[core]\n\trepositoryformatversion = 0\n',
    '/api/debug': '{"env":"prod"}',
  };
  const srv = await startServer((req, res) => (files[req.url] ? send(res, 200, files[req.url]) : send(res, 404, '')));
  const f = await checkCommonRoutes(srv.url);
  const crit = f.filter((x) => x.severity === 'critical').map((x) => x.title);
  assert.deepEqual(crit.sort(), ['Ruta expuesta: /.env', 'Ruta expuesta: /.git/config']);
  assert.ok(f.some((x) => x.severity === 'medium' && x.title.includes('/api/debug')));
  await srv.close();
});

test('rutas: un 200 con contenido que no coincide no es hallazgo', async () => {
  const srv = await startServer((req, res) => (req.url === '/.env' ? send(res, 200, 'hola mundo') : send(res, 404, '')));
  assert.equal((await checkCommonRoutes(srv.url)).length, 0);
  await srv.close();
});

test('cabeceras: faltantes en HTTP (HSTS no aplica) y reutiliza el HTML', async () => {
  const srv = await startServer((req, res) => send(res, 200, '<html>hola</html>', { 'Content-Type': 'text/html' }));
  const r = await checkHeaders(srv.url);
  assert.equal(r.reachable, true);
  assert.equal(r.html, '<html>hola</html>');
  const names = r.findings.map((x) => x.title);
  assert.ok(!names.some((n) => n.includes('HSTS')), 'HSTS no se exige sobre http');
  assert.ok(names.includes('Falta cabecera: Content-Security-Policy'));
  await srv.close();
});

test('cabeceras: frame-ancestors en CSP cubre X-Frame-Options', async () => {
  const srv = await startServer((req, res) => send(res, 200, 'x', { 'Content-Security-Policy': "frame-ancestors 'none'" }));
  const r = await checkHeaders(srv.url);
  assert.ok(!r.findings.some((x) => x.title.includes('X-Frame-Options')));
  assert.ok(!r.findings.some((x) => x.title.includes('Content-Security-Policy')));
  await srv.close();
});

test('cabeceras: respuesta 404 evalúa y lo explica sin contradecirse', async () => {
  const srv = await startServer((req, res) => send(res, 404, 'no'));
  const r = await checkHeaders(srv.url);
  const info = r.findings.find((x) => x.severity === 'info');
  assert.match(info.detail, /se evaluaron/);
  assert.ok(r.findings.some((x) => x.title.startsWith('Falta cabecera')));
  await srv.close();
});

test('cabeceras: sitio inalcanzable => reachable=false y severidad error', async () => {
  const r = await checkHeaders('http://127.0.0.1:1');
  assert.equal(r.reachable, false);
  assert.equal(r.findings[0].severity, 'error');
});
