import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanForSecrets } from '../src/checks/secrets.js';
import { startServer, send, fakeJwt } from './helpers.js';

const AWS = 'AKIA' + 'IOSFODNN7EXAMPLE'; // clave de ejemplo oficial de AWS
const SK = 'sk_live_' + 'x'.repeat(24);

function site(routes, html) {
  return startServer((req, res) => {
    if (req.url === '/') return send(res, 200, html, { 'Content-Type': 'text/html' });
    return routes[req.url] != null ? send(res, 200, routes[req.url], { 'Content-Type': 'application/javascript' }) : send(res, 404, '');
  });
}
const scripts = (n) => Array.from({ length: n }, (_, i) => `<script src="/s${i + 1}.js"></script>`).join('');

test('secretos: detecta AWS/Stripe, ignora la anon key', async () => {
  const srv = await site(
    { '/s1.js': `const anon="${fakeJwt('anon')}";`, '/s2.js': `const a="${AWS}";const s="${SK}";` },
    scripts(2),
  );
  const { findings } = await scanForSecrets(srv.url);
  const titles = findings.map((f) => f.title);
  assert.ok(titles.some((t) => t.includes('AWS')));
  assert.ok(titles.some((t) => t.includes('Stripe Live')));
  assert.ok(!titles.some((t) => t.includes('service_role')), 'la anon key no es un hallazgo');
  assert.ok(findings.every((f) => !f.detail.includes(SK)), 'el valor completo no se imprime');
  await srv.close();
});

test('secretos: service_role en el script #20 (antes el tope de 15 la ocultaba)', async () => {
  const routes = { '/s20.js': `const k="${fakeJwt('service_role')}";` };
  const srv = await site(routes, scripts(25));
  const { findings } = await scanForSecrets(srv.url);
  assert.ok(findings.some((f) => f.severity === 'critical' && f.title.includes('service_role')));
  await srv.close();
});

test('secretos: service_role en un chunk lazy descubierto vía import()', async () => {
  const srv = await site(
    { '/app.js': `import('/lazy.js')`, '/lazy.js': `export const k="${fakeJwt('service_role')}"` },
    '<script src="/app.js"></script>',
  );
  const { findings, scanned } = await scanForSecrets(srv.url);
  assert.ok(scanned >= 2);
  assert.ok(findings.some((f) => f.title.includes('service_role') && f.detail.includes('/lazy.js')));
  await srv.close();
});

test('secretos: sb_secret_ (llaves nuevas de Supabase) es crítico', async () => {
  const srv = await site({ '/a.js': 'const k="sb_secret_' + 'A1b2C3d4'.repeat(4) + '"' }, scripts(1).replace('s1', 'a'));
  const { findings } = await scanForSecrets(srv.url);
  assert.ok(findings.some((f) => f.severity === 'critical' && f.title.includes('sb_secret_')));
  await srv.close();
});

test('secretos: clases CSS largas tipo "task-..." no son claves OpenAI', async () => {
  const css = 'const c="task-management-dashboard-widget-container-wrapper-large-primary";const m="mask-position-x-center-top-left-bottom-right-inside";';
  const srv = await site({ '/a.js': css }, '<script src="/a.js"></script>');
  const { findings } = await scanForSecrets(srv.url);
  assert.equal(findings.length, 0);
  await srv.close();
});

test('secretos: avisa si se alcanza el tope de archivos', async () => {
  const srv = await site({}, scripts(10));
  const { findings } = await scanForSecrets(srv.url, { maxFiles: 3 });
  assert.ok(findings.some((f) => f.severity === 'info' && /tope/i.test(f.title)));
  await srv.close();
});

test('secretos: Firebase API key (pública por diseño) sale en bajo, no en alto', async () => {
  const srv = await site({ '/a.js': 'const f="AIza' + 'A'.repeat(35) + '"' }, '<script src="/a.js"></script>');
  const { findings } = await scanForSecrets(srv.url);
  assert.equal(findings[0].severity, 'low');
  await srv.close();
});
