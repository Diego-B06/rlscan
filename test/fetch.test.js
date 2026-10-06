import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fetchText, normalizeTargetUrl, ScanFetchError } from '../src/utils/fetchSafe.js';
import { startStallingServer } from './helpers.js';

test('fetchText corta una respuesta con cuerpo colgado (antes se bloqueaba para siempre)', async () => {
  const srv = await startStallingServer();
  const t0 = Date.now();
  await assert.rejects(() => fetchText(srv.url, { timeoutMs: 1000 }), (e) => e instanceof ScanFetchError && e.code === 'ETIMEDOUT');
  assert.ok(Date.now() - t0 < 4000, 'debe respetar el plazo total');
  await srv.close();
});

test('fetchText da mensajes claros: puerto cerrado', async () => {
  await assert.rejects(() => fetchText('http://127.0.0.1:1'), (e) => e instanceof ScanFetchError && /rechazada|bad port|fetch/i.test(e.message));
});

test('normalizeTargetUrl', () => {
  assert.equal(normalizeTargetUrl('mi-app.vercel.app').url, 'https://mi-app.vercel.app');
  assert.equal(normalizeTargetUrl('mi-app.vercel.app').assumedHttps, true);
  assert.equal(normalizeTargetUrl('http://localhost:3000/').url, 'http://localhost:3000');
  assert.ok(normalizeTargetUrl('ftp://x.com').error);
  assert.ok(normalizeTargetUrl('').error);
  assert.ok(normalizeTargetUrl('http://').error);
});
