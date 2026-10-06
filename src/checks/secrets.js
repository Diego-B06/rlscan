import { fetchText, resolveUrl } from '../utils/fetchSafe.js';

const DEFAULT_MAX_FILES = 80; // tope total de archivos JS por escaneo
const MAX_DEPTH = 3; // HTML -> script -> chunk -> chunk
const CONCURRENCY = 6;
const TOTAL_BUDGET_MS = 60_000; // tiempo máximo del escaneo de bundles completo

// Formatos reales de proveedor. Estrechos a propósito para minimizar falsos positivos.
const SECRET_PATTERNS = [
  { name: 'AWS Access Key ID', re: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'Stripe Live Secret Key', re: /sk_live_[0-9a-zA-Z]{20,}/g, severity: 'critical' },
  { name: 'Stripe Restricted Live Key', re: /rk_live_[0-9a-zA-Z]{20,}/g, severity: 'critical' },
  { name: 'Stripe Test Secret Key', re: /sk_test_[0-9a-zA-Z]{20,}/g, severity: 'medium' },
  { name: 'Supabase Secret Key (sb_secret_)', re: /sb_secret_[A-Za-z0-9_-]{20,}/g, severity: 'critical' },
  { name: 'GitHub Personal Access Token', re: /gh[pousr]_[0-9A-Za-z]{36,}/g, severity: 'critical' },
  { name: 'GitHub Fine-grained Token', re: /github_pat_[0-9A-Za-z_]{40,}/g, severity: 'critical' },
  { name: 'Anthropic API Key', re: /sk-ant-[A-Za-z0-9_-]{30,}/g, severity: 'critical' },
  { name: 'OpenAI API Key', re: /(?<![A-Za-z0-9_-])sk-(?:proj-)?(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{40,}/g, severity: 'critical' },
  { name: 'Slack Token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/g, severity: 'high' },
  { name: 'SendGrid API Key', re: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g, severity: 'high' },
  { name: 'Private Key Block', re: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, severity: 'critical' },
  // Las API keys web de Firebase/Google son públicas por diseño: se avisan en bajo,
  // para que verifiques que tengan restricciones de dominio/API.
  { name: 'Google/Firebase API Key (pública por diseño; verifica restricciones)', re: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'low' },
];

const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

function redact(value) {
  if (value.length <= 12) return '****';
  return `${value.slice(0, 6)}…${value.slice(-4)}`;
}

function decodeJwtPayload(token) {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

/** Devuelve [{ key, severity, title, hint, redacted }] encontrados en un texto. */
function matchSecrets(text) {
  const hits = [];
  for (const p of SECRET_PATTERNS) {
    for (const match of new Set(text.match(p.re) || [])) {
      if (p.name === 'OpenAI API Key') {
        if (match.startsWith('sk-ant-')) continue; // ya cubierta como Anthropic
      }
      hits.push({ key: `${p.name}|${match}`, severity: p.severity, title: `Posible ${p.name} expuesta`, redacted: redact(match) });
    }
  }
  for (const jwt of new Set(text.match(JWT_RE) || [])) {
    const payload = decodeJwtPayload(jwt);
    if (payload?.role === 'service_role') {
      hits.push({
        key: `service_role|${jwt}`,
        severity: 'critical',
        title: 'Supabase service_role key expuesta en el cliente',
        hint: 'Esta llave se salta Row Level Security por completo. Rótala de inmediato.',
        redacted: redact(jwt),
      });
    }
  }
  return hits;
}

/** URLs de scripts referenciadas en el HTML (script src, preload/modulepreload, import() inline). */
function extractFromHtml(html, baseUrl) {
  const urls = new Set();
  for (const m of html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) urls.add(resolveUrl(m[1], baseUrl));
  for (const m of html.matchAll(/<link\b[^>]*\bhref=["']([^"']+\.m?js(?:\?[^"']*)?)["'][^>]*>/gi)) urls.add(resolveUrl(m[1], baseUrl));
  for (const u of extractFromJs(html, baseUrl)) urls.add(u);
  urls.delete(null);
  return urls;
}

/** Chunks referenciados dentro de un texto JS/HTML: import('./x.js'), "static/chunks/x.js", "/assets/x.js". */
function extractFromJs(text, fileUrl) {
  const out = new Set();
  const origin = new URL(fileUrl).origin;
  for (const m of text.matchAll(/["'`]([^"'`\s\\]{3,200}?\.m?js(?:\?[^"'`\s\\]*)?)["'`]/g)) {
    const ref = m[1];
    let abs = null;
    if (/^https?:\/\//i.test(ref)) abs = ref;
    else if (ref.startsWith('//')) abs = `${new URL(fileUrl).protocol}${ref}`;
    else if (ref.startsWith('/')) abs = `${origin}${ref}`;
    else if (ref.startsWith('./') || ref.startsWith('../')) abs = resolveUrl(ref, fileUrl);
    else if (ref.startsWith('static/')) abs = `${origin}/_next/${ref}`; // Next.js (buildManifest)
    else if (ref.startsWith('assets/')) abs = `${origin}/${ref}`; // Vite
    if (abs) out.add(abs.split('#')[0]);
  }
  return out;
}

/**
 * Escanea el HTML principal y los bundles JS del MISMO origen en busca de secretos.
 * Descubre chunks cargados dinámicamente (hasta MAX_DEPTH niveles) y respeta un tope de archivos.
 */
export async function scanForSecrets(url, { html = null, maxFiles = DEFAULT_MAX_FILES } = {}) {
  const findings = [];
  const found = new Map(); // key -> { hit, sources:Set }
  const origin = new URL(url).origin;

  const record = (text, source) => {
    for (const hit of matchSecrets(text)) {
      const entry = found.get(hit.key) || { hit, sources: new Set() };
      entry.sources.add(source);
      found.set(hit.key, entry);
    }
  };

  let page = html;
  if (page == null) {
    try {
      page = (await fetchText(url)).text;
    } catch (err) {
      return { findings: [{ check: 'secrets', severity: 'error', title: 'No se pudo descargar el HTML principal', detail: `${url}: ${err.message}` }], scanned: 0 };
    }
  }
  record(page, url);

  const visited = new Set([url]);
  let frontier = [...extractFromHtml(page, url)];
  const startedAt = Date.now();
  let scanned = 0;
  let capped = false;

  for (let depth = 0; depth < MAX_DEPTH && frontier.length > 0; depth++) {
    const batch = [];
    for (const u of frontier) {
      if (visited.has(u)) continue;
      if (new URL(u).origin !== origin) continue; // solo código propio
      visited.add(u);
      if (visited.size - 1 > maxFiles) { capped = true; continue; }
      batch.push(u);
    }
    const next = new Set();
    let i = 0;
    const worker = async () => {
      while (i < batch.length && Date.now() - startedAt < TOTAL_BUDGET_MS) {
        const target = batch[i++];
        try {
          const res = await fetchText(target, { timeoutMs: 10_000 });
          if (!res.ok) continue;
          scanned++;
          record(res.text, target);
          for (const u of extractFromJs(res.text, target)) next.add(u);
        } catch {
          // un bundle que no carga no detiene el escaneo de los demás
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, batch.length) }, worker));
    frontier = [...next];
  }

  for (const { hit, sources } of found.values()) {
    const list = [...sources];
    findings.push({
      check: 'secrets',
      severity: hit.severity,
      title: hit.title,
      detail: `${hit.hint ? `${hit.hint} ` : ''}Encontrada en ${list[0]}${list.length > 1 ? ` (+${list.length - 1} archivo(s) más)` : ''}: ${hit.redacted}`,
    });
  }

  if (capped) {
    findings.push({
      check: 'secrets',
      severity: 'info',
      title: `Se alcanzó el tope de ${maxFiles} archivos JS`,
      detail: 'El escaneo de secretos fue parcial. Aumenta el tope con --max-files si tu app tiene muchos bundles.',
    });
  }
  return { findings, scanned };
}
