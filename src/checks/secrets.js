import { fetchText, resolveUrl } from '../utils/fetchSafe.js';

const DEFAULT_MAX_FILES = 80; // tope total de archivos JS por escaneo
const MAX_DEPTH = 3; // HTML -> script -> chunk -> chunk
const CONCURRENCY = 6;
const TOTAL_BUDGET_MS = 60_000; // tiempo máximo del escaneo de bundles completo
const MAX_GUESSED_MAPS = 10; // archivos .map adivinados (sin comentario sourceMappingURL)

const PLACEHOLDER_PASSWORD = /^(password|pass|passwd|secret|changeme|your[-_]?password|\*+|x+|<[^>]*>|\$\{?.*|\[[^\]]*\]|\{\{.*)$/i;
const PLACEHOLDER_HOST = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|host|hostname|db|database|example\.[a-z]+|.*\.example\.[a-z]+)(:\d+)?$/i;

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
  { name: 'Google OAuth Client Secret', re: /GOCSPX-[A-Za-z0-9_-]{28}/g, severity: 'critical' },
  {
    name: 'Cadena de conexión a base de datos con contraseña',
    re: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?):\/\/[^\s:@"'`/]+:[^\s@"'`/]+@[^\s"'`/?]+/g,
    severity: 'critical',
    skip: (m) => {
      const [, cred, host] = m.match(/:\/\/[^:]+:([^@]+)@(.+)$/) || [];
      return !cred || PLACEHOLDER_PASSWORD.test(cred) || PLACEHOLDER_HOST.test(host);
    },
  },
  { name: 'Resend API Key', re: /(?<![A-Za-z0-9_])re_(?=[A-Za-z0-9_]*\d)(?=[A-Za-z0-9_]*[A-Z])[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}(?![A-Za-z0-9_])/g, severity: 'high' },
  { name: 'Twilio API Key SID', re: /(?<![A-Za-z0-9])SK[0-9a-f]{32}(?![A-Za-z0-9])/g, severity: 'medium' },
  { name: 'Mailgun API Key', re: /(?<![A-Za-z0-9])key-[0-9a-f]{32}(?![A-Za-z0-9])/g, severity: 'high' },
  { name: 'Slack Token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/g, severity: 'high' },
  { name: 'SendGrid API Key', re: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g, severity: 'high' },
  { name: 'Private Key Block', re: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, severity: 'critical' },
  // Las API keys web de Firebase/Google son públicas por diseño: se avisan en bajo,
  // para que verifiques que tengan restricciones de dominio/API.
  { name: 'Google/Firebase API Key (pública por diseño; verifica restricciones)', re: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'low' },
];

const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const SUPABASE_URL_RE = /https:\/\/([a-z0-9]{20})\.supabase\.co/g;
const SB_PUBLISHABLE_RE = /sb_publishable_[A-Za-z0-9_-]{20,}/g;
const SOURCEMAP_RE = /\/[/*][#@]\s*sourceMappingURL=([^\s'"*]+)/g;

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

function sameOrigin(u, origin) {
  try {
    return new URL(u).origin === origin;
  } catch {
    return false;
  }
}

/** Devuelve [{ key, severity, title, hint, redacted }] encontrados en un texto. */
function matchSecrets(text) {
  const hits = [];
  for (const p of SECRET_PATTERNS) {
    for (const match of new Set(text.match(p.re) || [])) {
      if (p.name === 'OpenAI API Key' && match.startsWith('sk-ant-')) continue; // ya cubierta como Anthropic
      if (p.skip?.(match)) continue;
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

/** Último comentario sourceMappingURL de un JS: { inline: texto } | { url } | null. */
function findSourceMap(text, fileUrl) {
  const all = [...text.matchAll(SOURCEMAP_RE)];
  if (all.length === 0) return null;
  const ref = all[all.length - 1][1];
  const inline = ref.match(/^data:application\/json[^,]*;base64,(.+)$/i);
  if (inline) {
    try {
      return { inline: Buffer.from(inline[1], 'base64').toString('utf8') };
    } catch {
      return null;
    }
  }
  if (ref.startsWith('data:')) return null;
  const url = resolveUrl(ref, fileUrl);
  return url ? { url } : null;
}

/** Texto a escanear de un source map: sourcesContent si se puede parsear, si no el crudo. */
function sourceMapText(raw) {
  try {
    const map = JSON.parse(raw);
    if (typeof map?.mappings !== 'string') return null;
    return (map.sourcesContent || []).filter((s) => typeof s === 'string').join('\n');
  } catch {
    return /"mappings"\s*:/.test(raw) ? raw : null;
  }
}

/**
 * Escanea el HTML principal y los bundles JS del MISMO origen en busca de secretos.
 * Descubre chunks cargados dinámicamente (hasta MAX_DEPTH niveles), sigue los source maps
 * publicados y respeta un tope de archivos. También detecta la URL y la anon key de Supabase
 * que el sitio usa, para poder revisar su RLS sin parámetros.
 */
export async function scanForSecrets(url, { html = null, maxFiles = DEFAULT_MAX_FILES } = {}) {
  const findings = [];
  const found = new Map(); // key -> { hit, sources:Set }
  const origin = new URL(url).origin;
  const supabaseRefs = new Set();
  const anonJwts = []; // { jwt, ref }
  const publishableKeys = new Set();

  const record = (text, source) => {
    for (const hit of matchSecrets(text)) {
      const entry = found.get(hit.key) || { hit, sources: new Set() };
      entry.sources.add(source);
      found.set(hit.key, entry);
    }
    for (const m of text.matchAll(SUPABASE_URL_RE)) supabaseRefs.add(m[1]);
    for (const k of text.match(SB_PUBLISHABLE_RE) || []) publishableKeys.add(k);
    for (const jwt of new Set(text.match(JWT_RE) || [])) {
      const p = decodeJwtPayload(jwt);
      if (p?.role === 'anon' && !anonJwts.some((a) => a.jwt === jwt)) anonJwts.push({ jwt, ref: p.ref || null });
    }
  };

  let page = html;
  if (page == null) {
    try {
      page = (await fetchText(url)).text;
    } catch (err) {
      return { findings: [{ check: 'secrets', severity: 'error', title: 'No se pudo descargar el HTML principal', detail: `${url}: ${err.message}` }], scanned: 0, supabase: null };
    }
  }
  record(page, url);

  const visited = new Set([url]);
  const mapUrls = new Set();
  const guessedMaps = [];
  let inlineMaps = 0;
  let frontier = [...extractFromHtml(page, url)];
  const startedAt = Date.now();
  const overBudget = () => Date.now() - startedAt >= TOTAL_BUDGET_MS;
  let scanned = 0;
  let capped = false;
  let budgetHit = false;
  const failed = [];
  const truncated = [];

  // Descarga una lista de URLs con concurrencia limitada y bajo el presupuesto total de tiempo.
  const runPool = async (urls, handle) => {
    let i = 0;
    const worker = async () => {
      while (i < urls.length) {
        if (overBudget()) {
          budgetHit = true;
          return;
        }
        const target = urls[i++];
        try {
          const res = await fetchText(target, { timeoutMs: 10_000 });
          if (res.truncated) truncated.push(target);
          await handle(target, res);
        } catch {
          failed.push(target); // un archivo que no carga no detiene el escaneo de los demás
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, urls.length) }, worker));
  };

  for (let depth = 0; depth < MAX_DEPTH && frontier.length > 0; depth++) {
    const batch = [];
    for (const u of frontier) {
      if (visited.has(u)) continue;
      if (!sameOrigin(u, origin)) continue; // solo código propio
      visited.add(u);
      if (visited.size - 1 > maxFiles) { capped = true; continue; }
      batch.push(u);
    }
    const next = new Set();
    await runPool(batch, (target, res) => {
      if (!res.ok) {
        failed.push(target);
        return;
      }
      scanned++;
      record(res.text, target);
      for (const u of extractFromJs(res.text, target)) next.add(u);
      const sm = findSourceMap(res.text, target);
      if (sm?.inline) {
        const t = sourceMapText(sm.inline);
        if (t) {
          inlineMaps++;
          record(t, `${target} (source map en línea)`);
        }
      } else if (sm?.url) {
        if (sameOrigin(sm.url, origin)) mapUrls.add(sm.url);
      } else if (guessedMaps.length < MAX_GUESSED_MAPS) {
        // Builds con "hidden-source-map" (p. ej. Sentry) suben el .map sin comentario: también se prueba.
        guessedMaps.push(`${target.split('?')[0]}.map`);
      }
    });
    if (budgetHit) break;
    frontier = [...next];
  }

  // Source maps publicados: exponen el código fuente original (y a veces secretos que el minificado no muestra).
  const exposedMaps = [];
  const mapList = [...mapUrls].slice(0, maxFiles);
  const guessList = guessedMaps.filter((u) => !mapUrls.has(u));
  const mapsFailedBefore = failed.length;
  if (!budgetHit) {
    await runPool([...mapList, ...guessList], (target, res) => {
      if (!res.ok) {
        if (mapUrls.has(target)) failed.push(target);
        return;
      }
      const t = sourceMapText(res.text);
      if (t == null) return; // no era un source map (p. ej. fallback HTML)
      exposedMaps.push(target);
      record(t, target);
    });
  }
  // Los .map adivinados que no existen no cuentan como fallos.
  const guessSet = new Set(guessList);
  const realFailed = failed.filter((u, idx) => idx < mapsFailedBefore || !guessSet.has(u));

  for (const { hit, sources } of found.values()) {
    const srcs = [...sources];
    findings.push({
      check: 'secrets',
      severity: hit.severity,
      title: hit.title,
      detail: `${hit.hint ? `${hit.hint} ` : ''}Encontrada en ${srcs[0]}${srcs.length > 1 ? ` (+${srcs.length - 1} archivo(s) más)` : ''}: ${hit.redacted}`,
    });
  }

  if (exposedMaps.length > 0 || inlineMaps > 0) {
    findings.push({
      check: 'secrets',
      severity: 'medium',
      title: `Source maps públicos: ${exposedMaps.length + inlineMaps}`,
      detail:
        `Cualquiera puede reconstruir tu código fuente original${exposedMaps.length ? ` (p. ej. ${exposedMaps[0]})` : ' (incrustados en los bundles)'}. ` +
        'Desactívalos en producción o súbelos solo a tu herramienta de errores sin publicarlos.',
    });
  }

  if (capped) {
    findings.push({
      check: 'secrets',
      severity: 'info',
      title: `Escaneo de secretos parcial: se alcanzó el tope de ${maxFiles} archivos JS`,
      detail: 'Aumenta el tope con --max-files si tu app tiene muchos bundles.',
    });
  }
  if (budgetHit) {
    findings.push({
      check: 'secrets',
      severity: 'info',
      title: `Escaneo de secretos parcial: se agotó el tiempo máximo (${TOTAL_BUDGET_MS / 1000}s)`,
      detail: `Se escanearon ${scanned} archivo(s) antes del límite; el resto (y los source maps) quedaron sin revisar.`,
    });
  }
  if (realFailed.length > 0) {
    findings.push({
      check: 'secrets',
      severity: 'info',
      title: `Escaneo de secretos parcial: ${realFailed.length} archivo(s) no se pudieron descargar`,
      detail: `Sin revisar: ${realFailed.slice(0, 5).join(', ')}${realFailed.length > 5 ? '…' : ''}.`,
    });
  }
  if (truncated.length > 0) {
    findings.push({
      check: 'secrets',
      severity: 'info',
      title: `Escaneo de secretos parcial: ${truncated.length} archivo(s) superaron 5 MB y se revisaron solo en parte`,
      detail: `${truncated.slice(0, 5).join(', ')}${truncated.length > 5 ? '…' : ''}.`,
    });
  }

  return { findings, scanned, supabase: detectSupabase(supabaseRefs, anonJwts, publishableKeys) };
}

/** Elige el proyecto de Supabase del sitio y una llave PÚBLICA (anon/publishable) que le corresponda. */
function detectSupabase(refs, anonJwts, publishableKeys) {
  if (refs.size === 0) return null;
  const refList = [...refs];
  for (const ref of refList) {
    const match = anonJwts.find((a) => a.ref === ref);
    if (match) return { url: `https://${ref}.supabase.co`, anonKey: match.jwt, projects: refList.length };
  }
  const ref = refList[0];
  const key = (refList.length === 1 && ([...publishableKeys][0] || anonJwts.find((a) => !a.ref)?.jwt)) || null;
  return { url: `https://${ref}.supabase.co`, anonKey: key, projects: refList.length };
}
