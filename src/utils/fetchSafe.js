const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_MAX_BYTES = 5 * 1024 * 1024; // 5MB por recurso: los bundles pueden ser enormes

export class ScanFetchError extends Error {
  constructor(message, { code, cause } = {}) {
    super(message);
    this.name = 'ScanFetchError';
    this.code = code;
    this.cause = cause;
  }
}

function describeError(err, timeoutMs) {
  if (err?.name === 'AbortError' || err?.code === 'ABORT_ERR') {
    return { code: 'ETIMEDOUT', message: `sin respuesta completa tras ${Math.round(timeoutMs / 1000)}s (timeout)` };
  }
  const code = err?.cause?.code || err?.code;
  const map = {
    ENOTFOUND: 'el dominio no existe o no resuelve (DNS)',
    ECONNREFUSED: 'conexión rechazada (¿puerto cerrado o servidor apagado?)',
    ECONNRESET: 'la conexión fue cerrada por el servidor',
    CERT_HAS_EXPIRED: 'el certificado TLS está vencido',
    DEPTH_ZERO_SELF_SIGNED_CERT: 'certificado TLS autofirmado',
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'no se pudo verificar el certificado TLS',
    ERR_INVALID_URL: 'URL inválida',
  };
  if (code && map[code]) return { code, message: map[code] };
  if (/bad port/i.test(err?.cause?.message || err?.message || '')) {
    return { code: 'EBADPORT', message: 'puerto bloqueado por el estándar fetch (p. ej. 9, 25, 6000); usa otro puerto' };
  }
  return { code: code || 'EFETCH', message: err?.cause?.message || err?.message || 'error de red desconocido' };
}

/**
 * Descarga una URL y lee su cuerpo (como texto) bajo UN SOLO plazo total:
 * el temporizador sigue vivo mientras se lee el cuerpo, así que un servidor
 * que manda cabeceras y luego se cuelga ya no puede bloquear el escaneo.
 * Corta la lectura al superar maxBytes. Lanza ScanFetchError con un mensaje claro.
 */
export async function fetchText(url, { timeoutMs = DEFAULT_TIMEOUT_MS, maxBytes = DEFAULT_MAX_BYTES, headers = {} } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal, headers, redirect: 'follow' });
    let text = '';
    let truncated = false;
    const reader = res.body?.getReader?.();
    if (reader) {
      const decoder = new TextDecoder();
      let received = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > maxBytes) {
          truncated = true;
          reader.cancel().catch(() => {});
          break;
        }
        text += decoder.decode(value, { stream: true });
      }
    }
    return {
      url: res.url || url,
      status: res.status,
      ok: res.ok,
      statusText: res.statusText,
      headers: res.headers,
      text,
      truncated,
    };
  } catch (err) {
    const { code, message } = describeError(err, timeoutMs);
    throw new ScanFetchError(message, { code, cause: err });
  } finally {
    clearTimeout(timer);
  }
}

export function resolveUrl(maybeRelative, baseUrl) {
  try {
    return new URL(maybeRelative, baseUrl).toString();
  } catch {
    return null;
  }
}

/**
 * Normaliza la URL del usuario: añade https:// si falta el esquema y
 * rechaza lo que no sea http(s). Devuelve { url } o { error }.
 */
export function normalizeTargetUrl(input) {
  const raw = String(input || '').trim();
  if (!raw) return { error: 'Falta la URL a escanear.' };
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  try {
    const u = new URL(withScheme);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return { error: `Solo se admiten URLs http(s), recibí "${u.protocol}".` };
    }
    return { url: u.toString().replace(/\/$/, ''), assumedHttps: withScheme !== raw };
  } catch {
    return { error: `"${raw}" no es una URL válida.` };
  }
}
