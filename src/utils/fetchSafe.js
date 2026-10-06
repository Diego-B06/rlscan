const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_MAX_BYTES = 5 * 1024 * 1024; // 5MB cap per resource, bundles can be huge

/**
 * fetch() with a hard timeout and a byte cap, so a scan can never hang
 * forever or pull down a 200MB chunk by accident.
 */
export async function fetchSafe(url, { timeoutMs = DEFAULT_TIMEOUT_MS, maxBytes = DEFAULT_MAX_BYTES, headers = {} } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal, headers, redirect: 'follow' });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Reads a response body as text, aborting if it grows past maxBytes.
 * Returns '' on any read failure instead of throwing, so one bad
 * resource never kills the whole scan.
 */
export async function readTextCapped(res, maxBytes = DEFAULT_MAX_BYTES) {
  try {
    const reader = res.body?.getReader?.();
    if (!reader) return await res.text();

    const decoder = new TextDecoder();
    let received = 0;
    let out = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maxBytes) {
        reader.cancel().catch(() => {});
        break;
      }
      out += decoder.decode(value, { stream: true });
    }
    return out;
  } catch {
    return '';
  }
}

export function resolveUrl(maybeRelative, baseUrl) {
  try {
    return new URL(maybeRelative, baseUrl).toString();
  } catch {
    return null;
  }
}
