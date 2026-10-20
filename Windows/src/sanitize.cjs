'use strict';
const LIMIT = 32768;
function bounded(value) {
  const text = String(value || '');
  return text.slice(0, LIMIT) + (text.length > LIMIT ? '\n[обрезано: лимит 32 768 символов]' : '');
}
function secretKey(key) {
  return /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|password|secret|session_?key)$/i.test(key) || /token$/i.test(key);
}
function safeURL(value) {
  try { const url = new URL(value); url.username = ''; url.password = ''; url.search = ''; url.hash = ''; return bounded(url.href); }
  catch { return '[URL]'; }
}
function headers(value = {}) {
  return bounded(Object.keys(value).sort().map(key => key + ': ' + (secretKey(key) ? '[скрыто]' : value[key])).join('\n'));
}
function body(value) {
  const walk = object => {
    if (Array.isArray(object)) return object.map(walk);
    if (object && typeof object === 'object') return Object.fromEntries(Object.entries(object).map(([key, val]) => [key, secretKey(key) ? '[скрыто]' : walk(val)]));
    return object;
  };
  const text = String(value || '');
  try { return bounded(JSON.stringify(walk(JSON.parse(text)), null, 2)); }
  catch {
    return bounded(text.replace(/("(?:[^"\r\n]*token|password|secret|session_?key)"\s*:\s*")[^"\r\n]*(")/gi, '$1[скрыто]$2')
      .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]+/gi, '$1[скрыто]'));
  }
}
function audit(header = {}, text = '') {
  const flags = new Set();
  function inspect(key, value) {
    if (typeof value !== 'string') return;
    if (/timezone|time_zone|^tz$/i.test(key) && /europe\/moscow|europe\/moskow/i.test(value)) flags.add('В метаданных Europe/Moscow');
    if (/language|locale/i.test(key) && /^ru(?:[-_,;]|$)/i.test(value)) flags.add('В метаданных русский язык');
  }
  const walk = object => {
    if (Array.isArray(object)) object.forEach(walk);
    else if (object && typeof object === 'object') for (const [key, value] of Object.entries(object)) {
      inspect(key, value); if (value && typeof value === 'object') walk(value);
    }
  };
  walk(header); try { walk(JSON.parse(text)); } catch {}
  return [...flags];
}
function diagnostic(value) {
  // Diagnostics never receive bodies, headers, connection settings or subprocess stderr.
  return bounded(String(value).replace(/https?:\/\/[^\s]+/gi, url => safeURL(url))
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP скрыт]')
    .replace(/\b[0-9a-f]{0,4}:[0-9a-f:]{2,}(?:%\w+)?/gi, '[IP скрыт]')).slice(0, 1500);
}
module.exports = { LIMIT, bounded, secretKey, safeURL, headers, body, audit, diagnostic };
