'use strict';
const LIMIT = 32768;
function bounded(value) {
  const text = String(value || '');
  return text.slice(0, LIMIT) + (text.length > LIMIT ? '\n[обрезано: лимит 32 768 символов]' : '');
}
function secretKey(key) {
  return /^(authorization|proxy[_-]authorization|cookie|set[_-]cookie|x[_-]api[_-]key|api[_-]?key|client[_-]secret|session[_-]?key)$/i.test(key) || /token$/i.test(key) || /(?:^|[_-])(?:secret|password|passwd)$/i.test(key);
}
function safeURL(value) {
  try { const url = new URL(value); url.username = ''; url.password = ''; url.search = ''; url.hash = ''; return bounded(url.href); }
  catch { return '[URL]'; }
}
function headers(value = {}) {
  return bounded(Object.keys(value).sort().map(key => key + ': ' + (secretKey(key) ? '[скрыто]' : /^(referer|origin|location|from)$/i.test(key) ? safeURL(value[key]) : value[key])).join('\n'));
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
    if (/^[^\s&=]+=[^\s&]*(?:&[^\s&=]+=[^\s&]*)*$/.test(text)) {
      return bounded(text.split('&').map(pair => {
        const index = pair.indexOf('='), key = pair.slice(0, index);
        let decoded; try { decoded = decodeURIComponent(key.replace(/\+/g, ' ')); } catch { decoded = key; }
        return secretKey(decoded) ? key + '=[скрыто]' : pair;
      }).join('&'));
    }
    return bounded(text.replace(/("(?:[^"\r\n]*token|authorization|proxy[_-]authorization|cookie|set[_-]cookie|x[_-]api[_-]key|api[_-]?key|client[_-]secret|(?:[^"\r\n]*[_-])?(?:password|passwd|secret)|session[_-]?key)"\s*:\s*")[^"\r\n]*(")/gi, '$1[скрыто]$2')
      .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]+/gi, '$1[скрыто]'));
  }
}
// Only CDP's actual request headers are transport metadata. JSON bodies,
// account preferences, quoted text and application-specific headers are content;
// their locale-like field names do not describe the browser's system profile.
function auditRequestHeaders(header = {}, language = 'en-US') {
  const flags = new Set(), expected = String(language).toLowerCase();
  const primary = expected.split('-')[0];
  for (const [key, value] of Object.entries(header)) {
    if (key.toLowerCase() !== 'accept-language') continue;
    if (typeof value !== 'string' || !value || /[\r\n]/.test(value)) {
      flags.add('transport.Accept-Language.invalid'); continue;
    }
    for (const part of value.split(',')) {
      // Chromium may add the selected language's primary fallback. Any other
      // language, including a q=0 entry, still discloses a different preference.
      const match = /^[ \t]*([a-z]{1,8}(?:-[a-z0-9]{1,8})*)[ \t]*(?:;[ \t]*q=(?:0(?:\.[0-9]{0,3})?|1(?:\.0{0,3})?))?[ \t]*$/i.exec(part);
      if (!match) flags.add('transport.Accept-Language.invalid');
      else if (![expected, primary].includes(match[1].toLowerCase())) flags.add('transport.Accept-Language.mismatch');
    }
  }
  return [...flags];
}
function diagnostic(value) {
  // Diagnostics never receive bodies, headers, connection settings or subprocess stderr.
  return bounded(String(value).replace(/https?:\/\/[^\s]+/gi, url => safeURL(url))
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP скрыт]')
    .replace(/\b[0-9a-f]{0,4}:[0-9a-f:]{2,}(?:%\w+)?/gi, '[IP скрыт]')).slice(0, 1500);
}
module.exports = { LIMIT, bounded, secretKey, safeURL, headers, body, auditRequestHeaders, diagnostic };
