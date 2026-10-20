'use strict';
const net = require('node:net');
const os = require('node:os');
const countries = new Set(('AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW').split(' '));

function canonicalIP(value) {
  if (typeof value !== 'string' || !net.isIP(value.trim())) throw Error('Сервис не вернул корректный IP.');
  const ip = value.trim();
  return net.isIPv6(ip) ? new URL('http://[' + ip + ']').hostname.slice(1, -1).toLowerCase() : ip;
}

class IPPolicy {
  #pinned = null;
  #blocked = false;
  get blocked() { return this.#blocked; }
  get pinned() { return this.#pinned; }
  assertAvailable() { if (this.#blocked) throw Error('Сессия заблокирована до перезапуска Guard.'); }
  pin(result) {
    this.assertAvailable();
    if (this.#pinned) throw Error('Исходный IP уже закреплён.');
    const country = String(result.country_code || '').toUpperCase();
    if (result.success === false || !countries.has(country) || country === 'RU') {
      this.block(); throw Error('Страна не подтверждена или RU. Соединение заблокировано.');
    }
    try { this.#pinned = canonicalIP(result.ip); } catch (error) { this.block(); throw error; }
    return { ip: this.#pinned, country };
  }
  check(ip) {
    this.assertAvailable();
    let canonical;
    try { canonical = canonicalIP(ip); } catch (error) { this.block(); throw error; }
    if (!this.#pinned || canonical !== this.#pinned) {
      this.block(); throw Error('Внешний IP изменился. Сессия закрыта до перезапуска Guard.');
    }
  }
  block() { this.#blocked = true; }
}

function networkFingerprint() {
  return JSON.stringify(Object.entries(os.networkInterfaces()).flatMap(([name, list]) =>
    list.filter(x => !x.internal).map(x => [name, x.family, x.address, x.netmask, x.scopeid || 0])).sort());
}

function validateSettings(input) {
  const host = String(input.host || '').trim();
  const port = Number(input.port);
  if (!host || host.length > 253 || /[\s/@?#]/.test(host) || host.includes('://')) throw Error('Укажите хост SOCKS5 отдельно от порта.');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error('Неверный порт SOCKS5.');
  const username = String(input.username || ''), password = String(input.password || '');
  if (Buffer.byteLength(username) > 255 || Buffer.byteLength(password) > 255) throw Error('Логин и пароль SOCKS5: максимум 255 байт.');
  if (!username && password) throw Error('Для пароля нужен логин SOCKS5.');
  const timezone = String(input.timezone || 'Europe/Amsterdam');
  try { new Intl.DateTimeFormat('en-US', { timeZone: timezone }); } catch { throw Error('Неизвестный часовой пояс.'); }
  const language = String(input.language || 'en-US');
  if (!['en-US', 'en-GB', 'nl-NL', 'de-DE', 'fr-FR'].includes(language)) throw Error('Выберите язык из списка.');
  const interval = Number(input.interval || 5);
  if (![2, 5, 10, 30].includes(interval)) throw Error('Неверный интервал проверки IP.');
  return { host, port, username, password, timezone, language, interval,
    captureBodies: input.captureBodies === true, claudePath: String(input.claudePath || '') };
}

module.exports = { IPPolicy, canonicalIP, networkFingerprint, validateSettings };
