'use strict';
const $ = id => document.getElementById(id);
const fields = ['mode', 'claudeSource', 'claudePath', 'host', 'port', 'username', 'password', 'timezone', 'language', 'interval', 'captureBodies'];
const records = new Map(); let selected = '', state, finding = false, discoveryGeneration = 0;
const node = (tag, text, cls) => { const result = document.createElement(tag); result.textContent = text; if (cls) result.className = cls; return result; };
function connectionMode() {
  const socks = $('mode').value === 'socks5', busy = state && state.state !== 'idle';
  $('proxyFields').hidden = !socks; $('networkHint').hidden = socks;
  for (const id of ['host', 'port', 'username', 'password']) $(id).disabled = busy || !socks;
  $('host').required = socks; $('port').required = socks;
  $('claudePath').readOnly = $('claudeSource').value !== 'manual';
  $('find').disabled = busy || finding;
}
function discovered(value) {
  if (error(value)) { $('claudeStatus').textContent = value.error; return; }
  $('claudeSource').value = 'auto'; $('claudePath').value = value.path || '';
  $('claudeStatus').textContent = value.message;
  document.body.dataset.claudeFound = String(value.status === 'found'); connectionMode();
}
async function findClaude() {
  const generation = ++discoveryGeneration; finding = true; connectionMode();
  $('claudeStatus').textContent = 'Ищем установленный Claude, включая WindowsApps…';
  try { const value = await window.guard.find(); if (generation === discoveryGeneration) discovered(value); }
  catch { $('claudeStatus').textContent = 'Поиск не завершился. Нажмите «Найти» повторно.'; }
  finally { if (generation === discoveryGeneration) { finding = false; document.body.dataset.discoveryDone = 'true'; connectionMode(); } }
}
function showState(value) {
  state = value;
  $('state').textContent = ({ idle: 'Готов к проверке', checking: 'Проверка подключения', starting: 'Проверяем профиль Claude', rechecking: 'Трафик приостановлен', running: 'Claude под защитой Guard', blocked: 'Сессия закрыта' })[value.state] || value.state;
  $('message').textContent = value.message; $('lamp').className = 'lamp ' + value.state;
  $('country').textContent = value.country ? value.country + ' · ' + (value.exitIP || 'IP закреплён') : 'IP не закреплён';
  const busy = value.state !== 'idle';
  for (const id of fields) $(id).disabled = busy;
  $('choose').disabled = busy; $('start').disabled = busy; $('stop').disabled = !['checking', 'starting', 'running', 'rechecking'].includes(value.state);
  connectionMode();
  if (value.profile) { $('profile').textContent = value.profile.timezone + ' · ' + value.profile.language; $('locale').textContent = 'Intl locale: ' + value.profile.locale; }
  else { $('profile').textContent = value.state === 'blocked' ? 'Соединение закрыто' : 'Ожидаем запуск Claude'; $('locale').textContent = 'Проверяются Intl, navigator и Accept-Language'; }
}
function log(value) {
  const entry = node('div', '', 'log ' + value.kind);
  entry.append(node('time', new Date(value.date).toLocaleString()), node('span', value.message));
  $('logs').prepend(entry); while ($('logs').children.length > 80) $('logs').lastChild.remove();
}
function detail() {
  const value = records.get(selected); if (!value) return;
  $('detail').replaceChildren(node('pre', value.method + ' ' + value.url, 'url'));
  for (const [title, text] of [['Статус', value.status ?? value.note], ['Заголовки запроса', value.requestHeaders], ['Отправлено', value.sent], ['Заголовки ответа', value.responseHeaders], ['Получено', value.received]]) {
    if (text !== '' && text != null) $('detail').append(node('h3', title), node('pre', String(text)));
  }
}
let renderTimer;
function renderRecords() {
  renderTimer = null; $('count').textContent = records.size;
  const list = [...records.values()].reverse().map(value => {
    const button = node('button', '', 'request' + (selected === value.id ? ' selected' : ''));
    button.append(node('span', (value.status || '·') + ' ' + value.method), document.createTextNode(value.url));
    button.addEventListener('click', () => { selected = value.id; renderRecords(); }); return button;
  });
  $('requests').replaceChildren(...list); detail();
}
function record(value) { records.set(value.id, value); while (records.size > 200) records.delete(records.keys().next().value); if (!renderTimer) renderTimer = setTimeout(renderRecords, 120); }
function error(value) { if (value?.error) { $('message').textContent = value.error; return true; } return false; }
$('settings').addEventListener('submit', async event => {
  event.preventDefault();
  const input = Object.fromEntries(fields.map(id => [id, $(id).type === 'checkbox' ? $(id).checked : $(id).value]));
  const previous = state; showState({ ...state, state: 'checking', message: 'Ищем Claude и проверяем подключение…' });
  const result = await window.guard.start(input); $('password').value = ''; input.password = '';
  if (result?.error) { showState(previous); error(result); } else showState(result);
});
$('choose').addEventListener('click', async () => {
  const result = await window.guard.choose();
  if (!error(result) && result) { discoveryGeneration++; finding = false; $('claudeSource').value = 'manual'; $('claudePath').value = result; $('claudeStatus').textContent = 'Путь выбран вручную'; connectionMode(); }
});
$('find').addEventListener('click', findClaude);
$('mode').addEventListener('change', () => { if ($('mode').value === 'network') $('password').value = ''; connectionMode(); });
$('stop').addEventListener('click', () => window.guard.stop());
$('restart').addEventListener('click', () => { $('restart').disabled = true; window.guard.restart(); });
$('export').addEventListener('click', async () => error(await window.guard.export()));
function tab(traffic) {
  $('traffic').hidden = !traffic; $('logs').hidden = traffic;
  $('trafficTab').classList.toggle('active', traffic); $('logsTab').classList.toggle('active', !traffic); $('export').hidden = !traffic;
}
$('trafficTab').addEventListener('click', () => tab(true)); $('logsTab').addEventListener('click', () => tab(false));
window.guard.subscribe(event => {
  if (event.type === 'state') showState(event.data);
  if (event.type === 'log') log(event.data);
  if (event.type === 'record') record(event.data);
  if (event.type === 'discovery') discovered(event.data);
  if (event.type === 'clear') { records.clear(); selected = ''; $('detail').replaceChildren(node('p', 'Выберите запрос для просмотра.', 'empty')); renderRecords(); }
});
window.guard.init().then(data => {
  if (error(data)) return;
  $('version').textContent = data.version;
  for (const id of fields) { if (id === 'password') continue; if ($(id).type === 'checkbox') $(id).checked = data.settings[id]; else $(id).value = data.settings[id]; }
  showState(data.state); data.logs.forEach(log); data.records.forEach(record);
  document.body.dataset.ready = 'true';
  if ($('claudeSource').value === 'auto') findClaude();
  else { $('claudeStatus').textContent = 'Путь выбран вручную'; document.body.dataset.discoveryDone = 'true'; connectionMode(); }
}).catch(() => { $('message').textContent = 'Не удалось открыть Guard. Перезапустите приложение.'; });
