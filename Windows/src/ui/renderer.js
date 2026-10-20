'use strict';
const $ = id => document.getElementById(id);
const fields = ['claudePath', 'host', 'port', 'username', 'password', 'timezone', 'language', 'interval', 'captureBodies'];
const records = new Map(); let selected = '', state;
const node = (tag, text, cls) => { const result = document.createElement(tag); result.textContent = text; if (cls) result.className = cls; return result; };
function showState(value) {
  state = value;
  $('state').textContent = ({ idle: 'Готов к проверке', checking: 'Проверка подключения', starting: 'Проверяем профиль Claude', running: 'Claude под защитой Guard', blocked: 'Сессия закрыта' })[value.state] || value.state;
  $('message').textContent = value.message; $('lamp').className = 'lamp ' + value.state;
  $('country').textContent = value.country ? value.country + ' · IP закреплён' : 'IP не закреплён';
  const busy = value.state !== 'idle';
  for (const id of fields) $(id).disabled = busy;
  $('choose').disabled = busy; $('start').disabled = busy; $('stop').disabled = !['checking', 'starting', 'running'].includes(value.state);
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
  event.preventDefault(); $('start').disabled = true;
  const input = Object.fromEntries(fields.map(id => [id, $(id).type === 'checkbox' ? $(id).checked : $(id).value]));
  const result = await window.guard.start(input); $('password').value = ''; input.password = '';
  if (error(result)) $('start').disabled = state.state !== 'idle';
});
$('choose').addEventListener('click', async () => { const result = await window.guard.choose(); if (!error(result) && result) $('claudePath').value = result; });
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
  if (event.type === 'clear') { records.clear(); selected = ''; $('detail').replaceChildren(node('p', 'Выберите запрос для просмотра.', 'empty')); renderRecords(); }
});
window.guard.init().then(data => {
  if (error(data)) return;
  $('version').textContent = data.version;
  for (const id of fields) { if (id === 'password') continue; if ($(id).type === 'checkbox') $(id).checked = data.settings[id]; else $(id).value = data.settings[id]; }
  showState(data.state); data.logs.forEach(log); data.records.forEach(record);
  document.body.dataset.ready = 'true';
}).catch(() => { $('message').textContent = 'Не удалось открыть Guard. Перезапустите приложение.'; });
