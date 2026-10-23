'use strict';
const $ = id => document.getElementById(id);
const VM = window.GuardViewModel;
const fields = ['mode','claudeSource','claudePath','host','port','username','password','timezone','language','interval','captureBodies','codeEnabled'];
const records = new Map(), pending = new Set();
let selected = '', state = { state: 'idle' }, ready = false, finding = false, discoveryGeneration = 0, operationSerial = 0, serviceSnapshot;
const node = (tag, text, cls) => { const result = document.createElement(tag); result.textContent = text; if (cls) result.className = cls; return result; };
function failure(message) { $('errorText').textContent = message; $('errorBanner').hidden = false; }
function lastOperation(label, result, kind = 'info') {
  $('lastOperation').textContent = 'Последняя операция: ' + label + ' · ' + result + ' · ' + new Date().toLocaleTimeString();
  $('lastOperation').dataset.kind = kind;
}
function refreshControls() {
  const c = VM.controls(state, [...pending], ready);
  for (const id of ['start','stop','restart']) {
    $(id).disabled = !c[id]; $(id).classList.toggle('primary', c.primary === id && c[id]);
    $(id).classList.toggle('secondary', c.primary !== id || !c[id]); $(id).setAttribute('aria-busy', String(pending.has(id)));
  }
  for (const id of fields) $(id).disabled = !c.settings;
  $('choose').disabled = !c.settings || pending.has('choose');
  $('find').disabled = !c.settings || finding;
  $('activity').hidden = !c.progress;
  const activity = pending.has('restart') ? 'Перезапускаем Guard. Ожидаем новое окно…' : pending.has('stop') ? 'Передаём команду остановки…' : pending.has('start') && state.state === 'idle' ? 'Запрос запуска отправлен. Проверяем настройки и установленный Claude…' : state.message || 'Ожидаем ответ контроллера…';
  $('activityText').textContent = activity; $('activity').setAttribute('aria-valuetext', activity);
  $('approvalHint').hidden = state.windowsApprovalPending !== true;
  $('actionReason').textContent = state.windowsApprovalPending ? 'Ответьте на системный запрос Windows. Перезапуск станет доступен после ответа.' : state.state === 'blocked' ? 'Сессия закрыта. Для новой проверки перезапустите Guard; пароль прокси нужно будет ввести заново.' : c.progress ? 'Запуск и повторные проверки можно остановить. Повторный запуск во время выполнения недоступен.' : state.state === 'running' ? 'Claude запущен. Остановка закроет сессию; перезапуск заново откроет Guard.' : 'Запуск проверяет подключение. Перезапуск заново открывает Guard и закрывает его сессию Claude.';
  const socks = $('mode').value === 'socks5';
  $('proxyFields').hidden = !socks; $('networkHint').hidden = socks;
  for (const id of ['host','port','username','password']) $(id).disabled = !c.settings || !socks;
  $('host').required = socks; $('port').required = socks; $('claudePath').readOnly = $('claudeSource').value !== 'manual';
  $('export').disabled = records.size === 0 || pending.has('export');
  $('restartConfirmYes').disabled = !c.restart;
  for (const [id, key] of [['protocolSettings','protocolSettings'],['protocolCheck','protocolCheck'],['codeWorkspace','workspace'],['serviceRefresh','service']]) { $(id).disabled = !ready || pending.has(key); $(id).setAttribute('aria-busy', String(pending.has(key))); }
  for (const button of document.querySelectorAll('[data-service]')) button.disabled = pending.has('service') || VM.service(serviceSnapshot).busy;
  $('serviceActivity').hidden = !pending.has('service') && !VM.service(serviceSnapshot).busy;
}
function showState(value) {
  if (!value || !['idle','checking','starting','running','rechecking','blocked'].includes(value.state)) return;
  if (['idle','blocked'].includes(value.state) && value.state !== state.state) hideRestartConfirm();
  const previous = state; state = value; document.body.dataset.state = value.state;
  $('state').textContent = ({ idle: 'Готов к запуску', checking: 'Проверка подключения', starting: 'Запуск и проверка Claude', running: 'Claude под защитой Guard', rechecking: 'Трафик приостановлен', blocked: 'Сессия закрыта' })[value.state];
  $('message').textContent = value.message || 'Выберите подключение и запустите проверку.'; $('lamp').className = 'lamp ' + value.state;
  $('country').textContent = value.country ? value.country + ' · ' + (value.exitIP || 'IP закреплён') : 'IP не закреплён';
  if (value.profile) { $('profile').textContent = value.profile.timezone + ' · ' + value.profile.language; $('locale').textContent = 'Intl locale: ' + value.profile.locale; }
  else { $('profile').textContent = value.state === 'blocked' ? 'Соединение закрыто' : 'Ожидаем запуск Claude'; $('locale').textContent = 'Проверяются Intl, navigator и Accept-Language'; }
  if (value.state === 'running' && previous.state !== 'running') { $('errorBanner').hidden = true; lastOperation('Проверка сессии', 'профиль подтверждён'); }
  if (value.state === 'blocked' && previous.state !== 'blocked' && !pending.has('stop')) failure(value.message || 'Сессия закрыта. Откройте журнал и перезапустите Guard для новой проверки.');
  refreshControls();
}
async function perform(name, label, callback, resultText = 'готово') {
  if (pending.has(name)) return;
  const serial = ++operationSerial; pending.add(name); refreshControls();
  try {
    const result = await callback();
    if (result?.error) { if (serial === operationSerial) { failure(result.error); lastOperation(label, 'ошибка', 'error'); } return result; }
    if (serial === operationSerial) lastOperation(label, typeof resultText === 'function' ? resultText(result) : resultText);
    return result;
  } catch {
    if (serial === operationSerial) { failure('Не удалось выполнить действие «' + label + '». Повторите его или откройте журнал.'); lastOperation(label, 'нет подтверждения', 'error'); }
  } finally { pending.delete(name); refreshControls(); }
}
function showProtocol(value) {
  if (!value) return;
  $('protocolHint').textContent = value.defaultConfirmed ? 'Windows открывает ссылки входа Claude через Guard.' : value.skipped ? 'Регистрация обработчика ссылок проверяется в установленной Windows-сборке.' : value.registered ? 'В параметрах Windows выберите Claude Proxy Guard для ссылок claude, затем проверьте выбор.' : 'Обработчик входа пока не подтверждён. Проверьте выбор приложения в Windows.';
  document.body.dataset.protocolConfirmed = String(value.defaultConfirmed === true);
}
function discovered(value) {
  if (value?.error) { $('claudeStatus').textContent = value.error; return; }
  $('claudeSource').value = 'auto'; $('claudePath').value = value.path || ''; $('claudeStatus').textContent = value.message || 'Поиск завершён.';
  document.body.dataset.claudeFound = String(value.status === 'found'); refreshControls();
}
async function findClaude() {
  if (finding) return;
  const generation = ++discoveryGeneration; finding = true; refreshControls(); $('claudeStatus').textContent = 'Ищем Claude, включая WindowsApps…';
  try { const value = await window.guard.find(); if (generation === discoveryGeneration) discovered(value); }
  catch { if (generation === discoveryGeneration) $('claudeStatus').textContent = 'Поиск не завершился. Нажмите «Найти» или выберите EXE вручную.'; }
  finally { if (generation === discoveryGeneration) { finding = false; document.body.dataset.discoveryDone = 'true'; refreshControls(); } }
}
function showService(value) {
  serviceSnapshot = value; const presentation = VM.service(value);
  $('serviceState').textContent = presentation.label; $('serviceState').dataset.state = presentation.key;
  $('serviceMessage').textContent = presentation.message;
  $('serviceActions').hidden = !value?.available || presentation.actions.length === 0;
  for (const button of document.querySelectorAll('[data-service]')) { button.hidden = !presentation.actions.includes(button.dataset.service); button.disabled = presentation.busy || pending.has('service'); }
  $('serviceRefresh').disabled = pending.has('service');
  $('serviceActivity').hidden = !pending.has('service') && !presentation.busy;
}
async function refreshService() {
  if (pending.has('service')) return;
  pending.add('service'); refreshControls();
  try {
    const value = await window.guard.serviceStatus();
    if (value && !value.error) showService(value);
    else { $('serviceState').textContent = 'Служба не используется'; $('serviceState').dataset.state = 'unavailable'; $('serviceMessage').textContent = VM.service(null).message; $('serviceActions').hidden = true; }
  } catch {
    $('serviceState').textContent = 'Служба не используется'; $('serviceState').dataset.state = 'unavailable'; $('serviceMessage').textContent = VM.service(null).message; $('serviceActions').hidden = true;
  } finally { pending.delete('service'); refreshControls(); }
}
function log(value) {
  $('logsEmpty')?.remove(); const entry = node('div', '', 'log ' + value.kind), time = node('time', new Date(value.date).toLocaleString());
  time.dateTime = value.date; entry.append(time, node('span', value.message)); $('logs').prepend(entry);
  while ($('logs').children.length > 80) $('logs').lastChild.remove();
}
function detail() {
  const value = records.get(selected); if (!value) return;
  $('detail').replaceChildren(node('pre', value.method + ' ' + value.url, 'url'));
  for (const [title, text] of [['Статус', value.status ?? value.note],['Заголовки запроса',value.requestHeaders],['Отправлено',value.sent],['Заголовки ответа',value.responseHeaders],['Получено',value.received]]) if (text !== '' && text != null) $('detail').append(node('h3',title),node('pre',String(text)));
}
let renderTimer;
function renderRecords() {
  const focusedRecord = $('requests').contains(document.activeElement) ? document.activeElement.dataset.recordId : undefined;
  renderTimer = null; $('count').textContent = records.size;
  if (!records.size) $('requests').replaceChildren(node('p','Доступные веб-запросы появятся после запуска Claude.','empty'));
  else $('requests').replaceChildren(...[...records.values()].reverse().map(value => {
    const button = node('button','','request' + (selected === value.id ? ' selected' : '')); button.type = 'button'; button.dataset.recordId = String(value.id);
    button.append(node('span',(value.status || '·') + ' ' + value.method),document.createTextNode(value.url));
    button.setAttribute('aria-pressed',String(selected === value.id)); button.addEventListener('click',()=>{selected=value.id;renderRecords();}); return button;
  }));
  if (focusedRecord !== undefined) {
    const button = [...$('requests').querySelectorAll('button')].find(button => button.dataset.recordId === focusedRecord);
    button?.focus({preventScroll: true});
  }
  detail(); refreshControls();
}
function record(value) { records.set(value.id,value); while(records.size>200) records.delete(records.keys().next().value); if(!renderTimer) renderTimer=setTimeout(renderRecords,120); }
function tab(traffic, focus = false) {
  $('traffic').hidden=!traffic; $('logs').hidden=traffic; $('export').hidden=!traffic;
  for (const id of ['trafficTab','logsTab']) { const selected=id===(traffic?'trafficTab':'logsTab'); $(id).classList.toggle('active',selected); $(id).setAttribute('aria-selected',String(selected)); $(id).tabIndex=selected?0:-1; }
  if(focus) $(traffic?'trafficTab':'logsTab').focus();
}
$('settings').addEventListener('submit',async event=>{
  event.preventDefault(); if(!VM.controls(state,[...pending],ready).start) return;
  const input=Object.fromEntries(fields.map(id=>[id,$(id).type==='checkbox'?$(id).checked:$(id).value]));
  await perform('start','Запуск',async()=>{
    try { const result=await window.guard.start(input); if(result?.state)showState(result); return result?.state==='blocked'?{error:result.message||'Запуск остановлен контроллером.'}:result; }
    finally { $('password').value=''; input.password=''; }
  },result=>result?.state==='running'?'сессия подтверждена':'запрос принят контроллером');
});
$('stop').addEventListener('click',()=>{if(VM.controls(state,[...pending],ready).stop) void perform('stop','Остановка',async()=>{const result=await window.guard.stop();if(result?.state)showState(result);return result;},'команда отправлена');});
function hideRestartConfirm(){
  if($('restartConfirm').hidden)return;
  if($('restartConfirm').contains(document.activeElement))$('restart').focus();
  $('restartConfirm').hidden=true;
}
function performRestart(){if(!VM.controls(state,[...pending],ready).restart){hideRestartConfirm();return;}hideRestartConfirm();void perform('restart','Перезапуск Guard',()=>window.guard.restart(),'ожидаем новое окно');}
$('restart').addEventListener('click',()=>{
  if(!VM.controls(state,[...pending],ready).restart)return;
  const sessionActive=['checking','starting','running','rechecking'].includes(state?.state);
  if(sessionActive){$('restartConfirm').hidden=false;$('restartConfirmYes').focus();return;}
  performRestart();
});
$('restartConfirmYes').addEventListener('click',performRestart);
$('restartConfirmNo').addEventListener('click',()=>{hideRestartConfirm();});
$('restartConfirm').addEventListener('keydown',event=>{if(event.key==='Escape')hideRestartConfirm();});
$('choose').addEventListener('click',()=>{if(!VM.controls(state,[...pending],ready).settings)return;void perform('choose','Выбор Claude',async()=>{
  const result=await window.guard.choose();if(!result?.error&&result){discoveryGeneration++;finding=false;$('claudeSource').value='manual';$('claudePath').value=result;$('claudeStatus').textContent='Путь выбран вручную';document.body.dataset.discoveryDone='true';}return result;
},result=>result?'путь выбран':'выбор отменён');});
$('find').addEventListener('click',()=>{if(VM.controls(state,[...pending],ready).settings)void findClaude();});
$('protocolSettings').addEventListener('click',()=>void perform('protocolSettings','Параметры ссылок входа',()=>window.guard.protocolSettings(),'параметры Windows открыты'));
$('protocolCheck').addEventListener('click',()=>void perform('protocolCheck','Проверка ссылок входа',async()=>{const value=await window.guard.protocolCheck();if(!value?.error)showProtocol(value);return value;},result=>result?.defaultConfirmed?'Guard выбран':'выбор Guard не подтверждён'));
$('mode').addEventListener('change',()=>{if($('mode').value==='network')$('password').value='';refreshControls();});
$('codeWorkspace').addEventListener('click',()=>void perform('workspace','Открытие рабочей папки',()=>window.guard.codeWorkspace(),'папка открыта'));
$('export').addEventListener('click',()=>{if(records.size)void perform('export','Экспорт трафика',()=>window.guard.export(),result=>result?'файл сохранён':'сохранение отменено');});
for(const id of ['openLogs','errorLogs'])$(id).addEventListener('click',()=>{tab(false);$('logs').focus();});
$('dismissError').addEventListener('click',()=>{$('errorBanner').hidden=true;$('sessionActions').focus();});
$('trafficTab').addEventListener('click',()=>tab(true));$('logsTab').addEventListener('click',()=>tab(false));
for(const id of ['trafficTab','logsTab'])$(id).addEventListener('keydown',event=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(event.key)){event.preventDefault();tab(event.key==='End'||event.key!=='Home'&&id==='logsTab',true);}});
$('serviceRefresh').addEventListener('click',()=>{if(!pending.has('service'))void refreshService();});
for(const button of document.querySelectorAll('[data-service]'))button.addEventListener('click',()=>{
  const action=button.dataset.service;if(pending.has('service')||!serviceSnapshot?.available||!VM.service(serviceSnapshot).actions.includes(action))return;
  void perform('service','Управление службой',()=>window.guard.serviceOperation(action),'ответ получен').then(result=>{if(result&&!result.error)showService(result);else if(serviceSnapshot)showService(serviceSnapshot);});
});
const unsubscribe=window.guard.subscribe(event=>{
  if(event.type==='protocol')showProtocol(event.data);if(event.type==='state')showState(event.data);if(event.type==='log')log(event.data);if(event.type==='record')record(event.data);if(event.type==='discovery')discovered(event.data);if(event.type==='service')showService(event.data);
  if(event.type==='clear'){records.clear();selected='';$('detail').replaceChildren(node('p','Выберите запрос для просмотра.','empty'));renderRecords();}
});
window.addEventListener('beforeunload',()=>{unsubscribe?.();clearTimeout(renderTimer);},{once:true});
window.guard.init().then(data=>{
  if(data?.error){failure(data.error);$('state').textContent='Не удалось открыть Guard';return;}
  $('version').textContent=data.version;showProtocol(data.protocol);
  for(const id of fields){if(id==='password')continue;if($(id).type==='checkbox')$(id).checked=data.settings[id]===true;else if(data.settings[id]!==undefined)$(id).value=data.settings[id];}
  ready=true;showState(data.state);data.logs.forEach(log);data.records.forEach(record);document.body.dataset.ready='true';
  if($('claudeSource').value==='auto')void findClaude();else{$('claudeStatus').textContent='Путь выбран вручную';document.body.dataset.discoveryDone='true';refreshControls();}
  void refreshService();
}).catch(()=>{failure('Не удалось получить состояние Guard. Закройте и заново откройте приложение.');$('state').textContent='Состояние недоступно';});
