'use strict';
const RELEASES_URL = 'https://github.com/JFT-git/gate-claude/releases';

function createUpdateMenu({ Menu, onCheck, onInstall, onOpenReleases }) {
  if (!Menu?.buildFromTemplate || typeof onCheck !== 'function' || typeof onInstall !== 'function' || typeof onOpenReleases !== 'function') throw Error('Invalid update menu callbacks.');
  const menu = Menu.buildFromTemplate([{ label: 'Обновления', submenu: [
    { label: 'Проверка обновлений ещё не выполнялась', enabled: false },
    { label: 'Проверить обновления…', click: onCheck },
    { label: 'Установить и перезапустить…', visible: false, click: onInstall },
    { type: 'separator' },
    { label: 'Открыть страницу выпусков', click: () => onOpenReleases(RELEASES_URL) }
  ] }]);
  const items = menu.items[0].submenu.items;
  const [status, check, install] = items;
  function update(snapshot = {}) {
    const state = ['idle', 'checking', 'available', 'downloading', 'downloaded', 'installing', 'error'].includes(snapshot.state) ? snapshot.state : 'idle';
    const supported = snapshot.supported === true;
    const labels = {
      idle: snapshot.checkedAt ? 'Установлена последняя версия' : 'Проверка при запуске и раз в 24 часа',
      checking: 'Проверяем стабильный выпуск…',
      available: 'Доступна версия ' + snapshot.version,
      downloading: 'Загружаем обновление…',
      downloaded: 'Версия ' + snapshot.version + ' готова к установке',
      installing: 'Устанавливаем обновление…',
      error: 'Проверка не удалась; Guard продолжает работу'
    };
    status.label = supported ? labels[state] : snapshot.reason === 'portable' ? 'ZIP-сборка не поддерживает автообновление' : 'Автообновление недоступно';
    check.enabled = supported && ['idle', 'error'].includes(state);
    install.enabled = supported && state === 'downloaded';
    install.visible = supported && state === 'downloaded';
  }
  update();
  return { menu, update };
}
module.exports = { createUpdateMenu, RELEASES_URL };
