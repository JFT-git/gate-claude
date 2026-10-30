(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.GuardViewModel = api;
})(typeof globalThis === 'object' ? globalThis : this, function () {
  'use strict';
  const active = ['checking', 'starting', 'running', 'rechecking'];
  function controls(state, pending = [], ready = true) {
    const phase = state?.state || 'idle', has = name => pending.includes(name);
    if (has('resetIP')) return { start: false, stop: false, restart: false, settings: false, progress: true, primary: null };
    return {
      start: ready && phase === 'idle' && !has('start') && !has('stop') && !has('restart'),
      stop: ready && (active.includes(phase) || phase === 'idle' && has('start')) && !has('stop') && !has('restart'),
      restart: ready && !state?.windowsApprovalPending && !has('restart') && !has('stop') && !has('start'),
      settings: ready && phase === 'idle' && !has('start') && !has('restart'),
      progress: ['checking', 'starting', 'rechecking'].includes(phase) || has('start') || has('restart') || has('stop'),
      primary: has('stop') || has('restart') ? null : phase === 'blocked' ? 'restart' : active.includes(phase) || has('start') ? 'stop' : 'start'
    };
  }
  function service(value) {
    const labels = {
      not_installed: ['Не установлена', 'Для установки требуется системное подтверждение Windows.'],
      installing: ['Установка', 'Дождитесь ответа Windows и подтверждения установки.'],
      running: ['Работает', 'Состояние подтверждено API службы.'],
      stopped: ['Остановлена', 'Служба установлена, но сейчас не работает.'],
      error: ['Ошибка службы', 'Не удалось подтвердить состояние службы. Повторите проверку.'],
      update_required: ['Требуется обновление', 'Обновление службы может потребовать административные права.']
    };
    if (!value?.available || !labels[value.state]) return { key: 'unavailable', label: 'API службы не подключён',
      message: 'Установка постоянной службы в этой сборке недоступна. Сейчас NetworkFence запрашивает разрешение Windows на каждую новую сессию Claude.', actions: [], busy: false };
    return { key: value.state, label: labels[value.state][0], message: labels[value.state][1],
      actions: Array.isArray(value.actions) ? value.actions.filter(x => ['install', 'start', 'stop', 'update', 'uninstall'].includes(x)) : [], busy: value.state === 'installing' };
  }
  return Object.freeze({ controls, service });
});
