'use strict';
// UI integration boundary only. No service implementation, registry/SCM access,
// elevation, process launch or assumption about an installed service lives here.
const STATES = Object.freeze(['not_installed', 'installing', 'running', 'stopped', 'error', 'update_required']);
const OPERATIONS = Object.freeze(['install', 'start', 'stop', 'update', 'uninstall']);
const unavailable = () => Object.freeze({ schema: 1, available: false, state: 'unavailable',
  code: 'SERVICE_API_UNAVAILABLE', version: null, actions: [], sessionRoutingSupported: false });
function validateStatus(value) {
  if (!value || value.schema !== 1 || value.available !== true || !STATES.includes(value.state) ||
      !Array.isArray(value.actions) || value.actions.some(action => !OPERATIONS.includes(action)) ||
      new Set(value.actions).size !== value.actions.length ||
      value.version !== null && (typeof value.version !== 'string' || !/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(value.version))) throw Error('SERVICE_STATUS_INVALID');
  return Object.freeze({ schema: 1, available: true, state: value.state, code: null,
    version: value.version, actions: Object.freeze(value.actions.slice()),
    // A future backend must separately wire the controller to a service before
    // it can remove per-session UAC. This UI adapter does not do that wiring.
    sessionRoutingSupported: false });
}
class ServiceIntegration {
  constructor(backend = null) { this.backend = backend; this.pending = false; }
  async status() {
    if (!this.backend) return unavailable();
    try { return validateStatus(await this.backend.getStatus()); }
    catch { return Object.freeze({ schema: 1, available: true, state: 'error', code: 'SERVICE_STATUS_FAILED', version: null, actions: [], sessionRoutingSupported: false }); }
  }
  async invoke(action) {
    if (!OPERATIONS.includes(action)) return { error: 'Неизвестное действие службы.', code: 'SERVICE_ACTION_INVALID' };
    if (!this.backend) return { error: 'API системной службы отсутствует в этой сборке. Установка службы недоступна.', code: 'SERVICE_API_UNAVAILABLE' };
    if (this.pending) return { error: 'Дождитесь завершения текущего действия службы.', code: 'SERVICE_BUSY' };
    this.pending = true;
    try {
      const current = await this.status();
      if (!current.actions.includes(action) || typeof this.backend[action] !== 'function') return { error: 'Действие недоступно в текущем состоянии службы.', code: 'SERVICE_ACTION_UNAVAILABLE' };
      // Only a real backend can perform an operation. A successful method return
      // is not an installed/running state: read back authoritative status.
      await this.backend[action]();
      return await this.status();
    } catch { return { error: 'Действие службы не завершено. Откройте журнал службы или повторите проверку состояния.', code: 'SERVICE_OPERATION_FAILED' }; }
    finally { this.pending = false; }
  }
}
module.exports = { ServiceIntegration, STATES, OPERATIONS, validateStatus };
