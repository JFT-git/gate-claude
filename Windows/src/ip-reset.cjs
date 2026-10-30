'use strict';
// Confirmation comes from the trusted main-process dialog, never renderer data.
async function resetIPWithConfirmation(controller, confirm) {
  if (!controller.canResetIP()) throw Error('Сначала остановите сессию Claude и дождитесь завершения запуска.');
  if (await confirm() !== true) return { canceled: true };
  // The controller rechecks availability after the asynchronous warning.
  return controller.resetIP();
}
module.exports = { resetIPWithConfirmation };
