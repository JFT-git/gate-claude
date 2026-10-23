'use strict';
const path = require('node:path');
const { promisify } = require('node:util');
const run = promisify(require('node:child_process').execFile);
class FenceLaunchError extends Error {}
const fixedError = message => new FenceLaunchError(message);
const elevationFailure = error => error instanceof FenceLaunchError ? error : Error('Подтверждение Windows отменено или запуск защиты отклонён. Claude не запущен.');

function ownerHandle(value) {
  if (value == null) return '0';
  if (!Buffer.isBuffer(value) || ![4, 8].includes(value.length)) throw fixedError('Не удалось определить окно Guard для запроса Windows.');
  const handle = value.length === 8 ? value.readBigUInt64LE() : BigInt(value.readUInt32LE());
  if (handle === 0n || handle > 0x7fffffffffffffffn) throw fixedError('Окно Guard недоступно для запроса Windows.');
  return handle.toString(16);
}

function launchError(code) {
  const messages = {
    1223: 'Системный запрос Windows отменён. Claude не запущен.',
    5: 'Windows отказала в запуске сетевой защиты. Проверьте журнал «Безопасность Windows». Claude не запущен.',
    1260: 'Запуск сетевой защиты запрещён политикой Windows. Claude не запущен.',
    225: 'Безопасность Windows заблокировала сетевой помощник. Claude не запущен.',
    226: 'Безопасность Windows удалила сетевой помощник. Claude не запущен.',
    1400: 'Окно Guard закрылось до системного запроса. Перезапустите Guard.',
    2: 'В комплекте Guard отсутствует сетевой помощник. Распакуйте весь ZIP заново.',
    193: 'Windows не поддерживает этот сетевой помощник. Нужна сборка Windows x64.'
  };
  return fixedError((messages[code] || 'Windows не разрешила запуск сетевой защиты. Claude не запущен.') + ' Код Windows: ' + code + '.');
}

async function requestElevation({ helper, pipeName, token, ownerWindow }) {
  if (!path.isAbsolute(helper || '') || !/^gate-network-fence-[a-f0-9]{32}$/.test(pipeName || '') || !/^[a-f0-9]{64}$/.test(token || '')) throw fixedError('Неверный запрос сетевой защиты.');
  const owner = ownerHandle(ownerWindow);
  let output;
  try {
    // Only this ordinary-user requester is hidden. Its native ShellExecuteEx
    // binds the real Windows consent UI to Guard and uses SW_SHOWNORMAL.
    // No PowerShell, shell command, elevation fallback or runtime launch here.
    const result = await run(helper, ['--request-elevation', '--owner', owner, '--pipe', pipeName, '--token', token],
      { windowsHide: true, timeout: 0, maxBuffer: 4096 });
    output = JSON.parse(result.stdout.replace(/^\uFEFF/, '').trim());
  } catch {
    throw fixedError('Не удалось запустить системный запрос из комплекта Guard. Проверьте «Журнал защиты» в «Безопасность Windows» и распакуйте весь ZIP в локальную папку. Claude не запущен.');
  }
  if (!output || Array.isArray(output) || Object.keys(output).sort().join(',') !== 'code,launched,version' || output.version !== 1 || typeof output.launched !== 'boolean' || !Number.isInteger(output.code) || output.code < 0 || output.code > 65535 || output.launched !== (output.code === 0)) throw fixedError('Системный помощник вернул неподтверждённый результат. Claude не запущен.');
  if (!output.launched) throw launchError(output.code);
}

module.exports = { requestElevation, ownerHandle, elevationFailure };
