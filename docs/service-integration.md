# Интеграция системной службы Windows

## Реализованная архитектура

`GuardService.exe` — постоянная auto-start служба `ClaudeProxyGuard` с API 1. Production создаёт `new ServiceIntegration(new NativeServiceBackend(...))`; запуск Claude проходит через `GuardController → NetworkFence.prepare → serviceLaunch → GuardService → NetworkFence`. Служба не запускает Claude, не принимает произвольный executable или arguments и не выполняет shell/PowerShell-команды клиента.

При установке и privileged update `GuardService.exe` и неизменный `NetworkFence.exe` копируются в `C:\ProgramData\Claude Proxy Guard\Service`. Изменять файлы и каталог могут только SYSTEM и Administrators. Служба запускает только защищённый `NetworkFence.exe` с аргументами `--pipe gate-network-fence-[32hex] --token [64hex]`; SHA-256 NetworkFence закреплён в GuardService и сверяется перед установкой и запуском. Существующая WFP-логика `NetworkFence.cs` не изменена.

User-writable `GuardService.exe` из ресурсов приложения является requester/installer. Повышенный процесс из такого источника возможен только после явного UAC для install/update/uninstall. В обычной сессии requester работает без повышения, а SYSTEM запускает лишь binary из защищённого каталога. Silent fallback на запуск user-writable helper как SYSTEM отсутствует.

## UAC и жизненный цикл

- **Первая установка:** NSIS после копирования файлов вызывает `resources\GuardService.exe --request-install --owner 0` и ждёт завершения. Один системный запрос разрешает копирование, создание и запуск службы. Ошибка, включая native exit 2, прерывает установку и не маскируется как успех.
- **Повторный `--request-install`:** сначала читает authoritative status. Если текущая совместимая служба уже running, возвращает `elevated:false` и не создаёт UAC. Current stopped запускается через узкий SCM request без повторной установки.
- **Обычные сессии:** ensure/read-back подтверждает running и API 1; per-session UAC не нужен. Backend сериализует операции, поэтому одновременные запуски не создают параллельные install/UAC.
- **Обновление приложения:** если GuardService и NetworkFence byte-identical текущим защищённым binaries, UAC не вызывается. NSIS в режиме `--updated` не вызывает `--request-uninstall` и сохраняет текущую службу; ручной uninstall выполняет отдельный owned request. Изменение любого из binaries означает `update_required` и новый privileged update с UAC. Пересборка старым stock `csc` может изменить bytes даже без изменения исходника; это тоже privileged binary update.
- **Start/stop:** отдельные фиксированные native requests. Service DACL даёт Authenticated Users только query/start/stop/read control, а SYSTEM/Administrators — full control. Под общим `Sync` stop сначала запрещает новые launches и атомарно проверяет brokers. При active broker accepting восстанавливается, а stop/update/uninstall завершаются ошибкой без stopped/deleted service с новым broker. Уже принятые, но ещё не зарегистрированные clients проходят тот же admission gate.
- **Удаление:** требуется явный `--request-uninstall` и elevation. При активных brokers действие скрыто из capabilities и повторно отклоняется перед stop. ImagePath службы должен точно соответствовать owned protected binary. Удаляются только два известных helper и пустые собственные каталоги; чужие файлы, ACL, службы, профиль, CodeState, Workspace, settings и ip-memory не затрагиваются. Удаление и privileged update не обещаются бесплатными.

Install/update/uninstall/start/stop сериализуются `Global\ClaudeProxyGuard.Management.v1` между процессами и Windows terminal sessions с bounded wait; Authenticated Users получают только synchronize/modify-state, без write DACL/owner. SDDL не назначает владельца: им становится фактический creator mutex, поэтому standard user может создать его при первом start/stop. Mutex нужен только для сериализации, не для авторизации: install/uninstall по-прежнему требуют administrator, а start/stop разрешены отдельной service policy. Status и launch не ждут management mutex. Update/uninstall дополнительно выполняют read-only enumeration процессов по полному пути protected NetworkFence до stop и повторно перед replace/delete. Поэтому живой orphan broker после остановки или crash службы блокирует замену и удаление без попытки завершить чужой процесс.

Portable ZIP содержит тот же service requester и при первой защищённой сессии тоже требует установку службы с UAC. Portable не означает отсутствие системных изменений. Тестовые/source fixtures, которые не передают `serviceLaunch`, сохраняют старый `options.launch`/elevation mock; production main всегда получает real backend и не откатывается на per-session helper при ошибке службы.

## Авторизация privileged pipe

Имя pipe: `\\.\pipe\ClaudeProxyGuard.Service.v1`. DACL разрешает обмен Authenticated Users и полный доступ SYSTEM/Administrators. Для каждого launch служба:

1. Ограничивает одно сообщение 2048 bytes, применяет timeouts, допускает до 4 клиентов и до 16 broker processes; повторное имя pipe отклоняется.
2. Читает только `status` или `launch\t[base64 root]\t[pipe]\t[token]`.
3. Через impersonation получает SID клиента и его `ProfileImagePath` из `HKLM\...\ProfileList\<SID>`.
4. Требует canonical local root строго внутри профиля именно этого SID, имя каталога `Runtime-[24hex]` и `guard-manifest.json`. UNC, reparse points, выход за профиль и malformed base64 отклоняются.
5. Запускает только protected NetworkFence. NetworkFence независимо повторяет полную проверку inventory, manifest, списка EXE, links/hardlinks и WFP install/remove. Случайный token и обратное подключение к user pipe сохранены.

Renderer получает только прежние `window.guard.serviceStatus()` и `serviceOperation(action)` через проверенный Electron IPC. Privileged pipe и `NativeServiceBackend` доступны только main process. Ошибки native/service возвращаются как ограниченные коды и фиксированные сообщения без token, аргументов, путей профиля или stderr.

## Статусы и контракт JS

`NativeServiceBackend` вызывает только `--status`, `--request-install`, `--start`, `--stop`, `--request-uninstall` и фиксированный `--launch`. Ответы имеют строгую schema и точный набор полей. `ServiceIntegration` допускает состояния `not_installed`, `installing`, `running`, `stopped`, `error`, `update_required` и operations `install/start/stop/update/uninstall` только из authoritative capabilities.

`sessionRoutingSupported:true` допустимо исключительно для running service с совместимым API и подтверждённым pipe handshake. Любая ошибка, stopped, not installed или update required даёт `false`. После install/start/stop/update/uninstall адаптер перечитывает статус, а не считает возврат операции доказательством состояния. Controller не запускает Claude без последующего точного WFP proof от NetworkFence; stage/approval, timeouts, close/fatal и persistent BLOCK semantics сохранены.

## Проверено и оставшиеся ограничения

На выделенном Windows 11 x64 ПК выполнены stock `.NET Framework` csc build, clean install, running read-back, no-repeat install (`elevated:false`), native stop/start, privileged update, request install/uninstall, ACL/status checks и реальный service→NetworkFence handshake с WFP install/remove. Root вне профиля отклонён. Interactive limited-token install с видимым UAC, создание/open Global mutex, stop/start и две последовательные service-сессии подтверждены. Chat network и SOCKS5 через SYSTEM service прошли running, same-PID freeze/thaw, kill switch, restart и cleanup. Реальный `codeEnabled` сеанс через SOCKS5 дополнительно подтвердил `CodeHost --prepare-state`, `CodeFenceSession` с 10 фильтрами и cleanup через SYSTEM service. Windows-native NSIS прошёл fresh install, current same-version update и manual uninstall; при update сохранились service process и byte-identical protected binaries, после uninstall service и protected root отсутствуют.

**Ограничения текущей валидации:** A→B между разными версиями, differential download и реальная Inno migration не выполнялись. Собранный на macOS через Wine NSIS uninstaller не прошёл собственную integrity check; успешный lifecycle относится к Windows-native NSIS build, integrity checks не отключались. Roaming/UNC/reparse profile paths fail closed; их поддержка не заявляется. Реальный account login и физическая смена WAN в synthetic TLS fixture не проверялись.
