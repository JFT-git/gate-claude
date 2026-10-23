# Сборки и релиз

## Поддерживаемая матрица

- Windows 10/11 **x64**: Electron 44.9.2, Node >=22.12 для сборки, .NET Framework C# compiler для native-помощников. Portable ZIP; подготовлен Inno Setup 6.3+ установщик текущего пользователя. ARM64 и x86 не заявлены.
- macOS **13+ universal arm64 + x86_64**: Xcode Command Line Tools/SDK, SwiftUI/AppKit/Network, clang, codesign, lipo, ditto, hdiutil. Переносимый `.app` в ZIP и DMG для drag-and-drop установки. Это не PKG и не установка службы.
- Linux не поддерживается. Наличие universal-секции не означает проверенного исполнения на Intel. Cross-build Windows не является запуском Windows.

## Windows

```powershell
.\packaging\windows\package.ps1 -CodeToolsDir C:\verified\CodeTools -InnoCompiler 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe' -ArtifactDir C:\fresh\release
```

InnoCompiler необязателен: без него создаётся только ZIP, статус установщика — NOT_BUILT. Комплекты CodeTools обязательны для полного Code-релиза. Их готовит `Windows/scripts/prepare-code-tools.cjs` из закреплённых исходников Git/PowerShell и bootstrap; произвольный ZIP не принимается. Native-компиляция использует существующие исходники, движок не подменяется.

На macOS Windows ZIP можно собрать существующим `Windows/scripts/package.cjs` с `--host`, `--fence`, `--code-host`, `--code-tools-dir` и при необходимости `--electron-zip-dir`. Помощники должны соответствовать опубликованным исходникам и хешам; отсутствие Windows-компилятора нельзя замаскировать чужим бинарником. Проверяйте source commit, byte-match ASAR и хеши helper/sidecar.

`Guard.iss` устанавливает только приложение: `PrivilegesRequired=lowest`, каталог пользователя, без HKLM/SCM/служб/драйверов и без автоматического запуска. Он не завершает принудительно активную защищённую сессию. Перед обновлением/удалением пользователь должен выполнить штатную остановку и закрыть Guard. Профиль и документы не удаляются. Удаление собственных HKCU регистраций условно по marker и полному пути EXE; чужая установка не затрагивается.

Подпись Authenticode не настроена. Неподписанный Setup.exe может вызвать предупреждение ОС; успешная компиляция установщика не означает успешную установку, удаление или прохождение SmartScreen.

## macOS

```sh
bash test.sh
bash packaging/macos/package.sh /absolute/path/to/fresh-release
```

`build.sh` компилирует обе архитектуры и применяет ad-hoc codesign. Пакетный скрипт проверяет lipo/codesign, создаёт ZIP, DMG, SHA-256 и build-status. Секретов Developer ID/notarytool и настроенного Apple-профиля в workflow нет. Developer ID и нотариализация не выполняются и не заявляются. Для подписанного релиза нужен отдельный проверенный канал подписания; ключи не коммитятся и не копируются в артефакты.

## Проверки

- `cd Windows && npm test`: платформенные skipped должны быть перечислены, а не объявлены PASS.
- `Windows/scripts/ci-windows.ps1`: отдельные реальные Windows/native проверки; потенциально устанавливают временные собственные политики на выделенном runner. Нужны корректная сборка всех native-зависимостей и права, описанные самим скриптом. Этот legacy-скрипт не используется как доказательство нового UI.
- `Windows/scripts/ui-smoke.cjs`: тест локального renderer через Electron, отдельный temporary профиль и только тестовые bridge responses. Он проверяет UI/доступность/дубли/состояния, не WFP, Claude или установленную службу.
- `bash packaging/macos/test-ui.sh /tmp/guard-ui.png`: отрисовка собственного SwiftUI View с тестовой моделью, без сетевых действий.
- `bash test.sh`: macOS тесты с собственными локальными fixture. Работа реального Claude и смена VPN проверяются отдельно, не подменяются unit-тестами.
- `packaging/scripts/verify-scope.py`: проверка, что защищённые исходники движка/native не отличаются от baseline текущей UX-задачи.

## Workflow

Шаблоны находятся в `packaging/workflows`. Они не исполняются автоматически из этой папки. Для активации maintainer переносит их в `.github/workflows`, проверяет permissions и разрешает добавление workflow. Текущий OAuth-доступ ранее отклонил изменение активных workflow из-за отсутствующего `workflow` scope; обойти это скрытой активацией нельзя.

Mac workflow собирает universal ZIP/DMG и прогоняет локальные тесты. Windows workflow требует существующий публичный release tag этого репозитория с CodeTools assets и ожидаемый SHA-256 policy, компилирует приложение и при наличии ISCC — установщик, запускает UI-smoke и публикует только разрешённые артефакты. Никакие `.env`, PFX, пользовательские профили или account logs не загружаются.

## Публикация

Сначала зафиксируйте версии, changelog и commit. Создайте артефакты в свежем output, проверьте manifest/SHA-256, архитектуры, отсутствие данных профиля, ASAR source match, подписи и реальные статусы тестов. `packaging/scripts/release-manifest.py` создаёт allowlisted отчёт и SHA-256; приватные fixture и raw traffic не прикладываются.

Подготовьте draft release и приложите ZIP/DMG/Setup, только если они действительно созданы, и checksum-файлы. Недоступный установщик, неподтверждённый UAC/сервис, Windows runtime, Intel runtime и notarization отмечаются NOT RUN/NOT CONFIGURED. Не заменяйте результаты предыдущей версии новым PASS. Публикация предварительной сборки не делает её стабильной.
