# Сборки и релиз

## Поддерживаемая матрица

- Windows 10/11 **x64**: Electron 44.9.2, Node >=22.12 для сборки, .NET Framework C# compiler для native-помощников. Portable ZIP; подготовлен Inno Setup 6.3+ установщик текущего пользователя. ARM64 и x86 не заявлены.
- macOS **13+ universal arm64 + x86_64**: Xcode Command Line Tools/SDK, SwiftUI/AppKit/Network, clang, codesign, lipo, ditto, hdiutil. Переносимый `.app` в ZIP и DMG для drag-and-drop установки. Это не PKG и не установка службы.
- Linux не поддерживается. Наличие universal-секции не означает проверенного исполнения на Intel. Cross-build Windows не является запуском Windows.

## Windows

```powershell
$env:GUARD_WINDOWS_UPDATE_PRIVATE_KEY='C:\secure\guard-windows-ed25519.pem'
.\packaging\windows\package.ps1 -CodeToolsDir C:\verified\CodeTools -ArtifactDir C:\fresh\release
```

Приватный Ed25519-ключ должен находиться только во внешнем защищённом хранилище и соответствовать публичному ключу в `Windows/src/updater.cjs`. Скрипт собирает portable ZIP, per-user NSIS Setup, `.blockmap`, `latest.yml` и detached `latest.yml.sig`, затем вычисляет SHA-256. Изменение `latest.yml` после подписи запрещено: metadata нужно создать и подписать заново. Не публикуйте новый Setup/blockmap с metadata от другой сборки.

Комплекты CodeTools обязательны для полного Code-релиза. Их готовит `Windows/scripts/prepare-code-tools.cjs` из закреплённых исходников Git/PowerShell и bootstrap; произвольный ZIP не принимается. Native-компиляция использует существующие исходники, движок не подменяется. Проверяйте source commit, production dependencies, byte-match ASAR и хеши helper/sidecar.

NSIS устанавливает только приложение для текущего пользователя в `%LOCALAPPDATA%\Programs\Claude Proxy Guard`, без службы и без удаления Application Data. Он не должен завершать активную защищённую сессию: updater сначала запрашивает подтверждение и дожидается shutdown. Удаление собственных HKCU регистраций условно по marker и полному пути EXE; чужая установка не затрагивается. Миграция с Inno Setup и installed A→B проверяются на настоящей Windows.

Authenticode по-прежнему не настроена. Подпись update metadata подтверждает происхождение обновления относительно закреплённого ключа, но не является подписью издателя Windows. Неподписанный Setup.exe может вызвать предупреждение ОС; успешная компиляция не означает успешную установку, удаление, differential download или прохождение SmartScreen.

## macOS

```sh
bash test.sh
bash packaging/macos/appcast.sh /absolute/path/to/fresh-release
```

`build.sh` компилирует обе архитектуры, встраивает закреплённый Sparkle 2.10.1 и применяет ad-hoc codesign к приложению и вложенным компонентам. `package.sh` создаёт ZIP, DMG и SHA-256; `appcast.sh` дополнительно создаёт подписанный `appcast.xml` и проверяет ZIP/feed. Для обычной сборки без release feed по-прежнему используется `packaging/macos/package.sh`.

Sparkle EdDSA-ключ создаётся официальным `generate_keys` и хранится в macOS Keychain. Публичный ключ находится в `Info.plist`; приватный ключ не коммитится и не копируется в артефакты. Перед публикацией нужно проверить доступ к ключу и наличие его независимой резервной копии. `sparkle:version` должна совпадать с монотонным `CFBundleVersion`. Не изменяйте ZIP или appcast после подписи.

Developer ID и нотариализация не выполняются и не заявляются. Sparkle EdDSA защищает обновления, но не заменяет подпись издателя Apple и не устраняет предупреждения Gatekeeper.

## Проверки

- `cd Windows && npm test`: платформенные skipped должны быть перечислены, а не объявлены PASS.
- `Windows/scripts/ci-windows.ps1`: отдельные реальные Windows/native проверки; потенциально устанавливают временные собственные политики на выделенном runner. Нужны корректная сборка всех native-зависимостей и права, описанные самим скриптом. Этот legacy-скрипт не используется как доказательство нового UI.
- `Windows/scripts/ui-smoke.cjs`: тест локального renderer через Electron, отдельный temporary профиль и только тестовые bridge responses. Он проверяет UI/доступность/дубли/состояния, не WFP, Claude или установленную службу.
- `bash packaging/macos/test-ui.sh /tmp/guard-ui.png`: отрисовка собственного SwiftUI View с тестовой моделью, без сетевых действий.
- `bash test.sh`: macOS тесты с собственными локальными fixture. Работа реального Claude и смена VPN проверяются отдельно, не подменяются unit-тестами.
- `packaging/scripts/verify-scope.py`: проверка, что защищённые исходники движка/native не отличаются от baseline текущей UX-задачи.

## Workflow

Шаблоны находятся в `packaging/workflows`. Они не исполняются автоматически из этой папки. Для активации maintainer переносит их в `.github/workflows`, проверяет permissions и разрешает добавление workflow. Текущий OAuth-доступ ранее отклонил изменение активных workflow из-за отсутствующего `workflow` scope; обойти это скрытой активацией нельзя.

Mac workflow собирает universal ZIP/DMG и прогоняет локальные тесты, но не подписывает appcast без отдельно настроенного Sparkle key import. Windows workflow требует CodeTools и секрет `GUARD_WINDOWS_UPDATE_PRIVATE_KEY_PEM`; ключ записывается только во временный файл runner и не входит в upload-artifact. Workflow собирает NSIS, blockmap, `latest.yml` и `latest.yml.sig`, запускает UI-smoke и публикует только разрешённые артефакты. Пользовательские профили, account logs и приватные ключи не загружаются.

## Публикация

Сначала зафиксируйте версии, changelog и commit. Создайте артефакты в свежем output, проверьте manifest/SHA-256, архитектуры, отсутствие данных профиля, ASAR source match, вложенные подписи, Ed25519/EdDSA metadata и реальные статусы тестов. `packaging/scripts/release-manifest.py` создаёт allowlisted отчёт и SHA-256; приватные fixture и raw traffic не прикладываются.

Подготовьте draft release и приложите ZIP/DMG/Setup, Windows blockmap, signed `latest.yml` и macOS `appcast.xml` только из одной проверенной сборки. Не загружайте приватные ключи. Недоступные installed A→B, differential download, Windows runtime/UAC, Intel runtime и notarization отмечаются NOT RUN/NOT CONFIGURED. Не заменяйте результаты предыдущей версии новым PASS. Публикация предварительной сборки не делает её стабильной.
