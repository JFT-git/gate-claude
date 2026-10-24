import Foundation
import CryptoKit

/// System packet-filter barrier (PG-01): the prepared Claude tree runs with the
/// dedicated `_cpguard` group id, and PF allows that group loopback traffic only.
/// Native, MCP and helper processes spawned by Claude cannot open direct TCP/UDP
/// network connections — they can only talk to the local Guard relay. (Residual:
/// name resolution via mDNSResponder and ICMP are not group-matched; launchd or
/// AppleEvents hand-offs live outside the process tree.)
///
/// The barrier is installed once with administrator rights: a root-owned drop
/// helper (sudo NOPASSWD, pinned path), a sudoers entry, a PF anchor and a group.
/// The helper only REDUCES privileges (root → invoking user + barrier group), so
/// the sudoers grant cannot be used for local privilege escalation.
enum NetworkBarrier {
    static let helperPath = "/Library/PrivilegedHelperTools/claudeproxyguard-drop"
    static let sudoersPath = "/etc/sudoers.d/claudeproxyguard"
    static let anchorPath = "/etc/pf.anchors/claudeproxyguard"
    static let groupName = "_cpguard"
    static let blockLabel = "cpguard-block"
    static let markBegin = "# claudeproxyguard begin"
    static let markEnd = "# claudeproxyguard end"

    enum Probe: Equatable {
        case active
        case missing
        case broken(String)

        var active: Bool { self == .active }
        var summary: String {
            switch self {
            case .active: return "Барьер активен: Claude ограничен локальным шлюзом."
            case .missing: return "Барьер не установлен."
            case .broken(let reason): return "Барьер требует восстановления: \(reason)"
            }
        }
    }

    static func anchorRules() -> String {
        // Order matters: loopback pass first, both rules are `quick`. Labels make
        // the loaded ruleset verifiable: pfctl prints group ids numerically.
        "pass quick on lo0 all group \(groupName) label \"cpguard-lo\"\n" +
        "block return out quick all group \(groupName) label \"\(blockLabel)\"\n"
    }

    // The helper only downgrades privileges, so any local user may invoke it;
    // restricting to %admin would break installs for non-admin standard users.
    static func sudoersContent() -> String {
        "ALL ALL=(root) NOPASSWD: \(helperPath)\n" +
        "ALL ALL=(root) NOPASSWD: /sbin/pfctl -a claudeproxyguard -s rules\n" +
        "ALL ALL=(root) NOPASSWD: /sbin/pfctl -s rules\n" +
        "ALL ALL=(root) NOPASSWD: /sbin/pfctl -s info\n"
    }

    static func anchorBlock() -> String {
        "\(markBegin)\nanchor \"claudeproxyguard\"\nload anchor \"claudeproxyguard\" from \"\(anchorPath)\"\n\(markEnd)\n"
    }

    /// Inserts the anchor block right before the Apple anchor so the barrier is
    /// evaluated before vendor rules. Idempotent: an existing block is left as is.
    static func mergedPFConf(_ existing: String) -> String {
        if existing.contains(markBegin) { return existing }
        var lines = existing.components(separatedBy: "\n")
        let block = anchorBlock().components(separatedBy: "\n").filter { !$0.isEmpty }
        if let index = lines.firstIndex(where: { $0 == "anchor \"com.apple/*\"" }) {
            lines.insert(contentsOf: block, at: index)
            return lines.joined(separator: "\n")
        }
        var result = existing
        if !result.hasSuffix("\n") { result += "\n" }
        return result + anchorBlock()
    }

    /// Removes the anchor block (uninstall). Idempotent.
    static func strippedPFConf(_ existing: String) -> String {
        guard existing.contains(markBegin) else { return existing }
        var output: [String] = []
        var skipping = false
        for line in existing.components(separatedBy: "\n") {
            if line == markBegin { skipping = true; continue }
            if line == markEnd { skipping = false; continue }
            if !skipping { output.append(line) }
        }
        return output.joined(separator: "\n")
    }

    private static func base64(_ text: String) -> String {
        Data(text.utf8).base64EncodedString()
    }

    /// The privileged install script. All variable content (sudoers, anchor,
    /// merged pf.conf) is precomputed here and embedded as base64, so the root
    /// shell performs no parsing of attacker-influenced text. The helper source is
    /// passed as positional argument and installed only when its SHA-256 matches
    /// the constant embedded at build time.
    static func installScript(currentPFConf: String) throws -> String {
        let merged = mergedPFConf(currentPFConf)
        guard !merged.isEmpty else { throw GuardError.message("Не удалось подготовить конфигурацию PF.") }
        return """
        #!/bin/bash
        set -euo pipefail
        export PATH=/usr/bin:/bin:/usr/sbin:/sbin
        HELPER_SRC="$1"
        GROUP="\(groupName)"
        HELPER="\(helperPath)"
        SUDOERS="\(sudoersPath)"
        ANCHOR="\(anchorPath)"
        [ -n "$HELPER_SRC" ] && [ -f "$HELPER_SRC" ] && [ -x "$HELPER_SRC" ] || { echo "helper source missing"; exit 1; }
        case "$HELPER_SRC" in *".."*) echo "bad helper source"; exit 1;; esac
        # Stage through a root-owned private directory and hash the STAGED bytes:
        # the bundle path is user-writable, so hashing the source and installing it
        # later would leave a swap window. Whatever passes the hash check here is
        # exactly what gets installed below.
        STAGE="$(mktemp -d /tmp/cpguard-stage.XXXXXX)"
        chmod 0700 "$STAGE"
        trap 'rm -rf "$STAGE"' EXIT
        cp "$HELPER_SRC" "$STAGE/helper"
        ACTUAL="$(shasum -a 256 "$STAGE/helper" | awk '{print $1}')"
        [ "$ACTUAL" = "\(BarrierIntegrity.guardDropSHA256)" ] || { echo "helper hash mismatch"; exit 1; }
        if ! dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
          GID=380
          while :; do
            if ! dscl . -search /Groups PrimaryGroupID "$GID" 2>/dev/null | grep -q . \\
               && ! dscl . -search /Users UniqueID "$GID" 2>/dev/null | grep -q .; then break; fi
            GID=$((GID + 1))
            [ "$GID" -lt 400 ] || { echo "no free gid"; exit 1; }
          done
          dscl . -create "/Groups/$GROUP"
          dscl . -create "/Groups/$GROUP" PrimaryGroupID "$GID"
          dscl . -create "/Groups/$GROUP" RealName "Claude Proxy Guard network barrier"
          dscl . -create "/Groups/$GROUP" Password "*"
        fi
        install -o root -g wheel -m 0755 "$STAGE/helper" "$HELPER"
        printf %s '\(base64(sudoersContent()))' | base64 -D > "$SUDOERS"
        chown root:wheel "$SUDOERS"; chmod 0440 "$SUDOERS"
        visudo -cf "$SUDOERS" >/dev/null
        printf %s '\(base64(anchorRules()))' | base64 -D > "$ANCHOR"
        chown root:wheel "$ANCHOR"; chmod 0644 "$ANCHOR"
        TMP="$(mktemp /tmp/cpguard-pf.XXXXXX)"
        printf %s '\(base64(merged))' | base64 -D > "$TMP"
        pfctl -nf "$TMP"
        cat "$TMP" > /etc/pf.conf
        rm -f "$TMP"
        # Reload rules when PF is already enabled (`pfctl -e` would exit 1 there);
        # enable and load otherwise.
        if pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
          pfctl -f /etc/pf.conf
        else
          pfctl -ef /etc/pf.conf
        fi
        echo "barrier installed"
        """
    }

    static func uninstallScript() -> String {
        """
        #!/bin/bash
        set -euo pipefail
        export PATH=/usr/bin:/bin:/usr/sbin:/sbin
        rm -f "\(sudoersPath)" "\(helperPath)" "\(anchorPath)"
        if grep -qF '\(markBegin)' /etc/pf.conf; then
          TMP="$(mktemp /tmp/cpguard-pf.XXXXXX)"
          printf %s '\(base64(strippedPFConf((try? String(contentsOfFile: "/etc/pf.conf", encoding: .utf8)) ?? "")))' | base64 -D > "$TMP"
          if pfctl -nf "$TMP"; then cat "$TMP" > /etc/pf.conf; fi
          rm -f "$TMP"
        fi
        if pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then pfctl -f /etc/pf.conf || true; fi
        dscl . -delete "/Groups/\(groupName)" >/dev/null 2>&1 || true
        echo "barrier removed"
        """
    }

    private static func run(_ executable: String, _ arguments: [String]) -> (status: Int32, output: String) {
        let task = Process(); let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: executable); task.arguments = arguments
        task.standardOutput = pipe; task.standardError = pipe
        do { try task.run() } catch { return (-1, "") }
        task.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return (task.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    private static func sha256(_ path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static var bundledHelperPath: String {
        Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/GuardDrop").path
    }

    /// Cheap, password-free probe: the sudoers NOPASSWD entries make the checks
    /// non-interactive. Any password prompt fails immediately thanks to `-n`.
    static func probe() -> Probe {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: helperPath, isDirectory: &isDirectory), !isDirectory.boolValue,
              let attributes = try? FileManager.default.attributesOfItem(atPath: helperPath),
              (attributes[.ownerAccountID] as? NSNumber)?.intValue == 0,
              let mode = attributes[.posixPermissions] as? NSNumber, mode.intValue & 0o022 == 0 else {
            return .missing
        }
        // The installed helper must be byte-identical to the one sealed in this
        // bundle; a swapped helper would run as root via the NOPASSWD grant.
        guard let installed = sha256(helperPath), let bundled = sha256(bundledHelperPath), installed == bundled else {
            return .broken("хелпер не совпадает с комплектом приложения")
        }
        let helperProbe = run("/usr/bin/sudo", ["-n", helperPath])
        // The helper without arguments exits 64; sudo itself fails with 1.
        guard helperProbe.status == 64 else { return .broken("запуск хелпера через sudo не подтверждён") }
        // macOS does not enable PF at boot; a reboot or `pfctl -d` silently drops
        // the barrier while the anchor file stays on disk.
        let infoProbe = run("/usr/bin/sudo", ["-n", "/sbin/pfctl", "-s", "info"])
        guard infoProbe.status == 0, infoProbe.output.contains("Status: Enabled") else {
            return .broken("packet filter выключен")
        }
        let pfProbe = run("/usr/bin/sudo", ["-n", "/sbin/pfctl", "-a", "claudeproxyguard", "-s", "rules"])
        guard pfProbe.status == 0, pfProbe.output.contains(blockLabel) else { return .broken("правила PF не загружены") }
        // Rules inside a named anchor filter nothing unless the ACTIVE main
        // ruleset invokes that anchor — verify the attachment too.
        let mainProbe = run("/usr/bin/sudo", ["-n", "/sbin/pfctl", "-s", "rules"])
        guard mainProbe.status == 0, mainProbe.output.contains("anchor \"claudeproxyguard\"") else {
            return .broken("якорь PF не подключён к основному набору правил")
        }
        return .active
    }

    /// Runs the privileged script through a single osascript administrator prompt.
    /// The script never touches the filesystem: it travels inline as base64, so a
    /// user-writable temp file cannot be swapped between the prompt and execution.
    private static func runPrivileged(_ script: String) throws {
        let helperSource = bundledHelperPath
        guard helperSource.range(of: "^[A-Za-z0-9/._ @-]+$", options: .regularExpression) != nil,
              !helperSource.contains("'") else {
            throw GuardError.message("Путь GuardDrop содержит недопустимые символы.")
        }
        let command = "printf %s '\(base64(script))' | base64 -D | /bin/bash -s -- '\(helperSource)'"
        let appleScript = "do shell script \"\(command)\" with administrator privileges"
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-e", appleScript]
        task.standardOutput = FileHandle.nullDevice; task.standardError = FileHandle.nullDevice
        try task.run(); task.waitUntilExit()
        guard task.terminationStatus == 0 else {
            throw GuardError.message("Установка отменена или отклонена системой. Барьер не изменён.")
        }
    }

    static func install() throws {
        let conf = (try? String(contentsOfFile: "/etc/pf.conf", encoding: .utf8)) ?? ""
        try runPrivileged(installScript(currentPFConf: conf))
        let result = probe()
        guard result.active else {
            throw GuardError.message("Установка завершилась, но барьер не активен: \(result.summary)")
        }
    }

    static func uninstall() throws {
        try runPrivileged(uninstallScript())
    }
}
