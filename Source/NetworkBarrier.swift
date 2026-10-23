import Foundation

/// System packet-filter barrier (PG-01): the prepared Claude tree runs with the
/// dedicated `_cpguard` group id, and PF allows that group loopback traffic only.
/// Every native, MCP or helper process spawned by Claude is then physically unable
/// to reach the network directly — it can only talk to the local Guard relay.
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
        // Order matters: loopback pass first, both rules are `quick`.
        "pass quick on lo0 all group \(groupName)\nblock return out quick all group \(groupName)\n"
    }

    static func sudoersContent() -> String {
        "%admin ALL=(root) NOPASSWD: \(helperPath)\n" +
        "%admin ALL=(root) NOPASSWD: /usr/sbin/pfctl -a claudeproxyguard -s rules\n"
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
        if let index = lines.firstIndex(where: { $0.hasPrefix("anchor \"com.apple/*\"") }) {
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
    /// shell performs no parsing of attacker-influenced text. `helperSource` is
    /// passed as positional argument and never interpolated into the script.
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
        install -o root -g wheel -m 0755 "$HELPER_SRC" "$HELPER"
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
        pfctl -ef /etc/pf.conf
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

    /// Cheap, password-free probe: the sudoers NOPASSWD entries make both checks
    /// non-interactive. Any password prompt would fail immediately thanks to `-n`.
    static func probe() -> Probe {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: helperPath, isDirectory: &isDirectory), !isDirectory.boolValue,
              let attributes = try? FileManager.default.attributesOfItem(atPath: helperPath),
              (attributes[.ownerAccountID] as? NSNumber)?.intValue == 0,
              let mode = attributes[.posixPermissions] as? NSNumber, mode.intValue & 0o022 == 0 else {
            return .missing
        }
        let helperProbe = run("/usr/bin/sudo", ["-n", helperPath])
        // The helper without arguments exits 64; sudo itself fails with 1.
        guard helperProbe.status == 64 else { return .broken("запуск хелпера через sudo не подтверждён") }
        let pfProbe = run("/usr/bin/sudo", ["-n", "/usr/sbin/pfctl", "-a", "claudeproxyguard", "-s", "rules"])
        guard pfProbe.status == 0, pfProbe.output.contains(groupName) else { return .broken("правила PF не загружены") }
        return .active
    }

    /// Runs the given privileged script through a single osascript administrator
    /// prompt. The script file is private (0700) and its path is charset-checked.
    private static func runPrivileged(_ script: String) throws {
        let name = "cpguard-" + UUID().uuidString.lowercased() + ".sh"
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true).appendingPathComponent(name)
        guard url.path.range(of: "^[A-Za-z0-9/._-]+$", options: .regularExpression) != nil else {
            throw GuardError.message("Небезопасный путь временного скрипта.")
        }
        try script.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        defer { try? FileManager.default.removeItem(at: url) }
        let helperSource = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/GuardDrop").path
        guard helperSource.range(of: "^[A-Za-z0-9/._ -]+$", options: .regularExpression) != nil else {
            throw GuardError.message("Путь GuardDrop содержит недопустимые символы.")
        }
        let command = "/bin/bash '\(url.path)' '\(helperSource)'"
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
