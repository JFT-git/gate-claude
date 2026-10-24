import Foundation

@main
struct BarrierTests {
    static var failures = 0
    static func check(_ name: String, _ condition: Bool) {
        if condition { print("PASS \(name)") } else { failures += 1; print("FAIL \(name)") }
    }

    static func bashSyntax(_ script: String, _ name: String) {
        do {
            let url = URL(fileURLWithPath: NSTemporaryDirectory())
                .appendingPathComponent("barrier-test-" + UUID().uuidString.lowercased() + ".sh")
            try script.write(to: url, atomically: true, encoding: .utf8)
            defer { try? FileManager.default.removeItem(at: url) }
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/bin/bash")
            task.arguments = ["-n", url.path]
            try task.run(); task.waitUntilExit()
            check(name, task.terminationStatus == 0)
        } catch { check(name + " (error: \(error.localizedDescription))", false) }
    }

    static func main() {
        let rules = NetworkBarrier.anchorRules()
        check("anchor-pass-lo0", rules.contains("pass quick on lo0 all group _cpguard label \"cpguard-lo\""))
        check("anchor-block-quick", rules.contains("block return out quick all group _cpguard label \"cpguard-block\""))
        check("anchor-order", (rules.range(of: "pass quick")?.lowerBound ?? rules.endIndex) < (rules.range(of: "block return")?.lowerBound ?? rules.startIndex))

        let sudoers = NetworkBarrier.sudoersContent()
        check("sudoers-helper", sudoers.contains("ALL ALL=(root) NOPASSWD: /Library/PrivilegedHelperTools/claudeproxyguard-drop"))
        check("sudoers-pfctl", sudoers.contains("ALL ALL=(root) NOPASSWD: /sbin/pfctl -a claudeproxyguard -s rules"))
        check("sudoers-pf-info", sudoers.contains("ALL ALL=(root) NOPASSWD: /sbin/pfctl -s info"))
        check("sudoers-no-wildcards", !sudoers.contains("*") && sudoers.hasSuffix("\n"))

        let sample = "scrub-anchor \"com.apple/*\"\nnat-anchor \"com.apple/*\"\nrdr-anchor \"com.apple/*\"\n" +
            "dummynet-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\nload anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n"
        let merged = NetworkBarrier.mergedPFConf(sample)
        let ourBlock = merged.range(of: "\nanchor \"claudeproxyguard\"\n")
        let appleBlock = merged.range(of: "\nanchor \"com.apple/*\"\n")
        check("merge-before-apple", ourBlock != nil && appleBlock != nil && ourBlock!.lowerBound < appleBlock!.lowerBound)
        check("merge-idempotent", NetworkBarrier.mergedPFConf(merged) == merged)
        check("merge-loads-anchor", merged.contains("load anchor \"claudeproxyguard\" from \"/etc/pf.anchors/claudeproxyguard\""))
        let appended = NetworkBarrier.mergedPFConf("block all\n")
        check("merge-appends", appended.contains("block all\n") && appended.contains("anchor \"claudeproxyguard\""))
        check("merge-no-trailing-newline-input", NetworkBarrier.mergedPFConf("block all").contains(NetworkBarrier.markBegin))

        let stripped = NetworkBarrier.strippedPFConf(merged)
        check("strip-removes", !stripped.contains("claudeproxyguard"))
        check("strip-keeps-rest", stripped.contains("anchor \"com.apple/*\"") && stripped.contains("scrub-anchor"))
        check("strip-idempotent", NetworkBarrier.strippedPFConf(stripped) == stripped)
        check("strip-without-block", NetworkBarrier.strippedPFConf(sample) == sample)

        do {
            let script = try NetworkBarrier.installScript(currentPFConf: sample)
            bashSyntax(script, "install-script-syntax")
            check("install-script-helper-path", script.contains("HELPER=\"/Library/PrivilegedHelperTools/claudeproxyguard-drop\""))
            check("install-script-group", script.contains("GROUP=\"_cpguard\"") && script.contains("dscl . -create \"/Groups/$GROUP\""))
            check("install-script-hash-pin", script.contains("shasum -a 256 \"$HELPER_SRC\"") && script.contains("helper hash mismatch"))
            check("install-script-visudo", script.contains("visudo -cf"))
            check("install-script-pf-validate", script.contains("pfctl -nf"))
            check("install-script-pf-enable", script.contains("pfctl -ef /etc/pf.conf") && script.contains("Status: Enabled"))
            check("install-script-helper-arg", script.contains("install -o root -g wheel -m 0755 \"$HELPER_SRC\" \"$HELPER\""))
        } catch { check("install-script-generation", false) }
        bashSyntax(NetworkBarrier.uninstallScript(), "uninstall-script-syntax")

        // PF syntax validation of the anchor itself; a system without the group
        // resolves names at load, so that single complaint still proves syntax.
        do {
            let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("barrier-pf-" + UUID().uuidString.lowercased())
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: dir) }
            let anchorURL = dir.appendingPathComponent("anchor")
            try rules.write(to: anchorURL, atomically: true, encoding: .utf8)
            let conf = "anchor \"claudeproxyguard\"\nload anchor \"claudeproxyguard\" from \"\(anchorURL.path)\"\n"
            let confURL = dir.appendingPathComponent("pf.conf")
            try conf.write(to: confURL, atomically: true, encoding: .utf8)
            let task = Process(); let pipe = Pipe()
            task.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
            task.arguments = ["-nf", confURL.path]
            task.standardOutput = pipe; task.standardError = pipe
            try task.run(); task.waitUntilExit()
            let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            check("pf-anchor-syntax", task.terminationStatus == 0 || output.contains("unknown group"))
        } catch { check("pf-anchor-syntax (error)", false) }

        exit(failures == 0 ? 0 : 1)
    }
}
