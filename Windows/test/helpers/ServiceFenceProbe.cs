using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

internal static class ServiceFenceProbe {
    static string Hex(int count) {
        var bytes = new byte[count];
        using (var random = RandomNumberGenerator.Create()) random.GetBytes(bytes);
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }
    static string Base64(string value) { return Convert.ToBase64String(Encoding.UTF8.GetBytes(value)); }
    static string ReadLine(StreamReader reader) {
        var task = reader.ReadLineAsync();
        if (!task.Wait(30000) || task.Result == null || task.Result.Length > 262144) throw new TimeoutException();
        return task.Result;
    }
    static Process Request(string service, string root, string pipe, string token) {
        var process = Process.Start(new ProcessStartInfo {
            FileName = service, Arguments = "--launch --root " + Base64(root) + " --pipe " + pipe + " --token " + token,
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        });
        if (process == null) throw new InvalidOperationException();
        return process;
    }
    static void FinishRequest(Process process, bool expected) {
        if (!process.WaitForExit(30000)) throw new TimeoutException();
        string output = process.StandardOutput.ReadToEnd();
        if (expected) {
            if (process.ExitCode != 0 || output.Trim() != "{\"version\":1,\"launched\":true,\"code\":0}") throw new InvalidDataException();
        } else if (process.ExitCode == 0 || output.Trim() != "{\"version\":1,\"launched\":false,\"code\":5}") throw new UnauthorizedAccessException();
        process.Dispose();
    }
    public static int Main(string[] args) {
        if (args.Length != 2) return 64;
        bool installed = false;
        StreamWriter writer = null;
        try {
            string service = Path.GetFullPath(args[0]), root = Path.GetFullPath(args[1]);
            string deniedRoot = Path.Combine(@"C:\Windows\Temp", "Runtime-" + Hex(12));
            if (Directory.Exists(deniedRoot)) throw new InvalidDataException();
            Directory.CreateDirectory(deniedRoot);
            string deniedPipe = "gate-network-fence-" + Hex(16), deniedToken = Hex(32);
            FinishRequest(Request(service, deniedRoot, deniedPipe, deniedToken), false);
            Directory.Delete(deniedRoot, false);

            string name = "gate-network-fence-" + Hex(16), token = Hex(32);
            using (var pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096)) {
                Process request = Request(service, root, name, token);
                if (!pipe.WaitForConnectionAsync().Wait(30000)) throw new TimeoutException();
                using (var reader = new StreamReader(pipe, new UTF8Encoding(false, true), false, 4096, true))
                using (writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true) { AutoFlush = true }) {
                    string hello = ReadLine(reader);
                    if (hello != "{\"type\":\"hello\",\"version\":1,\"token\":\"" + token + "\"}") throw new InvalidDataException();
                    string executable = Path.Combine(root, "Claude.exe");
                    writer.WriteLine("install\t" + Base64(root) + "\t23456\t" + Base64(executable));
                    string proof = ReadLine(reader);
                    if (proof != "{\"type\":\"installed\",\"version\":1,\"paths\":1,\"filters\":6,\"persistent\":true,\"coverage\":\"private-runtime-executables\"}") throw new InvalidDataException();
                    installed = true;
                    writer.WriteLine("remove-after-job-exit");
                    if (ReadLine(reader) != "{\"type\":\"removed\",\"removed\":true}") throw new InvalidDataException();
                    installed = false;
                }
                FinishRequest(request, true);
            }
            Console.WriteLine("{\"authorizationDeniedOutsideProfile\":true,\"installed\":true,\"removed\":true,\"result\":\"PASS\"}");
            return 0;
        } catch (Exception error) {
            if (installed && writer != null) {
                try { writer.WriteLine("remove-after-job-exit"); Thread.Sleep(1000); } catch { }
            }
            Console.Error.WriteLine("GUARD_SERVICE_PROBE_" + error.GetType().Name);
            return 1;
        }
    }
}
