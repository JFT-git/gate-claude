using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;
using TimeoutException = System.TimeoutException;

internal static class GuardService {
    internal const string ServiceName = "ClaudeProxyGuard";
    internal const string ApiVersion = "1.0.0";
    internal const int Api = 1;
    internal const string NetworkFenceSHA256 = "9e1d8222b0d9e30b05885b0056abbc1a2027f62baf0ead7c8a4fb4a3b9ad525e";
    internal const string PipeName = "ClaudeProxyGuard.Service.v1";
    const uint ServiceQueryConfig = 0x0001, ServiceChangeConfig = 0x0002, ServiceQueryStatus = 0x0004;
    const uint ServiceStart = 0x0010, ServiceStop = 0x0020, ServiceDelete = 0x10000, ServiceWriteDac = 0x40000;
    const uint ScManagerConnect = 0x0001, ScManagerCreateService = 0x0002;
    const int ServiceWin32OwnProcess = 0x10, ServiceAutoStart = 2, ServiceErrorNormal = 1;
    const int ServiceStopped = 1, ServiceStartPending = 2, ServiceStopPending = 3, ServiceRunning = 4;
    static ServiceStatus ignored;

    [StructLayout(LayoutKind.Sequential)] internal struct ServiceStatus {
        public int type, state, accepted, exitCode, serviceExitCode, checkpoint, waitHint;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct ServiceConfig {
        public int type, start, error;
        public string binary, group;
        public int tag;
        public string dependencies, account, display;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct ShellExecuteInfo {
        public uint size, mask; public IntPtr window;
        public string verb, file, parameters, directory; public int show;
        public IntPtr instance, idList; public string className;
        public IntPtr classKey; public uint hotKey; public IntPtr icon, process;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Description { public string value; }
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {
        public int length; public IntPtr descriptor; public int inherit;
    }

    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenSCManager(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateService(IntPtr manager, string name, string display, uint access, int type, int start, int error, string binary, string group, IntPtr tags, string dependencies, string account, string password);
    [DllImport("advapi32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool CloseServiceHandle(IntPtr service);
    [DllImport("advapi32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool StartService(IntPtr service, int count, IntPtr arguments);
    [DllImport("advapi32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool ControlService(IntPtr service, int control, out ServiceStatus status);
    [DllImport("advapi32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool QueryServiceStatus(IntPtr service, out ServiceStatus status);
    [DllImport("advapi32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool DeleteService(IntPtr service);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool QueryServiceConfig(IntPtr service, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool ChangeServiceConfig2(IntPtr service, int level, IntPtr value);
    [DllImport("advapi32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool SetServiceObjectSecurity(IntPtr service, int security, IntPtr descriptor);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool ShellExecuteEx(ref ShellExecuteInfo info);
    [DllImport("user32.dll")] [return:MarshalAs(UnmanagedType.Bool)] static extern bool IsWindow(IntPtr window);
    [DllImport("ole32.dll")] static extern int CoInitializeEx(IntPtr reserved, uint flags);
    [DllImport("ole32.dll")] static extern void CoUninitialize();
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetExitCodeProcess(IntPtr process, out int code);
    [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateMutex(ref SecurityAttributes attributes, bool initialOwner, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenMutex(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool ReleaseMutex(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder file, ref uint size);

    internal static string ProgramDataRoot { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Claude Proxy Guard"); } }
    internal static string ServiceRoot { get { return Path.Combine(ProgramDataRoot, "Service"); } }
    internal static string ProtectedService { get { return Path.Combine(ServiceRoot, "GuardService.exe"); } }
    internal static string ProtectedFence { get { return Path.Combine(ServiceRoot, "NetworkFence.exe"); } }
    internal static string QuotedProtectedService { get { return "\"" + ProtectedService + "\""; } }
    static string Self { get { return System.Reflection.Assembly.GetExecutingAssembly().Location; } }

    static void Win32(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    sealed class ManagementLock : IDisposable {
        const string Name = @"Global\ClaudeProxyGuard.Management.v1";
        const uint Needed = 0x100001;
        IntPtr handle = IntPtr.Zero;
        bool owned;
        public ManagementLock() {
            handle = OpenMutex(Needed, false, Name);
            if (handle == IntPtr.Zero) {
                if (Marshal.GetLastWin32Error() != 2) throw new Win32Exception(Marshal.GetLastWin32Error());
                uint size; IntPtr descriptor;
                Win32(ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100001;;;AU)", 1, out descriptor, out size));
                try {
                    var attributes = new SecurityAttributes { length = Marshal.SizeOf(typeof(SecurityAttributes)), descriptor = descriptor, inherit = 0 };
                    handle = CreateMutex(ref attributes, false, Name);
                    if (handle == IntPtr.Zero && Marshal.GetLastWin32Error() == 5) handle = OpenMutex(Needed, false, Name);
                    if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                } finally { LocalFree(descriptor); }
            }
            uint acquired = WaitForSingleObject(handle, 10000);
            if (acquired == 0 || acquired == 0x80) { owned = true; return; }
            CloseHandle(handle); handle = IntPtr.Zero;
            if (acquired == 0x102) throw new TimeoutException();
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public void Dispose() {
            if (owned) { ReleaseMutex(handle); owned = false; }
            if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; }
        }
    }
    static bool ProtectedBrokerRunning() {
        foreach (Process process in Process.GetProcesses()) using (process) {
            try { if (!String.Equals(process.ProcessName, "NetworkFence", StringComparison.OrdinalIgnoreCase)) continue; }
            catch (InvalidOperationException) { continue; }
            catch (ArgumentException) { continue; }
            IntPtr handle = OpenProcess(0x1000, false, process.Id);
            if (handle == IntPtr.Zero) {
                if (Marshal.GetLastWin32Error() == 87) continue;
                throw new InvalidOperationException("broker-query-denied");
            }
            try {
                uint length = 32768; var image = new StringBuilder((int)length);
                if (!QueryFullProcessImageName(handle, 0, image, ref length)) throw new InvalidOperationException("broker-path-query-failed");
                if (String.Equals(Path.GetFullPath(image.ToString()), ProtectedFence, StringComparison.OrdinalIgnoreCase)) return true;
            } finally { CloseHandle(handle); }
        }
        return false;
    }
    static void RequireNoProtectedBroker() { if (ProtectedBrokerRunning()) throw new InvalidOperationException("protected-broker-active"); }
    internal static string SHA256File(string file) {
        using (var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read)) {
            if (stream.Length < 16 || stream.Length > 33554432) throw new InvalidDataException();
            using (var hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
        }
    }
    internal static string LocalPath(string value) {
        if (String.IsNullOrEmpty(value) || value.Length > 240 || !Regex.IsMatch(value, @"^[A-Za-z]:\\") || value.IndexOfAny(new char[] { '\0', '\r', '\n', '\t' }) >= 0 || value.IndexOf(':', 2) >= 0) throw new InvalidDataException();
        string full = Path.GetFullPath(value).TrimEnd(Path.DirectorySeparatorChar);
        if (full.Length == 2) full += "\\";
        if (!String.Equals(value, full, StringComparison.OrdinalIgnoreCase) || full.Length <= 3) throw new InvalidDataException();
        string cursor = full;
        while (!String.IsNullOrEmpty(cursor) && cursor.Length > 3) {
            if ((File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException();
            cursor = Path.GetDirectoryName(cursor);
        }
        return full;
    }
    static bool SameFileHash(string left, string right) {
        try { return String.Equals(left, right, StringComparison.OrdinalIgnoreCase) || SHA256File(left) == SHA256File(right); }
        catch { return false; }
    }
    static bool ProtectedFilesPresent() { return File.Exists(ProtectedService) || File.Exists(ProtectedFence) || Directory.Exists(ServiceRoot); }
    static bool OwnedService(IntPtr service) {
        int needed;
        QueryServiceConfig(service, IntPtr.Zero, 0, out needed);
        if (needed <= 0 || needed > 65536) return false;
        IntPtr buffer = Marshal.AllocHGlobal(needed);
        try {
            if (!QueryServiceConfig(service, buffer, needed, out needed)) return false;
            var config = (ServiceConfig)Marshal.PtrToStructure(buffer, typeof(ServiceConfig));
            return String.Equals(config.binary, QuotedProtectedService, StringComparison.OrdinalIgnoreCase);
        } catch { return false; }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    static IntPtr Manager(uint access) {
        IntPtr manager = OpenSCManager(null, null, access);
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        return manager;
    }
    static IntPtr Service(IntPtr manager, uint access, bool required) {
        IntPtr service = OpenService(manager, ServiceName, access);
        if (service == IntPtr.Zero && required) throw new Win32Exception(Marshal.GetLastWin32Error());
        return service;
    }
    static int ServiceState(IntPtr service) {
        ServiceStatus status;
        Win32(QueryServiceStatus(service, out status));
        return status.state;
    }
    static void WaitState(IntPtr service, int wanted) {
        for (int i = 0; i < 150; i++) {
            int state = ServiceState(service);
            if (state == wanted) return;
            if (wanted == ServiceRunning && state == ServiceStopped) throw new InvalidOperationException();
            Thread.Sleep(100);
        }
        throw new TimeoutException();
    }
    static bool ServiceExists() {
        IntPtr manager = IntPtr.Zero, service = IntPtr.Zero;
        try {
            manager = Manager(ScManagerConnect);
            service = Service(manager, ServiceQueryStatus, false);
            return service != IntPtr.Zero;
        } catch { return false; }
        finally { if (service != IntPtr.Zero) CloseServiceHandle(service); if (manager != IntPtr.Zero) CloseServiceHandle(manager); }
    }
    static int CurrentServiceState() {
        IntPtr manager = IntPtr.Zero, service = IntPtr.Zero;
        try {
            manager = Manager(ScManagerConnect); service = Service(manager, ServiceQueryStatus, true);
            return ServiceState(service);
        } finally { if (service != IntPtr.Zero) CloseServiceHandle(service); if (manager != IntPtr.Zero) CloseServiceHandle(manager); }
    }
    static void RequireOwnedService(IntPtr service) { if (!OwnedService(service)) throw new UnauthorizedAccessException(); }

    static string Actions(params string[] values) { return values.Length == 0 ? "[]" : "[\"" + String.Join("\",\"", values) + "\"]"; }
    static string StatusJson(string state, string code, string actions, bool routing, bool installed) {
        return "{\"schema\":1,\"available\":true,\"state\":\"" + state + "\",\"code\":" + (code == null ? "null" : "\"" + code + "\"") +
            ",\"version\":" + (installed ? "\"" + ApiVersion + "\"" : "null") + ",\"actions\":" + actions + ",\"sessionRoutingSupported\":" + (routing ? "true" : "false") + "}";
    }
    static string ClientRequest(string request, int timeout) {
        using (var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous)) {
            pipe.Connect(timeout);
            byte[] output = new UTF8Encoding(false).GetBytes(request + "\n");
            var write = pipe.WriteAsync(output, 0, output.Length);
            if (!write.Wait(timeout)) throw new TimeoutException();
            var flush = pipe.FlushAsync(); if (!flush.Wait(timeout)) throw new TimeoutException();
            var buffer = new byte[2049]; int used = 0;
            while (used < buffer.Length) {
                var read = pipe.ReadAsync(buffer, used, 1);
                if (!read.Wait(timeout) || read.Result == 0) throw new TimeoutException();
                if (buffer[used++] == 10) break;
            }
            if (used == 0 || used > 2048 || buffer[used - 1] != 10) throw new InvalidDataException();
            return new UTF8Encoding(false, true).GetString(buffer, 0, used - 1).TrimEnd('\r');
        }
    }
    internal static bool QueryApi(out int active, out int api, out string fenceHash) {
        active = -1; api = 0; fenceHash = null;
        try {
            string line = ClientRequest("status", 4000);
            var match = Regex.Match(line ?? "", @"^\{""version"":1,""api"":([0-9]+),""networkFenceSHA256"":""([a-f0-9]{64})"",""active"":([0-9]+)\}$");
            if (!match.Success) return false;
            api = Int32.Parse(match.Groups[1].Value); fenceHash = match.Groups[2].Value; active = Int32.Parse(match.Groups[3].Value);
            return active >= 0 && active <= 16;
        } catch { return false; }
    }
    static string GetStatus() {
        try {
            bool exists = ServiceExists(), files = ProtectedFilesPresent();
            if (!exists && !files) return StatusJson("not_installed", null, Actions("install"), false, false);
            bool current = exists && File.Exists(ProtectedService) && File.Exists(ProtectedFence) &&
                SHA256File(ProtectedFence) == NetworkFenceSHA256 && SameFileHash(Self, ProtectedService);
            if (!current) return StatusJson("update_required", "SERVICE_UPDATE_REQUIRED", Actions("update", "uninstall"), false, true);
            int state = CurrentServiceState();
            if (state == ServiceStopped) return StatusJson("stopped", null, Actions("start", "update", "uninstall"), false, true);
            if (state != ServiceRunning) return StatusJson("error", "SERVICE_TRANSITION", Actions("update", "uninstall"), false, true);
            int active, api; string hash;
            if (!QueryApi(out active, out api, out hash)) return StatusJson("error", "SERVICE_PIPE_UNAVAILABLE", Actions("update", "uninstall"), false, true);
            if (api != Api || hash != NetworkFenceSHA256) return StatusJson("update_required", "SERVICE_API_INCOMPATIBLE", Actions("update", "uninstall"), false, true);
            return StatusJson("running", null, active == 0 ? Actions("stop", "uninstall") : Actions(), true, true);
        } catch { return StatusJson("error", "SERVICE_STATUS_FAILED", Actions("update", "uninstall"), false, true); }
    }

    static IntPtr ParseOwner(string value) {
        if (!Regex.IsMatch(value ?? "", @"^[0-9a-f]{1,16}$")) throw new Win32Exception(87);
        ulong raw = Convert.ToUInt64(value, 16);
        if (raw > Int64.MaxValue) throw new Win32Exception(87);
        IntPtr owner = new IntPtr((long)raw);
        if (owner != IntPtr.Zero && !IsWindow(owner)) throw new Win32Exception(1400);
        return owner;
    }
    static int Elevate(string operation, string owner) {
        var info = new ShellExecuteInfo { size = (uint)Marshal.SizeOf(typeof(ShellExecuteInfo)), mask = 0x00000540,
            window = ParseOwner(owner), verb = "runas", file = Self, parameters = operation, directory = Path.GetDirectoryName(Self), show = 0 };
        bool com = false;
        try {
            if (CoInitializeEx(IntPtr.Zero, 0x6) < 0) throw new Win32Exception(31);
            com = true;
            if (!ShellExecuteEx(ref info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (info.process == IntPtr.Zero) throw new Win32Exception(31);
            if (WaitForSingleObject(info.process, 120000) != 0) throw new TimeoutException();
            int code;
            if (!GetExitCodeProcess(info.process, out code)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return code;
        } finally { if (info.process != IntPtr.Zero) CloseHandle(info.process); if (com) CoUninitialize(); }
    }
    static int RequestInstall(string owner) {
        try {
            string before = GetStatus();
            if (before.Contains("\"state\":\"running\"") && before.Contains("\"sessionRoutingSupported\":true")) {
                Console.WriteLine("{\"version\":1,\"operation\":\"install\",\"code\":0,\"elevated\":false,\"state\":\"running\"}"); return 0;
            }
            if (before.Contains("\"state\":\"stopped\"")) {
                StartCurrent();
                string started = GetStatus();
                if (started.Contains("\"state\":\"running\"") && started.Contains("\"sessionRoutingSupported\":true")) {
                    Console.WriteLine("{\"version\":1,\"operation\":\"install\",\"code\":0,\"elevated\":false,\"state\":\"running\"}"); return 0;
                }
            }
            int elevated = Elevate("--install", owner);
            if (elevated != 0) { Console.WriteLine("{\"version\":1,\"operation\":\"install\",\"code\":" + elevated + ",\"elevated\":true,\"state\":\"error\"}"); return elevated; }
            string after = GetStatus();
            bool ok = after.Contains("\"state\":\"running\"") && after.Contains("\"sessionRoutingSupported\":true");
            Console.WriteLine("{\"version\":1,\"operation\":\"install\",\"code\":" + (ok ? 0 : 2) + ",\"elevated\":true,\"state\":\"" + (ok ? "running" : "error") + "\"}");
            return ok ? 0 : 2;
        } catch (Win32Exception error) {
            int code = error.NativeErrorCode > 0 && error.NativeErrorCode <= 65535 ? error.NativeErrorCode : 31;
            Console.WriteLine("{\"version\":1,\"operation\":\"install\",\"code\":" + code + ",\"elevated\":true,\"state\":\"error\"}"); return code;
        } catch { Console.WriteLine("{\"version\":1,\"operation\":\"install\",\"code\":2,\"elevated\":true,\"state\":\"error\"}"); return 2; }
    }
    static int RequestUninstall(string owner) {
        try {
            if (!ServiceExists() && !ProtectedFilesPresent()) {
                Console.WriteLine("{\"version\":1,\"operation\":\"uninstall\",\"code\":0,\"elevated\":false,\"state\":\"not_installed\"}"); return 0;
            }
            if (ServiceExists() && CurrentServiceState() == ServiceRunning) {
                int active, api; string hash;
                if (QueryApi(out active, out api, out hash) && api == Api && hash == NetworkFenceSHA256 && active > 0) {
                    Console.WriteLine("{\"version\":1,\"operation\":\"uninstall\",\"code\":2,\"elevated\":false,\"state\":\"error\"}"); return 2;
                }
            }
            int elevated = Elevate("--uninstall", owner);
            if (elevated != 0) { Console.WriteLine("{\"version\":1,\"operation\":\"uninstall\",\"code\":" + elevated + ",\"elevated\":true,\"state\":\"error\"}"); return elevated; }
            bool ok = !ServiceExists() && !ProtectedFilesPresent();
            Console.WriteLine("{\"version\":1,\"operation\":\"uninstall\",\"code\":" + (ok ? 0 : 2) + ",\"elevated\":true,\"state\":\"" + (ok ? "not_installed" : "error") + "\"}");
            return ok ? 0 : 2;
        } catch (Win32Exception error) {
            int code = error.NativeErrorCode > 0 && error.NativeErrorCode <= 65535 ? error.NativeErrorCode : 31;
            Console.WriteLine("{\"version\":1,\"operation\":\"uninstall\",\"code\":" + code + ",\"elevated\":true,\"state\":\"error\"}"); return code;
        } catch { Console.WriteLine("{\"version\":1,\"operation\":\"uninstall\",\"code\":2,\"elevated\":true,\"state\":\"error\"}"); return 2; }
    }

    static void RequireAdministrator() {
        if (IntPtr.Size != 8 || !new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) throw new UnauthorizedAccessException();
    }
    static void SecureDirectory(string path, string[] allowedEntries) {
        if (Directory.Exists(path)) {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException();
            var security = Directory.GetAccessControl(path);
            string owner = security.GetOwner(typeof(SecurityIdentifier)).Value;
            if (owner != "S-1-5-18" && owner != "S-1-5-32-544") throw new UnauthorizedAccessException();
            foreach (string entry in Directory.GetFileSystemEntries(path)) {
                string name = Path.GetFileName(entry);
                if (Array.IndexOf(allowedEntries, name) < 0) throw new InvalidDataException();
            }
        } else Directory.CreateDirectory(path);
        var acl = new DirectorySecurity();
        acl.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
        acl.SetAccessRuleProtection(true, false);
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-18"), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-32-544"), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-11"), FileSystemRights.ReadAndExecute | FileSystemRights.Traverse | FileSystemRights.Synchronize, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        Directory.SetAccessControl(path, acl);
    }
    static void ConfigureServiceSecurity(IntPtr service) {
        uint size; IntPtr descriptor;
        Win32(ConvertStringSecurityDescriptorToSecurityDescriptor("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;AU)", 1, out descriptor, out size));
        try { Win32(SetServiceObjectSecurity(service, 4, descriptor)); }
        finally { LocalFree(descriptor); }
        var description = new Description { value = "Launches only the protected Claude Proxy Guard NetworkFence broker." };
        IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Description)));
        try { Marshal.StructureToPtr(description, buffer, false); Win32(ChangeServiceConfig2(service, 1, buffer)); }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    internal static void RepairServiceSecurity() {
        IntPtr manager = IntPtr.Zero, service = IntPtr.Zero;
        try {
            manager = Manager(ScManagerConnect); service = Service(manager, ServiceWriteDac | ServiceChangeConfig, true);
            ConfigureServiceSecurity(service);
        } finally { if (service != IntPtr.Zero) CloseServiceHandle(service); if (manager != IntPtr.Zero) CloseServiceHandle(manager); }
    }
    static void CopyProtected(string source, string target) {
        string temporary = target + ".new";
        File.Copy(source, temporary, true);
        if (!SameFileHash(source, temporary)) throw new InvalidDataException();
        for (int i = 0; i < 50; i++) {
            try { File.Copy(temporary, target, true); File.Delete(temporary); return; }
            catch (IOException) { if (i == 49) throw; Thread.Sleep(100); }
            catch (UnauthorizedAccessException) { if (i == 49) throw; Thread.Sleep(100); }
        }
    }
    static int Install() {
        IntPtr manager = IntPtr.Zero, service = IntPtr.Zero; ManagementLock management = null; int stage = 10;
        try {
            RequireAdministrator(); management = new ManagementLock();
            RequireNoProtectedBroker();
            string sourceFence = Path.Combine(Path.GetDirectoryName(Self), "NetworkFence.exe");
            if (SHA256File(sourceFence) != NetworkFenceSHA256 || SHA256File(Self) == NetworkFenceSHA256) throw new InvalidDataException();
            stage = 20;
            SecureDirectory(ProgramDataRoot, new[] { "Service" });
            SecureDirectory(ServiceRoot, new[] { "GuardService.exe", "NetworkFence.exe", "GuardService.exe.new", "NetworkFence.exe.new" });
            stage = 30;
            manager = Manager(ScManagerConnect | ScManagerCreateService);
            service = Service(manager, ServiceAll, false);
            if (service != IntPtr.Zero) {
                RequireOwnedService(service);
                if (ServiceState(service) != ServiceStopped) { Win32(ControlService(service, 1, out ignored)); WaitState(service, ServiceStopped); }
            }
            stage = 40;
            RequireNoProtectedBroker();
            CopyProtected(sourceFence, ProtectedFence);
            CopyProtected(Self, ProtectedService);
            if (SHA256File(ProtectedFence) != NetworkFenceSHA256 || !SameFileHash(Self, ProtectedService)) throw new InvalidDataException();
            stage = 50;
            if (service == IntPtr.Zero) {
                service = CreateService(manager, ServiceName, "Claude Proxy Guard", ServiceAll, ServiceWin32OwnProcess, ServiceAutoStart, ServiceErrorNormal,
                    QuotedProtectedService, null, IntPtr.Zero, null, "LocalSystem", null);
                if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            ConfigureServiceSecurity(service);
            stage = 60;
            Win32(StartService(service, 0, IntPtr.Zero)); WaitState(service, ServiceRunning);
            stage = 70;
            int active, api; string hash;
            if (!QueryApi(out active, out api, out hash) || api != Api || hash != NetworkFenceSHA256) throw new InvalidOperationException();
            return 0;
        } catch (Exception error) { Console.Error.WriteLine("GUARD_SERVICE_INSTALL_STAGE_" + stage + "_" + error.GetType().Name + "_" + (error is Win32Exception ? ((Win32Exception)error).NativeErrorCode : 0)); return 2; }
        finally { if (service != IntPtr.Zero) CloseServiceHandle(service); if (manager != IntPtr.Zero) CloseServiceHandle(manager); if (management != null) management.Dispose(); }
    }
    const uint ServiceAll = 0xF01FF;
    static void StartCurrent() {
        IntPtr manager = IntPtr.Zero, service = IntPtr.Zero; ManagementLock management = null;
        try {
            management = new ManagementLock();
            manager = Manager(ScManagerConnect); service = Service(manager, ServiceQueryConfig | ServiceQueryStatus | ServiceStart, true);
            RequireOwnedService(service);
            if (SHA256File(ProtectedFence) != NetworkFenceSHA256) throw new InvalidDataException();
            if (ServiceState(service) == ServiceStopped) Win32(StartService(service, 0, IntPtr.Zero));
            WaitState(service, ServiceRunning);
        } finally { if (service != IntPtr.Zero) CloseServiceHandle(service); if (manager != IntPtr.Zero) CloseServiceHandle(manager); if (management != null) management.Dispose(); }
    }
    static int StartRequest() {
        try {
            string status = GetStatus();
            if (status.Contains("\"state\":\"running\"") && status.Contains("\"sessionRoutingSupported\":true")) return 0;
            if (!status.Contains("\"state\":\"stopped\"")) return 2;
            StartCurrent();
            status = GetStatus();
            return status.Contains("\"state\":\"running\"") && status.Contains("\"sessionRoutingSupported\":true") ? 0 : 2;
        } catch { return 2; }
    }
    static int StopRequest() {
        IntPtr manager = IntPtr.Zero, service = IntPtr.Zero; ManagementLock management = null;
        try {
            management = new ManagementLock();
            string status = GetStatus();
            if (status.Contains("\"state\":\"stopped\"")) return 0;
            if (!status.Contains("\"state\":\"running\"") || !status.Contains("\"sessionRoutingSupported\":true")) return 2;
            int active, api; string hash;
            if (!QueryApi(out active, out api, out hash) || active != 0 || api != Api || hash != NetworkFenceSHA256) return 2;
            manager = Manager(ScManagerConnect); service = Service(manager, ServiceQueryConfig | ServiceQueryStatus | ServiceStop, true);
            RequireOwnedService(service);
            Win32(ControlService(service, 1, out ignored)); WaitState(service, ServiceStopped);
            return ServiceState(service) == ServiceStopped ? 0 : 2;
        } catch { return 2; }
        finally { if (service != IntPtr.Zero) CloseServiceHandle(service); if (manager != IntPtr.Zero) CloseServiceHandle(manager); if (management != null) management.Dispose(); }
    }
    static int Uninstall() {
        IntPtr manager = IntPtr.Zero, service = IntPtr.Zero; ManagementLock management = null;
        try {
            RequireAdministrator(); management = new ManagementLock();
            RequireNoProtectedBroker();
            manager = Manager(ScManagerConnect); service = Service(manager, ServiceAll, false);
            if (service != IntPtr.Zero) {
                RequireOwnedService(service);
                if (ServiceState(service) == ServiceRunning) {
                    int active, api; string hash;
                    if (QueryApi(out active, out api, out hash) && api == Api && hash == NetworkFenceSHA256 && active > 0) throw new InvalidOperationException();
                }
                if (ServiceState(service) != ServiceStopped) { Win32(ControlService(service, 1, out ignored)); WaitState(service, ServiceStopped); }
                RequireNoProtectedBroker();
                Win32(DeleteService(service));
                CloseServiceHandle(service); service = IntPtr.Zero;
            }
            for (int i = 0; i < 100 && ServiceExists(); i++) Thread.Sleep(100);
            if (ServiceExists()) throw new InvalidOperationException();
            RequireNoProtectedBroker();
            if (Directory.Exists(ServiceRoot)) {
                if ((File.GetAttributes(ServiceRoot) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException();
                foreach (string entry in Directory.GetFileSystemEntries(ServiceRoot)) {
                    string name = Path.GetFileName(entry);
                    if (name != "GuardService.exe" && name != "NetworkFence.exe" && name != "GuardService.exe.new" && name != "NetworkFence.exe.new") throw new InvalidDataException();
                }
                foreach (string name in new[] { "GuardService.exe", "NetworkFence.exe", "GuardService.exe.new", "NetworkFence.exe.new" }) {
                    string file = Path.Combine(ServiceRoot, name);
                    if (File.Exists(file)) { if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException(); File.Delete(file); }
                }
                Directory.Delete(ServiceRoot, false);
            }
            if (Directory.Exists(ProgramDataRoot) && Directory.GetFileSystemEntries(ProgramDataRoot).Length == 0) Directory.Delete(ProgramDataRoot, false);
            return ServiceExists() || ProtectedFilesPresent() ? 2 : 0;
        } catch { return 2; }
        finally { if (service != IntPtr.Zero) CloseServiceHandle(service); if (manager != IntPtr.Zero) CloseServiceHandle(manager); if (management != null) management.Dispose(); }
    }

    internal static string DecodeRoot(string encoded) {
        if (encoded == null || encoded.Length > 512 || !Regex.IsMatch(encoded, @"^[A-Za-z0-9+/]*={0,2}$")) throw new InvalidDataException();
        byte[] bytes = Convert.FromBase64String(encoded);
        if (Convert.ToBase64String(bytes) != encoded) throw new InvalidDataException();
        string root = new UTF8Encoding(false, true).GetString(bytes);
        return LocalPath(root);
    }
    internal static void ValidateClientRoot(NamedPipeServerStream pipe, string root) {
        string sid = null;
        pipe.RunAsClient(delegate { using (WindowsIdentity client = WindowsIdentity.GetCurrent()) sid = client.User.Value; });
        if (String.IsNullOrEmpty(sid)) throw new UnauthorizedAccessException();
        object value = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid, "ProfileImagePath", null);
        if (!(value is string)) throw new UnauthorizedAccessException();
        string profile = LocalPath(Environment.ExpandEnvironmentVariables((string)value));
        if (!root.StartsWith(profile + "\\", StringComparison.OrdinalIgnoreCase) || !Regex.IsMatch(Path.GetFileName(root), @"^Runtime-[a-f0-9]{24}$")) throw new UnauthorizedAccessException();
        string manifest = Path.Combine(root, "guard-manifest.json");
        if (!File.Exists(manifest) || (File.GetAttributes(manifest) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException();
    }
    static int Launch(string[] args) {
        try {
            if (args.Length != 7 || args[1] != "--root" || args[3] != "--pipe" || args[5] != "--token" ||
                !Regex.IsMatch(args[4], @"^gate-network-fence-[a-f0-9]{32}$") || !Regex.IsMatch(args[6], @"^[a-f0-9]{64}$")) return 64;
            string root = DecodeRoot(args[2]);
            string status = GetStatus();
            if (!status.Contains("\"state\":\"running\"") || !status.Contains("\"sessionRoutingSupported\":true")) return 5;
            string response = ClientRequest("launch\t" + Convert.ToBase64String(Encoding.UTF8.GetBytes(root)) + "\t" + args[4] + "\t" + args[6], 5000);
            if (response == "{\"version\":1,\"launched\":true,\"code\":0}") { Console.WriteLine(response); return 0; }
            var match = Regex.Match(response ?? "", @"^\{""version"":1,""launched"":false,""code"":([0-9]+)\}$");
            if (!match.Success) return 1;
            int code = Int32.Parse(match.Groups[1].Value);
            Console.WriteLine(response); return code == 0 ? 1 : code;
        } catch { return 1; }
    }

    [STAThread] public static int Main(string[] args) {
        try {
            if (args.Length == 0) { ServiceBase.Run(new BrokerService()); return 0; }
            if (args.Length == 1 && args[0] == "--status") { Console.WriteLine(GetStatus()); return 0; }
            if (args.Length == 3 && args[0] == "--request-install") { if (args[1] != "--owner") return 64; return RequestInstall(args[2]); }
            if (args.Length == 3 && args[0] == "--request-uninstall") { if (args[1] != "--owner") return 64; return RequestUninstall(args[2]); }
            if (args.Length == 1 && args[0] == "--install") return Install();
            if (args.Length == 1 && args[0] == "--uninstall") return Uninstall();
            if (args.Length == 1 && args[0] == "--start") return StartRequest();
            if (args.Length == 1 && args[0] == "--stop") return StopRequest();
            if (args.Length > 0 && args[0] == "--launch") return Launch(args);
            return 64;
        } catch { return 2; }
    }
}

internal sealed class BrokerService : ServiceBase {
    static readonly object Sync = new object();
    static readonly HashSet<string> BrokerNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    static readonly List<NamedPipeServerStream> Clients = new List<NamedPipeServerStream>();
    static int activeBrokers, activeClients;
    static volatile bool stopping = true;
    volatile NamedPipeServerStream pending;
    Thread acceptThread;

    internal BrokerService() {
        ServiceName = GuardService.ServiceName;
        CanStop = true; CanShutdown = true; AutoLog = false;
    }
    static PipeSecurity PipeAcl() {
        var security = new PipeSecurity();
        security.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)");
        return security;
    }
    protected override void OnStart(string[] args) {
        GuardService.RepairServiceSecurity();
        if (GuardService.SHA256File(GuardService.ProtectedFence) != GuardService.NetworkFenceSHA256) throw new InvalidDataException();
        lock (Sync) stopping = false;
        acceptThread = new Thread(AcceptLoop) { IsBackground = true, Name = "GuardServicePipe" };
        acceptThread.Start();
    }
    protected override void OnStop() {
        lock (Sync) {
            stopping = true;
            if (activeBrokers != 0) {
                stopping = false;
                throw new InvalidOperationException("protected-broker-active");
            }
        }
        StopListener(); base.OnStop();
    }
    protected override void OnShutdown() { lock (Sync) stopping = true; StopListener(); base.OnShutdown(); }
    void StopListener() {
        try { if (pending != null) pending.Dispose(); } catch { }
        lock (Sync) foreach (var client in Clients.ToArray()) try { client.Dispose(); } catch { }
        if (acceptThread != null && !acceptThread.Join(5000)) throw new TimeoutException();
        for (int i = 0; i < 50; i++) { lock (Sync) if (activeClients == 0) return; Thread.Sleep(100); }
        throw new TimeoutException();
    }
    void AcceptLoop() {
        while (!stopping) {
            NamedPipeServerStream pipe = null;
            try {
                lock (Sync) if (activeClients >= 4) { Thread.Sleep(20); continue; }
                pipe = new NamedPipeServerStream(GuardService.PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 2048, 2048, PipeAcl());
                pending = pipe;
                if (!pipe.WaitForConnectionAsync().Wait(10000)) { pipe.Dispose(); pending = null; continue; }
                pending = null;
                if (stopping) { pipe.Dispose(); break; }
                lock (Sync) { activeClients++; Clients.Add(pipe); }
                ThreadPool.QueueUserWorkItem(Handle, pipe); pipe = null;
            } catch { pending = null; if (pipe != null) try { pipe.Dispose(); } catch { } if (!stopping) Thread.Sleep(50); }
        }
    }
    static string ReadLine(NamedPipeServerStream pipe) {
        var buffer = new byte[2049]; int used = 0;
        while (used < buffer.Length) {
            var task = pipe.ReadAsync(buffer, used, 1);
            if (!task.Wait(5000) || task.Result == 0) throw new TimeoutException();
            byte value = buffer[used++];
            if (value == 10) break;
        }
        if (used == 0 || used > 2048 || buffer[used - 1] != 10) throw new InvalidDataException();
        return new UTF8Encoding(false, true).GetString(buffer, 0, used - 1).TrimEnd('\r');
    }
    static void WriteLine(NamedPipeServerStream pipe, string value) {
        byte[] bytes = new UTF8Encoding(false).GetBytes(value + "\n");
        var task = pipe.WriteAsync(bytes, 0, bytes.Length);
        if (!task.Wait(5000)) throw new TimeoutException();
        task = pipe.FlushAsync(); if (!task.Wait(5000)) throw new TimeoutException();
    }
    void Handle(object state) {
        var pipe = (NamedPipeServerStream)state;
        try {
            string request = ReadLine(pipe);
            if (request == "status") {
                int active; lock (Sync) active = activeBrokers;
                WriteLine(pipe, "{\"version\":1,\"api\":" + GuardService.Api + ",\"networkFenceSHA256\":\"" + GuardService.NetworkFenceSHA256 + "\",\"active\":" + active + "}");
                return;
            }
            string[] parts = request.Split('\t');
            if (parts.Length != 4 || parts[0] != "launch" || !Regex.IsMatch(parts[2], @"^gate-network-fence-[a-f0-9]{32}$") || !Regex.IsMatch(parts[3], @"^[a-f0-9]{64}$")) throw new InvalidDataException();
            string root = GuardService.DecodeRoot(parts[1]);
            GuardService.ValidateClientRoot(pipe, root);
            Launch(root, parts[2], parts[3]);
            WriteLine(pipe, "{\"version\":1,\"launched\":true,\"code\":0}");
        } catch {
            try { WriteLine(pipe, "{\"version\":1,\"launched\":false,\"code\":5}"); } catch { }
        } finally {
            try { pipe.Dispose(); } catch { }
            lock (Sync) { Clients.Remove(pipe); activeClients--; }
        }
    }
    static void Launch(string root, string pipeName, string token) {
        lock (Sync) {
            if (stopping || activeBrokers >= 16 || BrokerNames.Contains(pipeName)) throw new InvalidOperationException();
            BrokerNames.Add(pipeName); activeBrokers++;
        }
        bool registered = true;
        try {
            if (GuardService.SHA256File(GuardService.ProtectedFence) != GuardService.NetworkFenceSHA256) throw new InvalidDataException();
            var start = new ProcessStartInfo { FileName = GuardService.ProtectedFence,
                Arguments = "--pipe " + pipeName + " --token " + token,
                WorkingDirectory = GuardService.ServiceRoot, UseShellExecute = false, CreateNoWindow = true };
            var process = new Process { StartInfo = start, EnableRaisingEvents = true };
            process.Exited += delegate {
                lock (Sync) { BrokerNames.Remove(pipeName); activeBrokers--; }
                process.Dispose();
            };
            if (!process.Start()) throw new InvalidOperationException();
            registered = false;
        } finally {
            if (registered) lock (Sync) { BrokerNames.Remove(pipeName); activeBrokers--; }
        }
    }
}
