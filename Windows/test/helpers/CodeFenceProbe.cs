// Compatibility probe only. No production code or filesystem ACL is modified.
// Build with the stock .NET Framework 4.x csc.exe, /platform:x64.
// create --name gate-probe-<32 lowercase hex>
// launch --name ... --workdir C:\owned\runtime [--lpac] [--debug] [--heartbeat-ms 5000] -- C:\owned\runtime\app.exe [arguments]
// delete --name ...
// launch stdin: "ping" at least every 5 seconds; EOF, "stop", invalid input,
// helper death or watchdog expiry destroys the owned Job Object and its tree.
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

internal static class CodeFenceProbe {
    const uint CREATE_SUSPENDED = 0x4;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x400;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x80000;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const uint DEBUG_ONLY_THIS_PROCESS = 0x2;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;
    const uint TOKEN_QUERY = 0x8;
    const uint TOKEN_DUPLICATE = 0x2;
    const uint WAIT_TIMEOUT = 258;
    const uint STILL_ACTIVE = 259;
    const int TokenIntegrityLevel = 25;
    const int TokenIsAppContainer = 29;
    const int TokenCapabilities = 30;
    const int TokenAppContainerSid = 31;
    const int TokenIsLessPrivilegedAppContainer = 46;
    static readonly IntPtr SECURITY_CAPABILITIES_ATTRIBUTE = new IntPtr(0x00020009);
    static readonly IntPtr ALL_APPLICATION_PACKAGES_POLICY_ATTRIBUTE = new IntPtr(0x0002000f);
    static string stage = "arguments";
    static int lastTokenClass, lastTokenError;
    static uint lastTokenLength;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
        public int cb; public string reserved, desktop, title;
        public int x, y, xSize, ySize, xCount, yCount, fill, flags;
        public short show, reserved2;
        public IntPtr reservedPtr, input, output, error;
    }
    [StructLayout(LayoutKind.Sequential)] struct STARTUPINFOEX { public STARTUPINFO startup; public IntPtr attributes; }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr process, thread; public uint pid, tid; }
    [StructLayout(LayoutKind.Sequential)] struct SECURITY_CAPABILITIES { public IntPtr sid, capabilities; public uint count, reserved; }
    [StructLayout(LayoutKind.Sequential)] struct GENERIC_MAPPING { public uint read, write, execute, all; }
    [StructLayout(LayoutKind.Explicit, Size = 48)] struct MEMORY_BASIC_INFORMATION {
        [FieldOffset(0)] public IntPtr address;
        [FieldOffset(8)] public IntPtr allocationBase;
        [FieldOffset(16)] public uint allocationProtect;
        [FieldOffset(24)] public UIntPtr regionSize;
        [FieldOffset(32)] public uint state;
        [FieldOffset(36)] public uint protect;
        [FieldOffset(40)] public uint type;
    }
    [StructLayout(LayoutKind.Sequential)] struct BASIC_LIMIT {
        public long processTime, jobTime; public uint flags;
        public UIntPtr minWorking, maxWorking; public uint activeProcesses;
        public UIntPtr affinity; public uint priority, scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct IO_COUNTERS { public ulong readOps, writeOps, otherOps, readBytes, writeBytes, otherBytes; }
    [StructLayout(LayoutKind.Sequential)] struct EXTENDED_LIMIT {
        public BASIC_LIMIT basic; public IO_COUNTERS io;
        public UIntPtr processMemory, jobMemory, peakProcessMemory, peakJobMemory;
    }
    sealed class Options {
        public string mode, name, directory, target, relayImage;
        public int relayPort;
        public bool lpac, debug;
        public int heartbeat = 5000;
        public string[] childArguments = new string[0];
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] static extern int CreateAppContainerProfile(string name, string display, string description, IntPtr capabilities, uint count, out IntPtr sid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] static extern int DeleteAppContainerProfile(string name);
    [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr text);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int informationClass, IntPtr information, uint length, out uint needed);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateToken(IntPtr token, int level, out IntPtr duplicate);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string descriptor, uint revision, out IntPtr security, out uint bytes);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AccessCheck(IntPtr security, IntPtr token, uint desired, ref GENERIC_MAPPING mapping, IntPtr privileges, ref uint privilegeBytes, out uint granted, out bool accessStatus);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref IntPtr bytes);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr bytes, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)] static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref STARTUPINFOEX startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr job, int type, ref EXTENDED_LIMIT info, int length);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool QueryInformationJobObject(IntPtr job, int type, IntPtr data, uint length, out uint returned);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool WaitForDebugEventEx(IntPtr data, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ContinueDebugEvent(uint process, uint thread, uint status);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool DebugSetProcessKillOnExit(bool kill);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetFinalPathNameByHandle(IntPtr file, StringBuilder path, uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] data, UIntPtr length, out UIntPtr read);
    [DllImport("kernel32.dll", SetLastError = true)] static extern UIntPtr VirtualQueryEx(IntPtr process, IntPtr address, out MEMORY_BASIC_INFORMATION info, UIntPtr length);
    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetMappedFileName(IntPtr process, IntPtr address, StringBuilder path, uint length);
    [DllImport("kernel32.dll")] static extern uint GetCurrentProcessId();
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ProcessIdToSessionId(uint process, out uint session);
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool GetUserObjectInformation(IntPtr handle, int index, IntPtr information, uint length, out uint needed);

    static void Check(bool success) { if (!success) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static void CheckHR(int hr) { if (hr < 0) Marshal.ThrowExceptionForHR(hr); }
    static string Json(string value) {
        if (value == null) return "null";
        StringBuilder result = new StringBuilder("\"");
        foreach (char c in value) {
            if (c == '\\') result.Append("\\\\");
            else if (c == '"') result.Append("\\\"");
            else if (c < 32) result.Append("\\u" + ((int)c).ToString("x4"));
            else result.Append(c);
        }
        return result.Append('"').ToString();
    }
    static void Emit(string json) { Console.Out.WriteLine(json); Console.Out.Flush(); }
    static string Quote(string value) {
        StringBuilder result = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value) {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { result.Append('\\', slashes * 2 + 1); result.Append(c); }
            else { result.Append('\\', slashes); result.Append(c); }
            slashes = 0;
        }
        result.Append('\\', slashes * 2); return result.Append('"').ToString();
    }
    static Options Parse(string[] args) {
        if (args.Length < 3) throw new ArgumentException();
        Options result = new Options(); result.mode = args[0];
        if (result.mode != "create" && result.mode != "launch" && result.mode != "delete") throw new ArgumentException();
        int i = 1;
        while (i < args.Length) {
            string key = args[i++];
            if (key == "--") {
                if (result.mode != "launch" || i >= args.Length) throw new ArgumentException();
                result.target = args[i++];
                result.childArguments = new string[args.Length - i]; Array.Copy(args, i, result.childArguments, 0, result.childArguments.Length);
                i = args.Length; break;
            }
            if (key == "--lpac") { if (result.lpac) throw new ArgumentException(); result.lpac = true; continue; }
            if (key == "--debug") { if (result.debug) throw new ArgumentException(); result.debug = true; continue; }
            if (i == args.Length) throw new ArgumentException();
            string value = args[i++];
            if (key == "--name" && result.name == null) result.name = value;
            else if (key == "--workdir" && result.directory == null) result.directory = value;
            else if (key == "--relay-image" && result.relayImage == null) result.relayImage = value;
            else if (key == "--relay-port" && Int32.TryParse(value, out result.relayPort)) { }
            else if (key == "--heartbeat-ms" && Int32.TryParse(value, out result.heartbeat)) { }
            else throw new ArgumentException();
        }
        // Cleanup can address only a unique profile from this scratch probe.
        if (result.name == null || !Regex.IsMatch(result.name, "^gate-probe-[0-9a-f]{32}$")) throw new ArgumentException();
        if (result.heartbeat < 1000 || result.heartbeat > 30000) throw new ArgumentException();
        if (result.mode == "launch") {
            if (result.target == null || !Path.IsPathRooted(result.target) || !File.Exists(result.target) || !result.target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException();
            if (result.directory == null || !Path.IsPathRooted(result.directory) || !Directory.Exists(result.directory)) throw new ArgumentException();
        } else if (result.target != null || result.directory != null || result.lpac || result.debug) throw new ArgumentException();
        return result;
    }
    static string SidString(IntPtr sid) {
        IntPtr text = IntPtr.Zero;
        try { Check(sid != IntPtr.Zero && ConvertSidToStringSid(sid, out text)); return Marshal.PtrToStringUni(text); }
        finally { if (text != IntPtr.Zero) LocalFree(text); }
    }
    static IntPtr TokenInformation(IntPtr token, int type) {
        uint needed = 0;
        lastTokenClass = type;
        GetTokenInformation(token, type, IntPtr.Zero, 0, out needed);
        lastTokenError = Marshal.GetLastWin32Error(); lastTokenLength = needed;
        if (needed == 0 || needed > 65536) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr buffer = Marshal.AllocHGlobal((int)needed);
        try { Check(GetTokenInformation(token, type, buffer, needed, out needed)); return buffer; }
        catch { Marshal.FreeHGlobal(buffer); throw; }
    }
    static int TokenNumber(IntPtr token, int type) {
        if (type == TokenIsAppContainer || type == TokenIsLessPrivilegedAppContainer) {
            IntPtr scalar = Marshal.AllocHGlobal(4);
            try {
                Marshal.WriteInt32(scalar, 0); uint needed;
                lastTokenClass = type;
                bool success = GetTokenInformation(token, type, scalar, 4, out needed);
                lastTokenError = success ? 0 : Marshal.GetLastWin32Error(); lastTokenLength = needed;
                if (!success) throw new Win32Exception(lastTokenError);
                return Marshal.ReadInt32(scalar);
            } finally { Marshal.FreeHGlobal(scalar); }
        }
        IntPtr buffer = TokenInformation(token, type);
        try { return Marshal.ReadInt32(buffer); } finally { Marshal.FreeHGlobal(buffer); }
    }
    static string TokenSid(IntPtr token, int type) {
        IntPtr buffer = TokenInformation(token, type);
        try { return SidString(Marshal.ReadIntPtr(buffer)); } finally { Marshal.FreeHGlobal(buffer); }
    }
    static bool GrantsRead(IntPtr impersonationToken, string secondSid) {
        IntPtr security = IntPtr.Zero, privileges = IntPtr.Zero;
        try {
            uint bytes;
            // Both user and package checks must pass. Owner/group are explicit;
            // no real object or persistent security descriptor is ever changed.
            string sddl = "O:SYG:SYD:(A;;0x1;;;WD)(A;;0x1;;;" + secondSid + ")";
            Check(ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out security, out bytes));
            privileges = Marshal.AllocHGlobal(4096); uint privilegeBytes = 4096, granted;
            GENERIC_MAPPING mapping = new GENERIC_MAPPING(); mapping.read = 1; mapping.write = 2; mapping.execute = 4; mapping.all = 7;
            bool access;
            Check(AccessCheck(security, impersonationToken, 1, ref mapping, privileges, ref privilegeBytes, out granted, out access));
            return access && (granted & 1) != 0;
        } finally { if (security != IntPtr.Zero) LocalFree(security); if (privileges != IntPtr.Zero) Marshal.FreeHGlobal(privileges); }
    }
    static bool IsLPAC(IntPtr token, string packageSid, out string verification, out int queryError) {
        queryError = 0;
        try { bool value = TokenNumber(token, TokenIsLessPrivilegedAppContainer) != 0; verification = "token-class-46"; return value; }
        catch (Win32Exception error) {
            if (error.NativeErrorCode != 87 && error.NativeErrorCode != 50) throw;
            queryError = error.NativeErrorCode;
        }
        // Class 46 is rejected by some Windows builds. LPAC is documented as
        // disregarding ALL_APPLICATION_PACKAGES. This bounded AccessCheck probe
        // measures that semantic property, rather than silently skipping proof.
        // It is an observed semantic verification, not a class-46 API contract.
        IntPtr duplicate = IntPtr.Zero;
        try {
            Check(DuplicateToken(token, 2, out duplicate));
            if (!GrantsRead(duplicate, packageSid)) throw new SecurityException();
            bool allApplicationPackages = GrantsRead(duplicate, "S-1-15-2-1");
            verification = "access-check-semantics";
            return !allApplicationPackages;
        } finally { if (duplicate != IntPtr.Zero) CloseHandle(duplicate); }
    }
    static void Snapshot(IntPtr job, uint mainPid, long elapsed) {
        // Job membership, not a process-name search: unrelated installed Claude
        // processes are neither enumerated, inspected, nor terminated.
        IntPtr buffer = Marshal.AllocHGlobal(8192);
        try {
            uint returned;
            Check(QueryInformationJobObject(job, 3, buffer, 8192, out returned));
            int count = Marshal.ReadInt32(buffer, 4);
            if (count < 0 || count > (8192 - 8) / IntPtr.Size) throw new SecurityException();
            StringBuilder records = new StringBuilder(); bool mainAlive = false;
            for (int i = 0; i < count; i++) {
                uint pid = unchecked((uint)Marshal.ReadIntPtr(buffer, 8 + i * IntPtr.Size).ToInt64());
                if (records.Length != 0) records.Append(',');
                IntPtr process = IntPtr.Zero, token = IntPtr.Zero;
                try {
                    process = OpenProcess(0x1000, false, pid); Check(process != IntPtr.Zero);
                    Check(OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, out token));
                    bool ac = TokenNumber(token, TokenIsAppContainer) != 0;
                    string image=Process.GetProcessById((int)pid).ProcessName;string imageKind=String.Equals(image,"powershell",StringComparison.OrdinalIgnoreCase)?"powershell":String.Equals(image,"canary",StringComparison.OrdinalIgnoreCase)?"native-canary":"other";
                    int caps = TokenNumber(token, TokenCapabilities);
                    string sid = ac ? TokenSid(token, TokenAppContainerSid) : null;
                    string proof = "not-appcontainer"; int lpacError = 0;
                    bool lpac = ac && IsLPAC(token, sid, out proof, out lpacError);
                    uint code;
                    if (pid == mainPid && GetExitCodeProcess(process, out code) && code == STILL_ACTIVE) mainAlive = true;
                    records.Append("{\"pid\":").Append(pid).Append(",\"isAppContainer\":").Append(ac ? "true" : "false")
                        .Append(",\"imageKind\":").Append(Json(imageKind)).Append(",\"lpac\":").Append(lpac ? "true" : "false").Append(",\"capabilityCount\":").Append(caps)
                        .Append(",\"sid\":").Append(Json(sid)).Append(",\"lpacVerification\":").Append(Json(proof))
                        .Append(",\"lpacQueryError\":").Append(lpacError).Append('}');
                } catch (Exception error) {
                    int code = error is Win32Exception ? ((Win32Exception)error).NativeErrorCode : 0;
                    records.Append("{\"pid\":").Append(pid).Append(",\"queryError\":").Append(code).Append('}');
                } finally { if (token != IntPtr.Zero) CloseHandle(token); if (process != IntPtr.Zero) CloseHandle(process); }
            }
            Emit("{\"event\":\"job\",\"elapsedMilliseconds\":" + elapsed + ",\"mainAlive\":" + (mainAlive ? "true" : "false") + ",\"processes\":[" + records + "]}");
        } finally { Marshal.FreeHGlobal(buffer); }
    }
    static int Create(Options options) {
        stage = "CreateAppContainerProfile";
        IntPtr sid = IntPtr.Zero;
        try {
            int hr = CreateAppContainerProfile(options.name, options.name, "Temporary gate-claude compatibility probe", IntPtr.Zero, 0, out sid);
            bool created = hr >= 0;
            if (hr == unchecked((int)0x800700B7)) {
                stage = "DeriveAppContainerSid"; CheckHR(DeriveAppContainerSidFromAppContainerName(options.name, out sid));
            } else CheckHR(hr);
            Emit("{\"event\":\"profile\",\"result\":\"READY\",\"profile\":" + Json(options.name) + ",\"sid\":" + Json(SidString(sid)) + ",\"created\":" + (created ? "true" : "false") + ",\"capabilityCount\":0}");
            return 0;
        } finally { if (sid != IntPtr.Zero) FreeSid(sid); }
    }
    static int Delete(Options options) {
        stage = "DeleteAppContainerProfile";
        int hr = DeleteAppContainerProfile(options.name);
        bool deleted = hr >= 0;
        if (hr != unchecked((int)0x80070002) && hr != unchecked((int)0x80070003)) CheckHR(hr);
        Emit("{\"event\":\"cleanup\",\"profile\":" + Json(options.name) + ",\"deleted\":" + (deleted ? "true" : "false") + "}");
        return 0;
    }
    static void DesktopContext(uint childPid) {
        uint parentSession, childSession;
        bool parentKnown = ProcessIdToSessionId(GetCurrentProcessId(), out parentSession);
        bool childKnown = ProcessIdToSessionId(childPid, out childSession);
        string category = "unknown";
        bool visible = false, visibilityKnown = false;
        int error = 0;
        // Borrowed process handle: never close it, create a station, or change
        // any window-station/desktop ACL. Do not expose the service logon LUID.
        IntPtr station = GetProcessWindowStation();
        if (station == IntPtr.Zero) error = Marshal.GetLastWin32Error();
        else {
            uint needed;
            GetUserObjectInformation(station, 2, IntPtr.Zero, 0, out needed); // UOI_NAME
            if (needed > 0 && needed <= 4096) {
                IntPtr name = Marshal.AllocHGlobal((int)needed);
                try {
                    if (GetUserObjectInformation(station, 2, name, needed, out needed)) {
                        string value = Marshal.PtrToStringUni(name);
                        category = String.Equals(value, "WinSta0", StringComparison.OrdinalIgnoreCase) ? "winsta0" :
                            value != null && value.StartsWith("Service-", StringComparison.OrdinalIgnoreCase) ? "service" : "other";
                    } else error = Marshal.GetLastWin32Error();
                } finally { Marshal.FreeHGlobal(name); }
            }
            IntPtr flags = Marshal.AllocHGlobal(12); // USEROBJECTFLAGS: two BOOLs and DWORD flags.
            try {
                visibilityKnown = GetUserObjectInformation(station, 1, flags, 12, out needed); // UOI_FLAGS
                if (visibilityKnown) visible = (Marshal.ReadInt32(flags, 8) & 1) != 0; // WSF_VISIBLE
                else if (error == 0) error = Marshal.GetLastWin32Error();
            } finally { Marshal.FreeHGlobal(flags); }
        }
        bool interactive = category == "winsta0" && visibilityKnown && visible && parentKnown && parentSession != 0;
        Emit("{\"event\":\"desktop-context\",\"parentSessionId\":" + (parentKnown ? parentSession.ToString() : "null") +
            ",\"childSessionId\":" + (childKnown ? childSession.ToString() : "null") +
            ",\"sameSession\":" + (parentKnown && childKnown && parentSession == childSession ? "true" : "false") +
            ",\"windowStationCategory\":" + Json(category) + ",\"interactiveStation\":" + (interactive ? "true" : "false") +
            ",\"windowStationVisible\":" + (visibilityKnown ? visible ? "true" : "false" : "null") +
            ",\"childStationMeasured\":false,\"startupDesktopSpecified\":false,\"handlesInherited\":false,\"queryError\":" + error + "}");
    }
    sealed class DebugSession : IDisposable {
        const uint DBG_CONTINUE = 0x00010002, DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        readonly IntPtr process;
        readonly uint pid;
        readonly IntPtr buffer = Marshal.AllocHGlobal(176); // DEBUG_EVENT x64: union offset 16, EXCEPTION_DEBUG_INFO size 160.
        readonly Dictionary<long, string> modules = new Dictionary<long, string>();
        readonly StreamWriter raw;
        bool loaderBreakpoint;
        int records, criticalRecords, rawBytes;
        public bool Exited;
        public DebugSession(IntPtr processHandle, uint processId, string directory) {
            process = processHandle; pid = processId;
            // CreateNew + a fresh random filename before ResumeThread. Raw debug
            // strings stay private in the caller's owned, empty scratch profile.
            string file = Path.Combine(directory, "AppContainerProbe.debug-private-" + Guid.NewGuid().ToString("N") + ".jsonl");
            raw = new StreamWriter(new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.Read), new UTF8Encoding(false));
        }
        static string ModuleName(string filename) {
            string name = Path.GetFileName(filename);
            return name != null && Regex.IsMatch(name, @"^[A-Za-z0-9_.-]{1,128}$") ? name : "[module]";
        }
        static string FileModule(IntPtr file) {
            if (file == IntPtr.Zero || file == new IntPtr(-1)) return "[unknown]";
            StringBuilder path = new StringBuilder(4096);
            uint count = GetFinalPathNameByHandle(file, path, (uint)path.Capacity, 0);
            return count > 0 && count < path.Capacity ? ModuleName(path.ToString()) : "[unknown]";
        }
        string AddressModule(IntPtr address, out string offset) {
            offset = "[unknown]";
            MEMORY_BASIC_INFORMATION memory;
            if (VirtualQueryEx(process, address, out memory, new UIntPtr(48)).ToUInt64() == 0 || memory.type != 0x1000000) return "[unmapped]";
            long difference = address.ToInt64() - memory.allocationBase.ToInt64();
            if (difference < 0) return "[unknown]";
            offset = "0x" + difference.ToString("x");
            string name;
            if (modules.TryGetValue(memory.allocationBase.ToInt64(), out name) && !name.StartsWith("[", StringComparison.Ordinal)) return name;
            StringBuilder path = new StringBuilder(4096);
            uint count = GetMappedFileName(process, address, path, (uint)path.Capacity);
            return count > 0 && count < path.Capacity ? ModuleName(path.ToString()) : "[unknown]";
        }
        void Record(string fields) {
            // Bound diagnostics without ever stopping ContinueDebugEvent.
            bool critical = fields.Contains("\"kind\":\"exception\"") || fields.Contains("\"kind\":\"output\"") || fields.Contains("\"kind\":\"exit\"");
            if (++records <= 256 || critical && ++criticalRecords <= 64) Emit("{\"event\":\"debug\"," + fields + "}");
        }
        void DebugString(IntPtr data) {
            IntPtr address = Marshal.ReadIntPtr(data, 16);
            bool unicode = Marshal.ReadInt16(data, 24) != 0;
            int declaredBytes = unchecked((ushort)Marshal.ReadInt16(data, 26));
            // Microsoft documents nDebugStringLength in bytes. Never read past
            // that event-supplied boundary or past the explicit 8 KiB ceiling.
            int bytes = Math.Min(declaredBytes, 8192);
            if (unicode) bytes -= bytes % 2;
            if (address == IntPtr.Zero || bytes == 0) return;
            byte[] payload = new byte[bytes]; UIntPtr read;
            // The only process-memory read in this probe: this debug-event's
            // explicit string address and length, never a stack or arbitrary heap.
            bool success = ReadProcessMemory(process, address, payload, new UIntPtr((uint)bytes), out read);
            int actual = (int)Math.Min((ulong)bytes, read.ToUInt64());
            if (unicode) actual -= actual % 2;
            if (!success && actual == 0) { Record("\"kind\":\"output\",\"readError\":" + Marshal.GetLastWin32Error()); return; }
            string value = (unicode ? Encoding.Unicode : Encoding.Default).GetString(payload, 0, actual).TrimEnd('\0');
            if (rawBytes + actual <= 131072) {
                raw.WriteLine("{\"kind\":\"output\",\"unicode\":" + (unicode ? "true" : "false") + ",\"text\":" + Json(value) + "}");
                raw.Flush(); rawBytes += actual;
            }
            // Free-form debug text is confined to the private bounded file.
            Record("\"kind\":\"output\",\"unicode\":" + (unicode ? "true" : "false") + ",\"bytes\":" + actual +
                ",\"truncated\":" + (declaredBytes > bytes ? "true" : "false"));
        }
        public bool Pump(uint timeout) {
            if (!WaitForDebugEventEx(buffer, timeout)) {
                int error = Marshal.GetLastWin32Error();
                if (error == 121 || error == 258) return false;
                throw new Win32Exception(error);
            }
            uint code = unchecked((uint)Marshal.ReadInt32(buffer, 0));
            uint eventPid = unchecked((uint)Marshal.ReadInt32(buffer, 4));
            uint tid = unchecked((uint)Marshal.ReadInt32(buffer, 8));
            uint continuation = DBG_CONTINUE;
            try {
                if (eventPid != pid) throw new SecurityException();
                if (code == 3 || code == 6) {
                    IntPtr file = Marshal.ReadIntPtr(buffer, 16);
                    IntPtr address = Marshal.ReadIntPtr(buffer, code == 3 ? 40 : 24);
                    string module;
                    try { module = FileModule(file); }
                    finally { if (file != IntPtr.Zero && file != new IntPtr(-1)) CloseHandle(file); }
                    modules[address.ToInt64()] = module;
                    Record("\"kind\":\"module\",\"module\":" + Json(module) + ",\"mainImage\":" + (code == 3 ? "true" : "false"));
                    // Windows owns the debug-event process/thread handles and
                    // closes them after their EXIT_* events are continued.
                } else if (code == 7) {
                    modules.Remove(Marshal.ReadIntPtr(buffer, 16).ToInt64());
                } else if (code == 8) {
                    DebugString(buffer);
                } else if (code == 1) {
                    uint exception = unchecked((uint)Marshal.ReadInt32(buffer, 16));
                    IntPtr address = Marshal.ReadIntPtr(buffer, 32);
                    bool firstChance = Marshal.ReadInt32(buffer, 168) != 0;
                    string offset, module = AddressModule(address, out offset);
                    bool initial = exception == 0x80000003 && firstChance && !loaderBreakpoint &&
                        String.Equals(module, "ntdll.dll", StringComparison.OrdinalIgnoreCase);
                    if (initial) loaderBreakpoint = true;
                    continuation = initial ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
                    Record("\"kind\":\"exception\",\"code\":\"0x" + exception.ToString("x8") + "\",\"firstChance\":" + (firstChance ? "true" : "false") +
                        ",\"initialLoaderBreakpoint\":" + (initial ? "true" : "false") + ",\"module\":" + Json(module) + ",\"offset\":" + Json(offset));
                } else if (code == 5) {
                    uint exit = unchecked((uint)Marshal.ReadInt32(buffer, 16));
                    Exited = true;
                    Record("\"kind\":\"exit\",\"exitCode\":" + exit);
                } else if (code == 9) {
                    Record("\"kind\":\"rip\",\"code\":" + unchecked((uint)Marshal.ReadInt32(buffer, 16)) +
                        ",\"type\":" + unchecked((uint)Marshal.ReadInt32(buffer, 20)));
                }
            } finally {
                // The main thread that created the debuggee must always continue
                // each event, including ordinary loader/thread/module events.
                Check(ContinueDebugEvent(eventPid, tid, continuation));
            }
            return true;
        }
        public void Dispose() { raw.Dispose(); Marshal.FreeHGlobal(buffer); }
    }
    static int Launch(Options options) {
        IntPtr sid = IntPtr.Zero, attributes = IntPtr.Zero, capabilities = IntPtr.Zero, lpacPolicy = IntPtr.Zero, job = IntPtr.Zero, token = IntPtr.Zero;
        PROCESS_INFORMATION child = new PROCESS_INFORMATION();
        DebugSession debugger = null;
        bool attributesReady = false, assigned = false, installed=false, exempted=false, retired=false;
        string expectedSid=null;
        try {
            stage = "DeriveAppContainerSid"; CheckHR(DeriveAppContainerSidFromAppContainerName(options.name, out sid));
            expectedSid = SidString(sid);
            stage = "CreateJobObject"; job = CreateJobObject(IntPtr.Zero, null); Check(job != IntPtr.Zero);
            EXTENDED_LIMIT limits = new EXTENDED_LIMIT(); limits.basic.flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            Check(SetInformationJobObject(job, 9, ref limits, Marshal.SizeOf(limits)));
            stage = "CodeNetworkFence.Install"; installed=true;CodeNetworkFence.BindAndInstall(expectedSid,options.relayPort,options.relayImage,job);
            stage = "CodeNetworkFence.Verify"; CodeNetworkFence.Apply(expectedSid,options.relayPort,options.relayImage,"Verify");
            stage = "LoopbackExemption"; exempted=true;SetLoopback(expectedSid,true);
            Emit("{\"event\":\"policy\",\"filters\":10,\"zeroCapabilities\":true,\"relayPort\":"+options.relayPort+"}");
            stage = "InitializeProcThreadAttributeList";
            IntPtr bytes = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, options.lpac ? 2 : 1, 0, ref bytes);
            if (bytes.ToInt64() <= 0 || bytes.ToInt64() > 1048576) throw new Win32Exception(Marshal.GetLastWin32Error());
            attributes = Marshal.AllocHGlobal(bytes);
            Check(InitializeProcThreadAttributeList(attributes, options.lpac ? 2 : 1, 0, ref bytes)); attributesReady = true;
            SECURITY_CAPABILITIES security = new SECURITY_CAPABILITIES(); security.sid = sid; // No capabilities, including no network capability.
            capabilities = Marshal.AllocHGlobal(Marshal.SizeOf(security)); Marshal.StructureToPtr(security, capabilities, false);
            stage = "UpdateSecurityCapabilities";
            Check(UpdateProcThreadAttribute(attributes, 0, SECURITY_CAPABILITIES_ATTRIBUTE, capabilities, new IntPtr(Marshal.SizeOf(security)), IntPtr.Zero, IntPtr.Zero));
            if (options.lpac) {
                lpacPolicy = Marshal.AllocHGlobal(4); Marshal.WriteInt32(lpacPolicy, 1); // ALL_APPLICATION_PACKAGES_OPT_OUT
                stage = "UpdateLPACPolicy";
                Check(UpdateProcThreadAttribute(attributes, 0, ALL_APPLICATION_PACKAGES_POLICY_ATTRIBUTE, lpacPolicy, new IntPtr(4), IntPtr.Zero, IntPtr.Zero));
            }
            StringBuilder command = new StringBuilder(Quote(options.target));
            foreach (string argument in options.childArguments) command.Append(' ').Append(Quote(argument));
            if (command.Length > 32766) throw new ArgumentException();
            STARTUPINFOEX startup = new STARTUPINFOEX(); startup.startup.cb = Marshal.SizeOf(startup); startup.attributes = attributes;
            // No inherited handles and no new console: child output cannot pollute
            // this probe's JSON channel. The caller's environment is passed as-is,
            // including PROXY_GUARD_CONFIG; no environment values are ever printed.
            stage = "CreateProcessSuspended";
            Check(CreateProcessW(options.target, command, IntPtr.Zero, IntPtr.Zero, false,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | (options.debug ? DEBUG_ONLY_THIS_PROCESS : 0),
                IntPtr.Zero, options.directory, ref startup, out child));
            stage = "AssignProcessToJobObject"; Check(AssignProcessToJobObject(job, child.process)); assigned = true;
            DesktopContext(child.pid);
            if (options.debug) {
                stage = "InitializeDebugger"; Check(DebugSetProcessKillOnExit(true));
                debugger = new DebugSession(child.process, child.pid, options.directory);
            }
            stage = "OpenProcessToken"; Check(OpenProcessToken(child.process, TOKEN_QUERY | TOKEN_DUPLICATE, out token));
            stage = "TokenIsAppContainer";
            bool isAppContainer = TokenNumber(token, TokenIsAppContainer) != 0;
            stage = "TokenCapabilities";
            int capabilityCount = TokenNumber(token, TokenCapabilities);
            stage = "TokenAppContainerSid";
            string actualSid = TokenSid(token, TokenAppContainerSid);
            stage = "TokenIntegrityLevel";
            string integrity = TokenSid(token, TokenIntegrityLevel);
            stage = "VerifyLPAC";
            string lpacVerification; int lpacQueryError;
            bool isLPAC = IsLPAC(token, actualSid, out lpacVerification, out lpacQueryError);
            if (!isAppContainer || isLPAC != options.lpac || capabilityCount != 0 || !String.Equals(expectedSid, actualSid, StringComparison.Ordinal)) throw new SecurityException();
            Emit("{\"event\":\"token\",\"state\":\"suspended\",\"pid\":" + child.pid + ",\"isAppContainer\":true,\"sid\":" + Json(actualSid) +
                ",\"lpac\":" + (isLPAC ? "true" : "false") + ",\"lpacVerification\":" + Json(lpacVerification) + ",\"lpacQueryError\":" + lpacQueryError +
                ",\"integritySid\":" + Json(integrity) + ",\"capabilityCount\":0,\"jobAssigned\":true,\"breakawayAllowed\":false}");
            stage = "ResumeThread"; if (ResumeThread(child.thread) == UInt32.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
            Emit("{\"event\":\"started\",\"pid\":" + child.pid + ",\"heartbeatMilliseconds\":" + options.heartbeat +
                ",\"debugOnlyThisProcess\":" + (options.debug ? "true" : "false") + "}");
            long heartbeat = Stopwatch.GetTimestamp(), started = heartbeat, lastSnapshot = heartbeat; int control = 0;
            Task input = Task.Factory.StartNew(delegate {
                try {
                    string line;
                    while ((line = Console.In.ReadLine()) != null) {
                        if(line=="seal"){Interlocked.Exchange(ref control,5);continue;}
                        if (line != "ping") { Interlocked.Exchange(ref control, line == "stop" ? 2 : 3); return; }
                        Interlocked.Exchange(ref heartbeat, Stopwatch.GetTimestamp());
                    }
                    Interlocked.Exchange(ref control, 1);
                } catch { Interlocked.Exchange(ref control, 4); }
            });
            string reason = "child-exit";
            stage = "MonitorJob";
            for (;;) {
                if (debugger != null) {
                    stage = "WaitForDebugEvent";
                    debugger.Pump(50);
                    stage = "MonitorJob";
                    if (debugger.Exited) break;
                }
                uint wait = WaitForSingleObject(child.process, debugger == null ? (uint)50 : 0);
                if (wait != WAIT_TIMEOUT) { if (wait != 0) throw new Win32Exception(Marshal.GetLastWin32Error()); break; }
                int commandState = Interlocked.CompareExchange(ref control, 0, 0);
                if(commandState==5){
                    stage="CodeNetworkFence.Seal";CodeNetworkFence.Apply(expectedSid,options.relayPort,options.relayImage,"Seal");CodeNetworkFence.Apply(expectedSid,options.relayPort,options.relayImage,"VerifySealed");
                    bool wrongJobRejected=false;IntPtr otherJob=CreateJobObject(IntPtr.Zero,null);try{try{CodeNetworkFence.RetireAfterJobExit(expectedSid,options.relayPort,options.relayImage,otherJob);}catch(InvalidOperationException){wrongJobRejected=true;}}finally{if(otherJob!=IntPtr.Zero)CloseHandle(otherJob);}if(!wrongJobRejected)throw new SecurityException();
                    bool reopenRejected=false;try{CodeNetworkFence.BindAndInstall(expectedSid,options.relayPort,options.relayImage,job);}catch{reopenRejected=true;}if(!reopenRejected)throw new SecurityException();
                    bool rejected=false;try{CodeNetworkFence.RetireAfterJobExit(expectedSid,options.relayPort,options.relayImage,job);}catch(InvalidOperationException){rejected=true;}
                    if(!rejected)throw new SecurityException();
                    Emit("{\"event\":\"sealed\",\"filters\":8,\"retireWhileLiveRejected\":true,\"wrongJobRejected\":true,\"reopenRejected\":true}");Interlocked.CompareExchange(ref control,0,5);commandState=0;
                }
                if (commandState != 0) { reason = commandState == 1 ? "stdin-eof" : commandState == 2 ? "stop" : commandState == 3 ? "invalid-control" : "stdin-error"; break; }
                double elapsed = (Stopwatch.GetTimestamp() - Interlocked.Read(ref heartbeat)) * 1000.0 / Stopwatch.Frequency;
                if (elapsed > options.heartbeat) { reason = "heartbeat-timeout"; break; }
                long now = Stopwatch.GetTimestamp();
                if ((now - lastSnapshot) * 1000.0 / Stopwatch.Frequency >= 250) {
                    Snapshot(job, child.pid, (long)((now - started) * 1000.0 / Stopwatch.Frequency)); lastSnapshot = now;
                }
            }
            // Closing this non-inherited, anonymous job also kills descendants if
            // the main child already exited. No breakaway flags were granted.
            stage="SealBeforeKill";CodeNetworkFence.Apply(expectedSid,options.relayPort,options.relayImage,"Seal");
            stage="TerminateJob";Check(TerminateJobObject(job,1));Drain(job);
            stage="RetirePolicy";CodeNetworkFence.RetireAfterJobExit(expectedSid,options.relayPort,options.relayImage,job);retired=true;
            stage = "CloseJob"; Check(CloseHandle(job)); job = IntPtr.Zero;
            if (debugger != null && !debugger.Exited) {
                Stopwatch drain = Stopwatch.StartNew();
                while (!debugger.Exited && drain.ElapsedMilliseconds < 2000) debugger.Pump(50);
            }
            bool childExited = WaitForSingleObject(child.process, 2000) == 0;
            uint exitCode; Check(GetExitCodeProcess(child.process, out exitCode));
            Emit("{\"event\":\"stopped\",\"reason\":" + Json(reason) + ",\"exitCode\":" + exitCode + ",\"childExited\":" + (childExited ? "true" : "false") + ",\"jobClosed\":true}");
            GC.KeepAlive(input);
            return childExited ? 0 : 2;
        } finally {
            if(installed&&!retired&&expectedSid!=null){
                try{CodeNetworkFence.Apply(expectedSid,options.relayPort,options.relayImage,"Seal");if(job!=IntPtr.Zero){TerminateJobObject(job,1);Drain(job);CodeNetworkFence.RetireAfterJobExit(expectedSid,options.relayPort,options.relayImage,job);retired=true;}}catch{Emit("{\"event\":\"cleanup\",\"policyRetained\":true}");}
            }
            if(exempted&&expectedSid!=null){try{SetLoopback(expectedSid,false);}catch{Emit("{\"event\":\"cleanup\",\"loopbackRemovalFailed\":true}");}}
            if (!assigned && child.process != IntPtr.Zero) TerminateProcess(child.process, 1);
            if (token != IntPtr.Zero) CloseHandle(token);
            if (job != IntPtr.Zero) CloseHandle(job);
            if (child.thread != IntPtr.Zero) CloseHandle(child.thread);
            if (child.process != IntPtr.Zero) CloseHandle(child.process);
            if (attributesReady) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (capabilities != IntPtr.Zero) Marshal.FreeHGlobal(capabilities);
            if (lpacPolicy != IntPtr.Zero) Marshal.FreeHGlobal(lpacPolicy);
            if (sid != IntPtr.Zero) FreeSid(sid);
            if (debugger != null) debugger.Dispose();
        }
    }

    [StructLayout(LayoutKind.Sequential)] struct SidAttributes { public IntPtr sid;public uint attributes; }
    [DllImport("FirewallAPI.dll")] static extern uint NetworkIsolationGetAppContainerConfig(out uint count,out IntPtr sids);
    [DllImport("FirewallAPI.dll")] static extern uint NetworkIsolationSetAppContainerConfig(uint count,IntPtr sids);
    [DllImport("kernel32.dll")] static extern IntPtr GetProcessHeap();
    [DllImport("kernel32.dll")] static extern bool HeapFree(IntPtr heap,uint flags,IntPtr memory);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
    static void Drain(IntPtr job){IntPtr p=Marshal.AllocHGlobal(48);try{var timer=Stopwatch.StartNew();for(;;){uint returned;Check(QueryInformationJobObject(job,1,p,48,out returned));if(Marshal.ReadInt32(p,40)==0)return;if(timer.ElapsedMilliseconds>5000)throw new SecurityException();Thread.Sleep(20);}}finally{Marshal.FreeHGlobal(p);}}
    static void SetLoopback(string ownSid,bool enable){
        uint count=0;IntPtr current=IntPtr.Zero,buffer=IntPtr.Zero;var allocated=new List<IntPtr>();
        try{
            uint err=NetworkIsolationGetAppContainerConfig(out count,out current);if(err!=0)throw new Win32Exception((int)err);if(count>4096)throw new SecurityException();
            var list=new List<SidAttributes>();int size=Marshal.SizeOf(typeof(SidAttributes));bool existed=false;
            for(int i=0;i<count;i++){var entry=(SidAttributes)Marshal.PtrToStructure(IntPtr.Add(current,i*size),typeof(SidAttributes));if(SidString(entry.sid)==ownSid){existed=true;if(!enable)continue;}list.Add(entry);}
            if(enable&&!existed){var sid=new System.Security.Principal.SecurityIdentifier(ownSid);byte[] bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);IntPtr p=Marshal.AllocHGlobal(bytes.Length);allocated.Add(p);Marshal.Copy(bytes,0,p,bytes.Length);list.Add(new SidAttributes{sid=p});}
            buffer=Marshal.AllocHGlobal(Math.Max(1,size*list.Count));for(int i=0;i<list.Count;i++)Marshal.StructureToPtr(list[i],IntPtr.Add(buffer,i*size),false);
            err=NetworkIsolationSetAppContainerConfig((uint)list.Count,buffer);if(err!=0)throw new Win32Exception((int)err);
            uint verifyCount;IntPtr verify;err=NetworkIsolationGetAppContainerConfig(out verifyCount,out verify);if(err!=0)throw new Win32Exception((int)err);
            try{var expected=new HashSet<string>();foreach(var entry in list)expected.Add(SidString(entry.sid));var actual=new HashSet<string>();for(int i=0;i<verifyCount;i++)actual.Add(SidString(((SidAttributes)Marshal.PtrToStructure(IntPtr.Add(verify,i*size),typeof(SidAttributes))).sid));if(!expected.SetEquals(actual))throw new SecurityException();}
            finally{if(verify!=IntPtr.Zero){for(int i=0;i<verifyCount;i++)HeapFree(GetProcessHeap(),0,((SidAttributes)Marshal.PtrToStructure(IntPtr.Add(verify,i*size),typeof(SidAttributes))).sid);HeapFree(GetProcessHeap(),0,verify);}}
        }finally{foreach(var p in allocated)Marshal.FreeHGlobal(p);if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);if(current!=IntPtr.Zero){int size=Marshal.SizeOf(typeof(SidAttributes));for(int i=0;i<count;i++)HeapFree(GetProcessHeap(),0,((SidAttributes)Marshal.PtrToStructure(IntPtr.Add(current,i*size),typeof(SidAttributes))).sid);HeapFree(GetProcessHeap(),0,current);}}
    }


    static int ForeignOwnerProbe(string[] args){
        if(args.Length!=4||!Regex.IsMatch(args[1],"^gate-probe-[0-9a-f]{32}$"))throw new ArgumentException();
        int port=Int32.Parse(args[2]);IntPtr sid=IntPtr.Zero,job=IntPtr.Zero;
        try{
            CheckHR(DeriveAppContainerSidFromAppContainerName(args[1],out sid));job=CreateJobObject(IntPtr.Zero,null);Check(job!=IntPtr.Zero);
            EXTENDED_LIMIT limits=new EXTENDED_LIMIT();limits.basic.flags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;Check(SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(limits)));
            bool previousOwnerRejected=false,retireRejected=false,sealRejected=false,launchCleanupRejected=false;
            try{CodeNetworkFence.BindAndInstall(SidString(sid),port,args[3],job);}catch(InvalidOperationException error){previousOwnerRejected=error.Message=="code-package-previous-owner";}
            try{CodeNetworkFence.RetireAfterJobExit(SidString(sid),port,args[3],job);}catch(InvalidOperationException){retireRejected=true;}
            try{CodeNetworkFence.Apply(SidString(sid),port<65535?port+1:port-1,args[3],"Seal");}catch(InvalidOperationException){sealRejected=true;}
            var originalOutput=Console.Out;var captured=new StringWriter();try{
                Console.SetOut(captured);var rejected=new Options{name=args[1],relayPort=port,relayImage=args[3],directory=Path.GetDirectoryName(args[3]),target=args[3],childArguments=new[]{"--version"}};
                try{Launch(rejected);}catch(InvalidOperationException error){launchCleanupRejected=error.Message=="code-package-previous-owner";}
            }finally{Console.SetOut(originalOutput);captured.Dispose();}
            CodeNetworkFence.Apply(SidString(sid),port,args[3],"VerifySealed");

            Emit("{\"event\":\"foreign-owner\",\"previousOwnerRejected\":"+(previousOwnerRejected?"true":"false")+",\"retireRejected\":"+(retireRejected?"true":"false")+",\"sealRejected\":"+(sealRejected?"true":"false")+",\"launchCleanupRejected\":"+(launchCleanupRejected?"true":"false")+",\"originalPolicyVerified\":true}");return previousOwnerRejected&&retireRejected&&sealRejected&&launchCleanupRejected?0:2;
        }finally{if(job!=IntPtr.Zero)CloseHandle(job);if(sid!=IntPtr.Zero)FreeSid(sid);}
    }

    public static int Main(string[] args) {
        try {
            if (IntPtr.Size != 8) throw new PlatformNotSupportedException();
            if(args.Length>0&&args[0]=="foreign-owner-probe")return ForeignOwnerProbe(args);
            Options options = Parse(args);
            if (options.mode == "create") return Create(options);
            if (options.mode == "delete") return Delete(options);
            return Launch(options);
        } catch (Exception error) {
            // Never echo arguments, environment, paths, passwords, or raw OS messages.
            int native = error is Win32Exception ? ((Win32Exception)error).NativeErrorCode : 0;
            Emit("{\"event\":\"error\",\"stage\":" + Json(stage) + ",\"type\":" + Json(error.GetType().Name) + ",\"win32\":" + native + ",\"hresult\":" + error.HResult +
                ",\"tokenClass\":" + lastTokenClass + ",\"tokenLength\":" + lastTokenLength + ",\"tokenQueryError\":" + lastTokenError + "}");
            return 1;
        }
    }
}
