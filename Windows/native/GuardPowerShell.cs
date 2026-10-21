// Private portable PowerShell entry point. The child inherits its caller's token,
// environment, standard handles and jobs; the configuration only sets a PSDrive.
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

internal static class GuardPowerShell {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct StartupInfo {
        public int size; public string reserved, desktop, title;
        public int x, y, width, height, xChars, yChars, fill, flags;
        public short show, reservedSize; public IntPtr reservedData, input, output, error;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupInfoEx { public StartupInfo startup; public IntPtr attributes; }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr process, thread; public uint pid, tid; }
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int which);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr source, IntPtr targetProcess, out IntPtr target, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool InitializeProcThreadAttributeList(IntPtr list, uint count, uint flags, ref UIntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr key, IntPtr value, UIntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateProcess(string executable, StringBuilder command, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInfo process);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    static void Check(bool value) { if (!value) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); }
    static IntPtr CopyStandardHandle(int which) {
        IntPtr source = GetStdHandle(which), copy;
        if (source == IntPtr.Zero || source == new IntPtr(-1)) throw new InvalidOperationException();
        Check(DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), out copy, 0, true, 2));
        return copy;
    }
    [StructLayout(LayoutKind.Sequential)] struct BasicLimit { public long processTime, jobTime; public uint flags; public UIntPtr minimum, maximum; public uint active; public UIntPtr affinity; public uint priority, scheduling; }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong readOps, writeOps, otherOps, readBytes, writeBytes, otherBytes; }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimit { public BasicLimit basic; public IoCounters io; public UIntPtr processMemory, jobMemory, peakProcessMemory, peakJobMemory; }
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateJobObject(IntPtr security, string name);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr job, int type, ref ExtendedLimit value, int size);
    static string Quote(string value) {
        var text = new StringBuilder("\"");
        int slashes = 0;
        foreach (char character in value) {
            if (character == '\\') { slashes++; continue; }
            if (character == '"') text.Append('\\', slashes * 2 + 1).Append(character);
            else text.Append('\\', slashes).Append(character);
            slashes = 0;
        }
        return text.Append('\\', slashes * 2).Append('"').ToString();
    }

    public static int Main(string[] args) {
        IntPtr attributes = IntPtr.Zero, handles = IntPtr.Zero, job = IntPtr.Zero, jobs = IntPtr.Zero;
        var standard = new IntPtr[3]; bool initialized = false;
        ProcessInfo child = new ProcessInfo();
        try {
            string root = AppDomain.CurrentDomain.BaseDirectory;
            string engine = Path.Combine(root, "GuardPwsh.exe");
            string configuration = Path.Combine(root, "Guard.PowerShell.pssc");
            if (!File.Exists(engine) || !File.Exists(configuration) || !File.Exists(Path.Combine(root, "Guard.PowerShell.ps1"))) return 125;
            var arguments = new StringBuilder("-ConfigurationFile ").Append(Quote(configuration));
            foreach (string argument in args) arguments.Append(' ').Append(Quote(argument));
            if (arguments.Length > 32766) return 125;
            job = CreateJobObject(IntPtr.Zero, null); Check(job != IntPtr.Zero);
            var limit = new ExtendedLimit(); limit.basic.flags = 0x2000;
            Check(SetInformationJobObject(job, 9, ref limit, Marshal.SizeOf(limit)));
            for (int i = 0; i < standard.Length; i++) standard[i] = CopyStandardHandle(-10 - i);
            UIntPtr size = UIntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
            if (size == UIntPtr.Zero || size.ToUInt64() > 1048576) throw new InvalidOperationException();
            attributes = Marshal.AllocHGlobal((int)size.ToUInt64());
            Check(InitializeProcThreadAttributeList(attributes, 2, 0, ref size)); initialized = true;
            handles = Marshal.AllocHGlobal(IntPtr.Size * standard.Length);
            for (int i = 0; i < standard.Length; i++) Marshal.WriteIntPtr(handles, IntPtr.Size * i, standard[i]);
            Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), handles, new UIntPtr((uint)(IntPtr.Size * standard.Length)), IntPtr.Zero, IntPtr.Zero));
            jobs = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobs, job);
            Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x2000d), jobs, new UIntPtr((uint)IntPtr.Size), IntPtr.Zero, IntPtr.Zero));
            var startup = new StartupInfoEx(); startup.startup.size = Marshal.SizeOf(startup);
            startup.startup.flags = 0x100; startup.startup.input = standard[0]; startup.startup.output = standard[1]; startup.startup.error = standard[2]; startup.attributes = attributes;
            var command = new StringBuilder(Quote(engine)).Append(' ').Append(arguments);
            if (command.Length > 32766) return 125;
            // Inherit the caller's environment/token/jobs and exactly its three standard handles.
            Check(CreateProcess(engine, command, IntPtr.Zero, IntPtr.Zero, true, 0x80000 | 0x08000000, IntPtr.Zero, Environment.CurrentDirectory, ref startup, out child));
            Check(WaitForSingleObject(child.process, 0xffffffff) == 0);
            uint exit; Check(GetExitCodeProcess(child.process, out exit));
            // A completed shell may leave intentional background work. The inherited
            // CodeHost/session jobs still contain it; cancellation keeps this inner kill.
            limit.basic.flags = 0;
            Check(SetInformationJobObject(job, 9, ref limit, Marshal.SizeOf(limit)));
            return unchecked((int)exit);
        } catch {
            Console.Error.WriteLine("Guard PowerShell could not start.");
            return 125;
        } finally {
            if (job != IntPtr.Zero) CloseHandle(job);
            if (child.thread != IntPtr.Zero) CloseHandle(child.thread);
            if (child.process != IntPtr.Zero) CloseHandle(child.process);
            if (initialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (jobs != IntPtr.Zero) Marshal.FreeHGlobal(jobs);
            if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
            foreach (IntPtr handle in standard) if (handle != IntPtr.Zero) CloseHandle(handle);
        }
    }
}
