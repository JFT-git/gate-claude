using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

// An owned Job Object kills the whole runtime tree on EOF, parent crash or helper exit.
// JOB_LIST assigns the child atomically inside CreateProcess. Suspension alone
// would leave an unowned child if this helper died before a later assignment.
internal static class GuardHost {
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct STARTUPINFO {
        public int cb; public string reserved, desktop, title;
        public int x,y,xSize,ySize,xCount,yCount,fill,flags; public short show,reserved2;
        public IntPtr reservedPtr,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] struct STARTUPINFOEX { public STARTUPINFO startup; public IntPtr attributes; }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr process,thread; public int pid,tid; }
    [StructLayout(LayoutKind.Sequential)] struct BASIC_LIMIT {
        public long processTime,jobTime; public uint flags;
        public UIntPtr minWorking,maxWorking; public uint activeProcesses;
        public UIntPtr affinity; public uint priority,scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct IO_COUNTERS { public ulong readOps,writeOps,otherOps,readBytes,writeBytes,otherBytes; }
    [StructLayout(LayoutKind.Sequential)] struct EXTENDED_LIMIT {
        public BASIC_LIMIT basic; public IO_COUNTERS io;
        public UIntPtr processMemory,jobMemory,peakProcessMemory,peakJobMemory;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int type,ref EXTENDED_LIMIT info,int length);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr attributes,uint count,uint flags,ref UIntPtr size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr attributes,uint flags,IntPtr key,IntPtr value,UIntPtr size,IntPtr previous,IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr attributes);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool result);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcess(string executable,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string directory,ref STARTUPINFOEX startup,out PROCESS_INFORMATION info);
    [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr handle,uint code);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr handle,out uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    static string Quote(string value) {
        var output = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value) {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { output.Append('\\', slashes*2+1); output.Append(c); }
            else { output.Append('\\', slashes); output.Append(c); }
            slashes = 0;
        }
        output.Append('\\',slashes*2); output.Append('"'); return output.ToString();
    }
    static void Check(bool value) { if (!value) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    public static int Main(string[] args) {
        if (args.Length < 1 || !System.IO.Path.IsPathRooted(args[0])) return 64;
        IntPtr job = IntPtr.Zero, attributes = IntPtr.Zero, jobList = IntPtr.Zero;
        PROCESS_INFORMATION child = new PROCESS_INFORMATION();
        bool verified = false, attributesInitialized = false;
        try {
            job = CreateJobObject(IntPtr.Zero,null); Check(job != IntPtr.Zero);
            var limits = new EXTENDED_LIMIT(); limits.basic.flags = 0x2000; // KILL_ON_JOB_CLOSE
            Check(SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(limits)));
            UIntPtr attributeSize = UIntPtr.Zero;
            bool sized = InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref attributeSize);
            int sizeError = Marshal.GetLastWin32Error();
            if (sized || sizeError != 122 || attributeSize == UIntPtr.Zero) throw new Win32Exception(sizeError);
            attributes = Marshal.AllocHGlobal(checked((int)attributeSize.ToUInt64()));
            Check(InitializeProcThreadAttributeList(attributes,1,0,ref attributeSize)); attributesInitialized = true;
            jobList = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobList,job);
            // PROC_THREAD_ATTRIBUTE_JOB_LIST: INPUT (0x20000) | JobList (13).
            // Neither this handle nor any other helper handle is inherited.
            Check(UpdateProcThreadAttribute(attributes,0,new IntPtr(0x2000D),jobList,new UIntPtr((uint)IntPtr.Size),IntPtr.Zero,IntPtr.Zero));
            var command = new StringBuilder(); foreach (var arg in args) { if (command.Length > 0) command.Append(' '); command.Append(Quote(arg)); }
            var startup = new STARTUPINFOEX(); startup.startup.cb = Marshal.SizeOf(startup); startup.attributes = attributes;
            // CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT.
            // Unsupported/failed atomic job assignment aborts; there is no fallback.
            Check(CreateProcess(args[0],command,IntPtr.Zero,IntPtr.Zero,false,0x4|0x400|0x80000,IntPtr.Zero,System.IO.Path.GetDirectoryName(args[0]),ref startup,out child));
            bool inOwnJob; Check(IsProcessInJob(child.process,job,out inOwnJob));
            if (!inOwnJob) throw new InvalidOperationException("The process was not created in its owned job.");
            verified = true;
            if (ResumeThread(child.thread) == 0xffffffff) throw new Win32Exception(Marshal.GetLastWin32Error());
            Console.WriteLine("{\"pid\":" + child.pid + "}"); Console.Out.Flush();
            long lastHeartbeat = Stopwatch.GetTimestamp();
            Task eof = Task.Factory.StartNew(() => {
                string line;
                while ((line = Console.In.ReadLine()) != null) {
                    if (line != "ping") return;
                    Interlocked.Exchange(ref lastHeartbeat,Stopwatch.GetTimestamp());
                }
            });
            while (!eof.Wait(50) && WaitForSingleObject(child.process,0) == 258) {
                double elapsed = (Stopwatch.GetTimestamp()-Interlocked.Read(ref lastHeartbeat))*1000.0/Stopwatch.Frequency;
                if (elapsed > 5000) break;
            }
            uint code; GetExitCodeProcess(child.process,out code);
            if (code != 259) { Console.WriteLine("{\"exitCode\":" + code + "}"); Console.Out.Flush(); }
            return 0;
        } catch (Exception error) {
            // No arguments, environment or account data are written to diagnostics.
            Console.Error.WriteLine("GuardHost: " + error.GetType().Name + " (" + Marshal.GetLastWin32Error() + ")");
            return 1;
        } finally {
            if (!verified && child.process != IntPtr.Zero) TerminateProcess(child.process,1);
            if (child.thread != IntPtr.Zero) CloseHandle(child.thread);
            if (child.process != IntPtr.Zero) CloseHandle(child.process);
            if (attributesInitialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (jobList != IntPtr.Zero) Marshal.FreeHGlobal(jobList);
            if (job != IntPtr.Zero) CloseHandle(job);
        }
    }
}
