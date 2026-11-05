using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

// An owned Job Object kills the whole runtime tree on EOF, parent crash or helper exit.
// JOB_LIST assigns the child atomically inside CreateProcess. Suspension alone
// would leave an unowned child if this helper died before a later assignment.
internal static class GuardHost {
    // Windows SDK netioapi.h/ws2ipdef.h: SOCKADDR_INET is a 28-byte union.
    // These integer fields keep the structure blittable without overlapping
    // managed arrays. Address octets are copied in their native memory order.
    [StructLayout(LayoutKind.Sequential)] internal struct SOCKADDR_INET {
        public ushort family,port; public uint data0,data1,data2,data3,data4,scope;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct IP_ADDRESS_PREFIX {
        public SOCKADDR_INET prefix; public byte length;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct MIB_IPFORWARD_ROW2 {
        public ulong luid; public uint index; public IP_ADDRESS_PREFIX destination;
        public SOCKADDR_INET nextHop; public byte sitePrefixLength;
        public uint validLifetime,preferredLifetime,metric,protocol;
        public byte loopback,autoconfigure,publish,immortal; public uint age,origin;
    }
    [StructLayout(LayoutKind.Sequential)] struct MIB_IPFORWARD_TABLE2 {
        public uint count; public MIB_IPFORWARD_ROW2 first;
    }
    [DllImport("iphlpapi.dll")] static extern uint GetIpForwardTable2(ushort family,out IntPtr table);
    [DllImport("iphlpapi.dll")] static extern void FreeMibTable(IntPtr table);
    internal static void ValidateRouteLayout() {
        if (Marshal.SizeOf(typeof(SOCKADDR_INET)) != 28 || Marshal.SizeOf(typeof(IP_ADDRESS_PREFIX)) != 32 ||
            Marshal.SizeOf(typeof(MIB_IPFORWARD_ROW2)) != 104 || Marshal.OffsetOf(typeof(MIB_IPFORWARD_TABLE2),"first").ToInt32() != 8 ||
            Marshal.OffsetOf(typeof(MIB_IPFORWARD_ROW2),"destination").ToInt32() != 12 ||
            Marshal.OffsetOf(typeof(MIB_IPFORWARD_ROW2),"nextHop").ToInt32() != 44 ||
            Marshal.OffsetOf(typeof(MIB_IPFORWARD_ROW2),"metric").ToInt32() != 84)
            throw new InvalidOperationException("Unsupported route table layout.");
    }
    static IPAddress RouteAddress(SOCKADDR_INET value) {
        if (value.family == 2) return new IPAddress(BitConverter.GetBytes(value.data0));
        if (value.family != 23) throw new InvalidOperationException("Unsupported route address family.");
        var octets = new byte[16];
        Buffer.BlockCopy(BitConverter.GetBytes(value.data1),0,octets,0,4);
        Buffer.BlockCopy(BitConverter.GetBytes(value.data2),0,octets,4,4);
        Buffer.BlockCopy(BitConverter.GetBytes(value.data3),0,octets,8,4);
        Buffer.BlockCopy(BitConverter.GetBytes(value.data4),0,octets,12,4);
        // InterfaceIndex already identifies the IPv6 next-hop's zone, matching
        // Get-NetRoute's unscoped NextHop representation.
        return new IPAddress(octets);
    }
    internal static string RouteIdentity(MIB_IPFORWARD_ROW2 row) {
        if ((row.destination.prefix.family != 2 && row.destination.prefix.family != 23) ||
            row.nextHop.family != row.destination.prefix.family ||
            row.destination.length > (row.destination.prefix.family == 2 ? 32 : 128))
            throw new InvalidOperationException("Invalid route entry.");
        if (row.destination.length > 1) return null;
        string prefix = RouteAddress(row.destination.prefix).ToString() + "/" + row.destination.length.ToString(CultureInfo.InvariantCulture);
        if (prefix != "0.0.0.0/0" && prefix != "0.0.0.0/1" && prefix != "128.0.0.0/1" &&
            prefix != "::/0" && prefix != "::/1" && prefix != "8000::/1") return null;
        return row.index.ToString(CultureInfo.InvariantCulture) + "|" + RouteAddress(row.nextHop).ToString() + "|" +
            row.metric.ToString(CultureInfo.InvariantCulture) + "|" + prefix;
    }
    internal static string EncodeRouteSnapshot(List<string> routes) {
        routes.Sort(StringComparer.Ordinal);
        // Each identity consists only of numeric addresses and decimal fields;
        // none of its generated characters require JSON string escaping.
        return routes.Count == 0 ? "[]" : "[\"" + string.Join("\",\"",routes.ToArray()) + "\"]";
    }
    static string RouteFingerprint() {
        ValidateRouteLayout(); IntPtr table = IntPtr.Zero;
        try {
            uint status = GetIpForwardTable2(0,out table); // AF_UNSPEC includes IPv4 and IPv6.
            if (status != 0) throw new Win32Exception(unchecked((int)status));
            if (table == IntPtr.Zero) throw new InvalidOperationException("Missing route table.");
            uint count = unchecked((uint)Marshal.ReadInt32(table));
            if (count > 65536) throw new InvalidOperationException("Unexpected route table size.");
            var routes = new List<string>();
            for (uint index = 0; index < count; index++) {
                var row = (MIB_IPFORWARD_ROW2)Marshal.PtrToStructure(IntPtr.Add(table,checked(8 + (int)index * 104)),typeof(MIB_IPFORWARD_ROW2));
                string identity = RouteIdentity(row); if (identity != null) routes.Add(identity);
            }
            return EncodeRouteSnapshot(routes);
        } finally { if (table != IntPtr.Zero) FreeMibTable(table); }
    }
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
    [DllImport("kernel32.dll", EntryPoint="ResumeThread", SetLastError=true)] static extern uint NativeResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", EntryPoint="SuspendThread", SetLastError=true)] static extern uint NativeSuspendThread(IntPtr thread);
    [DllImport("kernel32.dll", EntryPoint="OpenThread", SetLastError=true)] static extern IntPtr NativeOpenThread(uint access,bool inherit,uint tid);
    [DllImport("kernel32.dll", EntryPoint="GetThreadTimes", SetLastError=true)] static extern bool NativeGetThreadTimes(IntPtr thread,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags,uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool Thread32First(IntPtr snapshot,ref THREADENTRY32 entry);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool Thread32Next(IntPtr snapshot,ref THREADENTRY32 entry);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr handle,uint code);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr handle,out uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int type,IntPtr info,int length,out int returned);
    [DllImport("kernel32.dll", EntryPoint="OpenProcess", SetLastError=true)] static extern IntPtr NativeOpenProcess(uint access,bool inherit,uint pid);
    static string nativeOperation = "";
    static uint ResumeThread(IntPtr thread) { nativeOperation = "ResumeThread"; return NativeResumeThread(thread); }
    static uint SuspendThread(IntPtr thread) { nativeOperation = "SuspendThread"; return NativeSuspendThread(thread); }
    static IntPtr OpenThread(uint access,bool inherit,uint tid) { nativeOperation = "OpenThread"; return NativeOpenThread(access,inherit,tid); }
    static bool GetThreadTimes(IntPtr thread,out long created,out long exited,out long kernel,out long user) {
        nativeOperation = "GetThreadTimes"; return NativeGetThreadTimes(thread,out created,out exited,out kernel,out user);
    }
    static IntPtr OpenProcess(uint access,bool inherit,uint pid) { nativeOperation = "OpenProcess"; return NativeOpenProcess(access,inherit,pid); }
    [StructLayout(LayoutKind.Sequential)] struct THREADENTRY32 {
        public uint dwSize,cntUsage,th32ThreadID,th32OwnerProcessID;
        public int tpBasePri,tpDeltaPri;
        public uint dwFlags;
    }
    struct ThreadIdentity : IEquatable<ThreadIdentity> {
        readonly uint pid,tid; readonly long created;
        public uint ProcessId { get { return pid; } }
        public uint ThreadId { get { return tid; } }
        public long Created { get { return created; } }
        public ThreadIdentity(uint process,uint thread,long start) { pid=process; tid=thread; created=start; }
        public bool Equals(ThreadIdentity other) { return pid==other.pid && tid==other.tid && created==other.created; }
        public override bool Equals(object other) { return other is ThreadIdentity && Equals((ThreadIdentity)other); }
        public override int GetHashCode() { unchecked { return (((int)pid*397)^(int)tid)*397^created.GetHashCode(); } }
    }
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
    static uint[] JobProcessIds(IntPtr job) {
        int capacity = 16;
        for (int attempt = 0; attempt < 8; attempt++) {
            if (capacity < 1 || capacity > 4096) throw new InvalidOperationException("Too many processes in the owned job.");
            int size = checked(8 + capacity * IntPtr.Size);
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try {
                int returned;
                bool ok = QueryInformationJobObject(job,3,buffer,size,out returned);
                int error = Marshal.GetLastWin32Error();
                if (!ok && error != 234) throw new Win32Exception(error);
                uint assigned = unchecked((uint)Marshal.ReadInt32(buffer));
                uint listed = unchecked((uint)Marshal.ReadInt32(buffer,4));
                if (assigned > 4096 || listed > 4096) throw new InvalidOperationException("Too many processes in the owned job.");
                if (!ok || assigned > listed) { capacity = checked(Math.Max(capacity * 2,(int)assigned + 8)); continue; }
                if (returned < 8 || returned > size) throw new InvalidOperationException("Invalid job process list.");
                var ids = new uint[listed]; int offset = 8;
                for (int index = 0; index < ids.Length; index++,offset += IntPtr.Size)
                    ids[index] = IntPtr.Size == 8 ? unchecked((uint)Marshal.ReadInt64(buffer,offset)) : unchecked((uint)Marshal.ReadInt32(buffer,offset));
                return ids;
            } finally { Marshal.FreeHGlobal(buffer); }
        }
        throw new InvalidOperationException("The job process list did not stabilize.");
    }
    static void VerifyProcessMembership(IntPtr job,uint pid) {
        IntPtr process = OpenProcess(0x0800|0x1000,false,pid); Check(process != IntPtr.Zero);
        try {
            nativeOperation = "IsProcessInJob";
            bool inJob; Check(IsProcessInJob(process,job,out inJob));
            if (!inJob) throw new InvalidOperationException("A process left the owned job.");
        } finally { CloseHandle(process); }
    }
    static bool TryThreadIdentity(uint pid,uint tid,out ThreadIdentity identity) {
        identity = default(ThreadIdentity);
        IntPtr thread = OpenThread(0x0002|0x0800,false,tid);
        if (thread == IntPtr.Zero) {
            int error = Marshal.GetLastWin32Error(); if (error == 87) return false; throw new Win32Exception(error);
        }
        long created,exited,kernel,user;
        bool ok = GetThreadTimes(thread,out created,out exited,out kernel,out user);
        int readError = Marshal.GetLastWin32Error(); CloseHandle(thread);
        if (!ok) { if (readError == 87) return false; throw new Win32Exception(readError); }
        identity = new ThreadIdentity(pid,tid,created); return true;
    }
    static IntPtr OpenVerifiedThread(ThreadIdentity identity) {
        IntPtr thread = OpenThread(0x0002|0x0800,false,identity.ThreadId);
        if (thread == IntPtr.Zero) {
            int error = Marshal.GetLastWin32Error(); if (error == 87) return IntPtr.Zero; throw new Win32Exception(error);
        }
        long created,exited,kernel,user;
        bool ok = GetThreadTimes(thread,out created,out exited,out kernel,out user);
        int readError = Marshal.GetLastWin32Error();
        if (!ok) { CloseHandle(thread); if (readError == 87) return IntPtr.Zero; throw new Win32Exception(readError); }
        if (created != identity.Created) { CloseHandle(thread); return IntPtr.Zero; }
        return thread;
    }
    static void ResumeThreadIdentity(ThreadIdentity identity) {
        IntPtr thread = OpenVerifiedThread(identity); if (thread == IntPtr.Zero) return;
        try {
            if (ResumeThread(thread) == 0xffffffff) {
                int error = Marshal.GetLastWin32Error(); if (error != 87) throw new Win32Exception(error);
            }
        } finally { CloseHandle(thread); }
    }
    static void SuspendNewThread(uint pid,uint tid,HashSet<ThreadIdentity> threads,List<ThreadIdentity> added) {
        ThreadIdentity identity; if (!TryThreadIdentity(pid,tid,out identity) || threads.Contains(identity)) return;
        IntPtr thread = OpenVerifiedThread(identity); if (thread == IntPtr.Zero) return;
        try {
            uint previous = SuspendThread(thread);
            if (previous == 0xffffffff) {
                int error = Marshal.GetLastWin32Error(); if (error == 87) return; throw new Win32Exception(error);
            }
            if (previous != 0) {
                ResumeThread(thread);
                throw new InvalidOperationException("A thread was already suspended by another owner.");
            }
            threads.Add(identity); added.Add(identity);
        } finally { CloseHandle(thread); }
    }
    static void FreezeProcessThreads(uint pid,HashSet<ThreadIdentity> threads,List<ThreadIdentity> added) {
        bool stable = false,sawThread = false;
        for (int pass = 0; pass < 8 && !stable; pass++) {
            int before = threads.Count;
            nativeOperation = "ThreadSnapshot";
            IntPtr snapshot = CreateToolhelp32Snapshot(0x4,0);
            if (snapshot == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                var entry = new THREADENTRY32(); entry.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));
                Check(Thread32First(snapshot,ref entry));
                do {
                    if (entry.th32OwnerProcessID != pid) continue;
                    sawThread = true; SuspendNewThread(pid,entry.th32ThreadID,threads,added);
                    entry.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));
                } while (Thread32Next(snapshot,ref entry));
                int enumerationError = Marshal.GetLastWin32Error();
                if (enumerationError != 18) throw new Win32Exception(enumerationError);
            } finally { CloseHandle(snapshot); }
            stable = threads.Count == before;
        }
        if (!sawThread) throw new InvalidOperationException("An owned process has no threads to freeze.");
        if (!stable) throw new InvalidOperationException("The process thread list did not stabilize.");
    }
    static int FreezeProcesses(IntPtr job,HashSet<uint> frozen,HashSet<ThreadIdentity> threads) {
        var added = new List<ThreadIdentity>();
        try {
            bool stable = false;
            for (int pass = 0; pass < 8 && !stable; pass++) {
                int beforeProcesses = frozen.Count,beforeThreads = threads.Count;
                foreach (uint pid in JobProcessIds(job)) {
                    VerifyProcessMembership(job,pid);
                    FreezeProcessThreads(pid,threads,added);
                    frozen.Add(pid);
                }
                stable = frozen.Count == beforeProcesses && threads.Count == beforeThreads;
            }
            if (frozen.Count == 0 || threads.Count == 0) throw new InvalidOperationException("The owned job has no processes to freeze.");
            if (!stable) throw new InvalidOperationException("The job process tree did not stabilize.");
            return frozen.Count;
        } catch {
            foreach (var identity in added) { try { ResumeThreadIdentity(identity); } catch {} threads.Remove(identity); }
            throw;
        }
    }
    static int ThawProcesses(IntPtr job,HashSet<uint> frozen,HashSet<ThreadIdentity> threads) {
        if (frozen.Count == 0) return 0;
        var identities = new ThreadIdentity[threads.Count]; threads.CopyTo(identities);
        foreach (var identity in identities) { ResumeThreadIdentity(identity); threads.Remove(identity); }
        int resumed = frozen.Count; frozen.Clear(); return resumed;
    }
    static void ProcessAck(string command,int id,bool ok,int count,string error = null) {
        Console.WriteLine("{\"" + command + "Ack\":" + id.ToString(CultureInfo.InvariantCulture) +
            ",\"ok\":" + (ok ? "true" : "false") + ",\"count\":" + count.ToString(CultureInfo.InvariantCulture) +
            (error == null ? "" : ",\"error\":\"" + error + "\"") + "}");
        Console.Out.Flush();
    }
    public static int Main(string[] args) {
        if (args.Length > 0 && args[0] == "--route-fingerprint") {
            if (args.Length != 1) return 64;
            try { Console.OutputEncoding = new UTF8Encoding(false); Console.WriteLine(RouteFingerprint()); return 0; }
            catch (Exception error) { Console.Error.WriteLine("GuardHost routes: " + error.GetType().Name); return 1; }
        }
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
            var frozen = new HashSet<uint>();
            var frozenThreads = new HashSet<ThreadIdentity>();
            Task eof = Task.Factory.StartNew(() => {
                string line;
                while ((line = Console.In.ReadLine()) != null) {
                    if (line == "ping") { Interlocked.Exchange(ref lastHeartbeat,Stopwatch.GetTimestamp()); continue; }
                    string[] parts = line.Split(' ');
                    if (parts.Length != 2 || (parts[0] != "freeze" && parts[0] != "thaw")) return;
                    int id;
                    if (!int.TryParse(parts[1],NumberStyles.None,CultureInfo.InvariantCulture,out id) || id <= 0) return;
                    Interlocked.Exchange(ref lastHeartbeat,Stopwatch.GetTimestamp());
                    try {
                        int count = parts[0] == "freeze" ? FreezeProcesses(job,frozen,frozenThreads) : ThawProcesses(job,frozen,frozenThreads);
                        ProcessAck(parts[0],id,true,count);
                    } catch (Exception error) {
                        int errorCode = error is Win32Exception ? ((Win32Exception)error).NativeErrorCode : 0;
                        ProcessAck(parts[0],id,false,frozen.Count,error.GetType().Name + ":" + errorCode.ToString(CultureInfo.InvariantCulture) + ":" + nativeOperation);
                    }
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
