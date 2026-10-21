using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32.SafeHandles;

// Optional package/job lifecycle owned solely by the elevated WFP broker.
// Dispose is an abort path: it never retires a package policy.
internal sealed class CodeFenceSession : IDisposable {
    const string LoopbackMutex = @"Global\gate-code-loopback-config-v1";
    const string Privileged = "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)";
    const uint ControllerRights=0x100005, KillOnClose=0x2000;
    IntPtr job=IntPtr.Zero,controller=IntPtr.Zero;
    FileStream controllerImage;
    string sid,image; int port;
    bool policyAttempted,exemptionOwned,retired,disposed;
    public string Sid { get { return sid; } }
    public string JobName { get; private set; }
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int length; public IntPtr descriptor; public int inherit; }
    [StructLayout(LayoutKind.Sequential)] struct BasicLimit {
        public long processTime,jobTime; public uint flags; public UIntPtr minWorking,maxWorking;
        public uint activeLimit; public UIntPtr affinity; public uint priority,scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct Counters { public ulong readOps,writeOps,otherOps,readBytes,writeBytes,otherBytes; }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimit {
        public BasicLimit basic; public Counters io; public UIntPtr processMemory,jobMemory,peakProcessMemory,peakJobMemory;
    }
    [StructLayout(LayoutKind.Sequential)] struct Accounting { public long user,kernel,periodUser,periodKernel; public uint faults,total,active,terminated; }
    [StructLayout(LayoutKind.Sequential)] struct SidAttributes { public IntPtr sid; public uint attributes; }
    sealed class LoopbackEntry { public string sid; public uint attributes; }
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr process,uint flags,StringBuilder file,ref uint size);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int type,IntPtr buffer,uint length,out uint needed);
    [DllImport("advapi32.dll")] static extern bool IsValidSid(IntPtr sid);
    [DllImport("advapi32.dll")] static extern uint GetLengthSid(IntPtr sid);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int DeriveAppContainerSidFromAppContainerName(string name,out IntPtr sid);
    [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint bytes);
    [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle,uint type,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(ref SecurityAttributes security,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int type,ref ExtendedLimit limits,int size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int type,out Accounting accounting,int length,out uint returned);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int type,IntPtr information,int length,out uint returned);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetHandleInformation(IntPtr handle,out uint flags);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateMutex(ref SecurityAttributes security,bool initialOwner,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReleaseMutex(IntPtr handle);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("kernel32.dll")] static extern IntPtr GetProcessHeap();
    [DllImport("kernel32.dll")] static extern bool HeapFree(IntPtr heap,uint flags,IntPtr memory);
    [DllImport("FirewallAPI.dll")] static extern uint NetworkIsolationGetAppContainerConfig(out uint count,out IntPtr entries);
    [DllImport("FirewallAPI.dll")] static extern uint NetworkIsolationSetAppContainerConfig(uint count,IntPtr entries);
    static void Check(bool value) { if(!value)throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static void Status(uint value) { if(value!=0)throw new Win32Exception(unchecked((int)value)); }
    static string CanonicalImage(string path) {
        if(String.IsNullOrEmpty(path)||path.Length>1024||!Regex.IsMatch(path,@"^[A-Za-z]:\\")||
            path.IndexOf(':',2)>=0||path.IndexOfAny(new[]{'\0','\r','\n','\t','"','*','?'})>=0||
            !String.Equals(Path.GetExtension(path),".exe",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("code-relay-image");
        string full=Path.GetFullPath(path);
        if(!String.Equals(path,full,StringComparison.OrdinalIgnoreCase)||!File.Exists(full))throw new InvalidDataException("code-relay-image");
        string cursor=full;
        while(cursor!=null&&cursor.Length>3){if((File.GetAttributes(cursor)&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("code-relay-link");cursor=Path.GetDirectoryName(cursor);}
        return full;
    }
    static string SidText(IntPtr pointer) {
        if(pointer==IntPtr.Zero||!IsValidSid(pointer)||GetLengthSid(pointer)>192)throw new InvalidDataException("code-native-sid");
        return new SecurityIdentifier(pointer).Value;
    }
    static IntPtr Descriptor(string text) {
        IntPtr result;uint size;Check(ConvertStringSecurityDescriptorToSecurityDescriptor(text,1,out result,out size));return result;
    }
    static RawSecurityDescriptor Security(IntPtr handle,bool label) {
        IntPtr descriptor=IntPtr.Zero,owner,group,dacl,sacl;
        try {
            Status(GetSecurityInfo(handle,6,label?0x15u:5u,out owner,out group,out dacl,out sacl,out descriptor));
            uint size=GetSecurityDescriptorLength(descriptor);if(size==0||size>65536)throw new InvalidDataException("code-kernel-security");
            byte[] bytes=new byte[size];Marshal.Copy(descriptor,bytes,0,bytes.Length);return new RawSecurityDescriptor(bytes,0);
        } finally { if(descriptor!=IntPtr.Zero)LocalFree(descriptor); }
    }
    static void VerifyAcl(IntPtr handle,string user,bool label) {
        var security=Security(handle,label);var ba=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);var sy=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
        bool includeUser=user!=null&&user!=ba.Value&&user!=sy.Value;
        if(!ba.Equals(security.Owner)||(security.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0||
            security.DiscretionaryAcl==null||security.DiscretionaryAcl.Count!=(includeUser?3:2))throw new InvalidDataException("code-kernel-security");
        bool hasBa=false,hasSy=false,hasUser=!includeUser;
        foreach(GenericAce item in security.DiscretionaryAcl) {
            var ace=item as CommonAce;
            if(ace==null||ace.IsCallback||ace.AceQualifier!=AceQualifier.AccessAllowed||ace.AceFlags!=AceFlags.None)throw new InvalidDataException("code-kernel-security");
            if(ba.Equals(ace.SecurityIdentifier)){if(hasBa)throw new InvalidDataException();hasBa=true;}
            else if(sy.Equals(ace.SecurityIdentifier)){if(hasSy)throw new InvalidDataException();hasSy=true;}
            else if(includeUser&&ace.SecurityIdentifier.Value==user){if(hasUser||ace.AccessMask!=(int)ControllerRights)throw new InvalidDataException();hasUser=true;continue;}
            else throw new InvalidDataException("code-kernel-security");
            // Kernel object managers can map GENERIC_ALL while storing the DACL.
            int mask=ace.AccessMask;
            if(mask!=0x10000000&&mask!=(label?0x1f003f:0x1f0001)&&!(label&&mask==0x1f001f))throw new InvalidDataException("code-kernel-security");
        }
        if(!hasBa||!hasSy||!hasUser)throw new InvalidDataException("code-kernel-security");
        if(label) {
            if(security.SystemAcl==null||security.SystemAcl.Count!=1)throw new InvalidDataException("code-job-label");
            GenericAce ace=security.SystemAcl[0];byte[] data=new byte[ace.BinaryLength];ace.GetBinaryForm(data,0);
            if(data.Length!=20||data[0]!=17||data[1]!=0||BitConverter.ToUInt32(data,4)!=1||new SecurityIdentifier(data,8).Value!="S-1-16-8192")throw new InvalidDataException("code-job-label");
        }
    }
    string AuthenticateController(NamedPipeClientStream pipe,string trustedImage) {
        image=CanonicalImage(trustedImage);uint pid;Check(GetNamedPipeServerProcessId(pipe.SafePipeHandle,out pid));
        if(pid==0)throw new InvalidDataException("code-controller");
        controller=OpenProcess(0x101000,false,pid);Check(controller!=IntPtr.Zero);
        var name=new StringBuilder(32768);uint size=(uint)name.Capacity;Check(QueryFullProcessImageName(controller,0,name,ref size));
        if(!String.Equals(CanonicalImage(name.ToString()),image,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("code-controller-image");
        controllerImage=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read);
        IntPtr token=IntPtr.Zero,information=IntPtr.Zero;
        try {
            Check(OpenProcessToken(controller,8,out token));uint needed;GetTokenInformation(token,1,IntPtr.Zero,0,out needed);
            if(needed<16||needed>65536)throw new InvalidDataException("code-controller-token");
            information=Marshal.AllocHGlobal((int)needed);Check(GetTokenInformation(token,1,information,needed,out needed));
            string user=SidText(Marshal.ReadIntPtr(information));
            uint repeated;Check(GetNamedPipeServerProcessId(pipe.SafePipeHandle,out repeated));
            if(repeated!=pid||WaitForSingleObject(controller,0)!=258)throw new InvalidDataException("code-controller-exited");
            return user;
        } finally { if(information!=IntPtr.Zero)Marshal.FreeHGlobal(information);if(token!=IntPtr.Zero)CloseHandle(token); }
    }
    void CreateOwnedJob(string name,string user) {
        JobName=name;
        string extra=(user=="S-1-5-18"||user=="S-1-5-32-544")?"":"(A;;0x100005;;;"+user+")";
        IntPtr descriptor=Descriptor(Privileged+extra+"S:(ML;;NW;;;ME)");
        try {
            var security=new SecurityAttributes{length=Marshal.SizeOf(typeof(SecurityAttributes)),descriptor=descriptor,inherit=0};
            job=CreateJobObject(ref security,name);int error=Marshal.GetLastWin32Error();Check(job!=IntPtr.Zero);
            if(error==183){CloseHandle(job);job=IntPtr.Zero;throw new InvalidOperationException("code-job-already-exists");}
            var limits=new ExtendedLimit();limits.basic.flags=KillOnClose;Check(SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(limits)));
            uint flags;Check(GetHandleInformation(job,out flags));if((flags&1)!=0)throw new InvalidDataException("code-job-inheritable");
            VerifyAcl(job,user,true);
            IntPtr buffer=Marshal.AllocHGlobal(64);
            try { uint returned;Check(QueryInformationJobObject(job,2,buffer,64,out returned));if(returned!=64||unchecked((uint)Marshal.ReadInt32(buffer,16))!=KillOnClose)throw new InvalidDataException("code-job-limits"); }
            finally { Marshal.FreeHGlobal(buffer); }
        } finally { LocalFree(descriptor); }
    }
    static List<LoopbackEntry> ReadLoopback() {
        uint count;IntPtr current;uint status=NetworkIsolationGetAppContainerConfig(out count,out current);
        try {
            Status(status);if(count>4096||(count!=0&&current==IntPtr.Zero))throw new InvalidDataException("code-loopback-size");
            var result=new List<LoopbackEntry>();var seen=new HashSet<string>(StringComparer.Ordinal);int size=Marshal.SizeOf(typeof(SidAttributes));
            for(int i=0;i<count;i++){var entry=(SidAttributes)Marshal.PtrToStructure(IntPtr.Add(current,i*size),typeof(SidAttributes));string value=SidText(entry.sid);if(!seen.Add(value))throw new InvalidDataException("code-loopback-duplicate");result.Add(new LoopbackEntry{sid=value,attributes=entry.attributes});}
            return result;
        } finally {
            // This allocator is specified by NetworkIsolationGetAppContainerConfig,
            // including separately allocated SIDs, not only the outer array.
            if(current!=IntPtr.Zero){int size=Marshal.SizeOf(typeof(SidAttributes));for(uint i=0;i<count;i++){IntPtr value=Marshal.ReadIntPtr(IntPtr.Add(current,checked((int)i*size)));if(value!=IntPtr.Zero)HeapFree(GetProcessHeap(),0,value);}HeapFree(GetProcessHeap(),0,current);}
        }
    }
    static bool SameEntries(List<LoopbackEntry> expected,List<LoopbackEntry> actual) {
        if(expected.Count!=actual.Count)return false;var map=new Dictionary<string,uint>(StringComparer.Ordinal);
        foreach(var item in expected)map.Add(item.sid,item.attributes);
        foreach(var item in actual){uint value;if(!map.TryGetValue(item.sid,out value)||value!=item.attributes)return false;}return true;
    }
    void ChangeLoopback(bool add) {
        IntPtr descriptor=Descriptor(Privileged),mutex=IntPtr.Zero,entries=IntPtr.Zero;bool locked=false;var allocated=new List<IntPtr>();
        try {
            var security=new SecurityAttributes{length=Marshal.SizeOf(typeof(SecurityAttributes)),descriptor=descriptor,inherit=0};
            mutex=CreateMutex(ref security,false,LoopbackMutex);Check(mutex!=IntPtr.Zero);VerifyAcl(mutex,null,false);
            uint wait=WaitForSingleObject(mutex,10000);if(wait!=0&&wait!=0x80)throw new TimeoutException("code-loopback-lock");locked=true;
            var current=ReadLoopback();var expected=new List<LoopbackEntry>();bool present=false;
            foreach(var item in current){if(item.sid==sid){present=true;if(!add)continue;}expected.Add(item);}
            if(add&&present)throw new InvalidOperationException("code-loopback-previous-owner");
            if(add)expected.Add(new LoopbackEntry{sid=sid});
            if(!add&&!present){exemptionOwned=false;return;}
            int size=Marshal.SizeOf(typeof(SidAttributes));entries=Marshal.AllocHGlobal(Math.Max(1,size*expected.Count));
            for(int i=0;i<expected.Count;i++){
                var item=expected[i];var identity=new SecurityIdentifier(item.sid);byte[] bytes=new byte[identity.BinaryLength];identity.GetBinaryForm(bytes,0);
                IntPtr value=Marshal.AllocHGlobal(bytes.Length);allocated.Add(value);Marshal.Copy(bytes,0,value,bytes.Length);
                Marshal.StructureToPtr(new SidAttributes{sid=value,attributes=item.attributes},IntPtr.Add(entries,i*size),false);
            }
            Status(NetworkIsolationSetAppContainerConfig((uint)expected.Count,entries));
            if(add)exemptionOwned=true; // Set may have succeeded even if its readback fails.
            if(!SameEntries(expected,ReadLoopback()))throw new InvalidDataException("code-loopback-readback");
            if(!add)exemptionOwned=false;
        } finally {
            foreach(IntPtr value in allocated)Marshal.FreeHGlobal(value);if(entries!=IntPtr.Zero)Marshal.FreeHGlobal(entries);
            if(locked)ReleaseMutex(mutex);if(mutex!=IntPtr.Zero)CloseHandle(mutex);LocalFree(descriptor);
        }
    }
    void Seal() {
        if(!policyAttempted)return;
        if(CodeNetworkFence.Apply(sid,port,image,"Seal")!=8||CodeNetworkFence.Apply(sid,port,image,"VerifySealed")!=8)throw new InvalidDataException("code-policy-not-sealed");
    }
    void StopJob() {
        if(job==IntPtr.Zero)return;
        Check(TerminateJobObject(job,1));var watch=Stopwatch.StartNew();
        while(watch.ElapsedMilliseconds<8000){Accounting info;uint returned;Check(QueryInformationJobObject(job,1,out info,Marshal.SizeOf(typeof(Accounting)),out returned));if(returned!=48)throw new InvalidDataException("code-job-accounting");if(info.active==0)return;Thread.Sleep(50);}
        throw new TimeoutException("code-job-not-drained");
    }
    public static CodeFenceSession Open(NamedPipeClientStream pipe,string containerName,string jobName,string trustedRelayExecutable,int relayPort) {
        if(IntPtr.Size!=8||pipe==null||!Regex.IsMatch(containerName??"","^gate-code-[0-9a-f]{24}$")||
            !Regex.IsMatch(jobName??"",@"^Global\\gate-code-job-[0-9a-f]{32}$")||relayPort<1024||relayPort>65535)throw new InvalidDataException("code-session-request");
        var session=new CodeFenceSession();session.port=relayPort;
        try {
            string user=session.AuthenticateController(pipe,trustedRelayExecutable);IntPtr package=IntPtr.Zero;
            try { int hr=DeriveAppContainerSidFromAppContainerName(containerName,out package);if(hr<0)Marshal.ThrowExceptionForHR(hr);session.sid=SidText(package); }
            finally { if(package!=IntPtr.Zero)FreeSid(package); }
            session.CreateOwnedJob(jobName,user);session.policyAttempted=true;
            if(CodeNetworkFence.BindAndInstall(session.sid,relayPort,session.image,session.job)!=10)throw new InvalidDataException("code-policy-count");
            session.ChangeLoopback(true);
            if(WaitForSingleObject(session.controller,0)!=258)throw new InvalidDataException("code-controller-exited");
            return session;
        } catch { session.Dispose();throw; }
    }
    public string ProofJson() { return "{\"sid\":\""+sid+"\",\"jobName\":\""+JobName.Replace("\\","\\\\")+"\",\"filters\":10}"; }
    public void CloseAndRetire() {
        if(retired)return;if(disposed||job==IntPtr.Zero)throw new InvalidOperationException("code-session-closed");
        try { Seal(); } finally { StopJob(); }
        if(exemptionOwned)ChangeLoopback(false);
        if(CodeNetworkFence.RetireAfterJobExit(sid,port,image,job)!=0)throw new InvalidDataException("code-policy-retire");
        retired=true;
    }
    public void Dispose() {
        if(disposed)return;disposed=true;
        try {
            if(!retired){
                try{Seal();}catch{}bool drained=false;try{StopJob();drained=true;}catch{}
                if(drained&&exemptionOwned)try{ChangeLoopback(false);}catch{}
                // Never Retire on EOF, partial startup, broker error or abort.
            }
        } finally {
            if(job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}
            if(controller!=IntPtr.Zero){CloseHandle(controller);controller=IntPtr.Zero;}
            if(controllerImage!=null){controllerImage.Dispose();controllerImage=null;}
        }
    }
}
