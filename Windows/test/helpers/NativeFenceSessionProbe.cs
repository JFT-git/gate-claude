using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

// Runs as the interactive Limited user. The production broker runs elevated in
// a different process; no test hook is added to its authentication or lifecycle.
internal static class NativeFenceSessionProbe {
    const uint ControllerRights=0x100005;
    [StructLayout(LayoutKind.Sequential)] struct SidAttributes { public IntPtr sid; public uint attributes; }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup {
        public uint size; public string reserved,desktop,title; public uint x,y,width,height,columns,rows,fill,flags;
        public ushort show,reservedLength; public IntPtr reservedPointer,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr process,thread; public uint pid,tid; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenJobObject(uint access,bool inherit,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int type,IntPtr buffer,uint size,out uint returned);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetHandleInformation(IntPtr handle,out uint flags);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string cwd,ref Startup startup,out ProcessInfo process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr GetProcessHeap();
    [DllImport("kernel32.dll")] static extern bool HeapFree(IntPtr heap,uint flags,IntPtr memory);
    [DllImport("FirewallAPI.dll")] static extern uint NetworkIsolationGetAppContainerConfig(out uint count,out IntPtr entries);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int DeriveAppContainerSidFromAppContainerName(string name,out IntPtr sid);
    [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine,ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr engine,ref Guid key,out IntPtr filter);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
    static void Check(bool value) { if(!value)throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static string B64(string value) { return Convert.ToBase64String(Encoding.UTF8.GetBytes(value)); }
    static Dictionary<string,object> Read(StreamReader reader) { var line=reader.ReadLine();if(line==null)throw new EndOfStreamException();return Json.Deserialize<Dictionary<string,object>>(line); }
    static string Text(Dictionary<string,object> value,string key) { return (string)value[key]; }
    static string[] Loopback() {
        uint count;IntPtr entries;uint status=NetworkIsolationGetAppContainerConfig(out count,out entries);
        try {
            if(status!=0)throw new Win32Exception((int)status);
            if(count>4096)throw new InvalidDataException();var list=new List<string>();int size=Marshal.SizeOf(typeof(SidAttributes));
            for(int i=0;i<count;i++){var entry=(SidAttributes)Marshal.PtrToStructure(IntPtr.Add(entries,i*size),typeof(SidAttributes));list.Add(new SecurityIdentifier(entry.sid).Value+":"+entry.attributes);}
            list.Sort(StringComparer.Ordinal);return list.ToArray();
        } finally {
            if(entries!=IntPtr.Zero){int size=Marshal.SizeOf(typeof(SidAttributes));for(int i=0;i<count;i++){IntPtr sid=Marshal.ReadIntPtr(IntPtr.Add(entries,i*size));if(sid!=IntPtr.Zero)HeapFree(GetProcessHeap(),0,sid);}HeapFree(GetProcessHeap(),0,entries);}
        }
    }
    static bool Denied(string name,uint rights) { IntPtr handle=OpenJobObject(rights,false,name);if(handle==IntPtr.Zero)return Marshal.GetLastWin32Error()==5;CloseHandle(handle);return false; }
    static void Status(uint value) { if(value!=0)throw new Win32Exception(unchecked((int)value)); }
    static Guid PolicyKey(string sid,string kind) {
        byte[] bytes;using(var hash=SHA256.Create())bytes=hash.ComputeHash(Encoding.UTF8.GetBytes("gate-claude-code-package-wfp-v1\n"+sid+"\n"+kind));
        byte[] key=new byte[16];Array.Copy(bytes,key,16);return new Guid(key);
    }
    static int CleanupEof(string configFile) {
        // Administrative test-artifact cleanup only. Production deliberately
        // refuses to retire another broker's binding. Verify its complete sealed
        // footprint, absent exact Job and absent exemption before deleting only
        // these eight deterministic fixture keys. Shared sublayers stay intact.
        if(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))return 5;
        var config=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(configFile));
        if(Text(config,"mode")!="eof"||!Regex.IsMatch(Text(config,"containerName"),"^gate-code-[0-9a-f]{24}$")||!Regex.IsMatch(Text(config,"jobName"),@"^Global\\gate-code-job-[0-9a-f]{32}$"))return 64;
        var proof=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(Text(config,"root"),"proof.json")));
        if(!(bool)proof["pass"]||!(bool)proof["jobKilledAfterEof"]||!(bool)proof["loopbackRestoredExactly"])throw new InvalidDataException("unproven-eof");
        var installed=(Dictionary<string,object>)proof["installed"];var code=(Dictionary<string,object>)installed["code"];string sid=Text(code,"sid");IntPtr package=IntPtr.Zero;
        try{int hr=DeriveAppContainerSidFromAppContainerName(Text(config,"containerName"),out package);if(hr<0)Marshal.ThrowExceptionForHR(hr);if(new SecurityIdentifier(package).Value!=sid)throw new InvalidDataException("fixture-sid");}finally{if(package!=IntPtr.Zero)FreeSid(package);}
        IntPtr job=OpenJobObject(4,false,Text(config,"jobName"));int jobError=Marshal.GetLastWin32Error();if(job!=IntPtr.Zero){CloseHandle(job);throw new InvalidDataException("fixture-job-live");}if(jobError!=2)throw new Win32Exception(jobError);
        foreach(string entry in Loopback())if(entry.StartsWith(sid+":",StringComparison.Ordinal))throw new InvalidDataException("fixture-exemption-live");
        string image=Process.GetCurrentProcess().MainModule.FileName;int port=Convert.ToInt32(proof["relayPort"]);
        if(CodeNetworkFence.Apply(sid,port,image,"VerifySealed")!=8)throw new InvalidDataException("fixture-not-sealed");
        string[] kinds={"sealed-out4","sealed-out6","sealed-in4","sealed-in6","relay-bind4","relay-bind6","relay-listen4","relay-listen6"};
        IntPtr engine=IntPtr.Zero;bool transaction=false;
        try {
            Status(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine));Status(FwpmTransactionBegin0(engine,0));transaction=true;
            foreach(string kind in kinds){Guid key=PolicyKey(sid,kind);Status(FwpmFilterDeleteByKey0(engine,ref key));}
            Status(FwpmTransactionCommit0(engine));transaction=false;
            foreach(string kind in kinds){Guid key=PolicyKey(sid,kind);IntPtr filter;uint status=FwpmFilterGetByKey0(engine,ref key,out filter);if(filter!=IntPtr.Zero)FwpmFreeMemory0(ref filter);if(status!=0x80320003)throw new InvalidDataException("fixture-key-retained");}
        } finally {if(transaction)FwpmTransactionAbort0(engine);if(engine!=IntPtr.Zero)FwpmEngineClose0(engine);}
        Console.WriteLine("{\"verifiedSealedFilters\":8,\"jobAbsent\":true,\"exemptionAbsent\":true,\"exactKeysDeleted\":8}");return 0;
    }
    public static int Main(string[] args) {
        if(args.Length==1&&args[0]=="--child"){Thread.Sleep(60000);return 0;}
        if(args.Length==2&&args[0]=="--cleanup-eof")return CleanupEof(args[1]);
        if(args.Length!=1)return 64;
        var config=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(args[0]));string root=Text(config,"root"),mode=Text(config,"mode");
        var proof=new Dictionary<string,object>();IntPtr job=IntPtr.Zero;ProcessInfo child=new ProcessInfo();TcpListener relay=null;
        try {
            bool standard=!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            proof["standardUser"]=standard;proof["interactiveSession"]=Process.GetCurrentProcess().SessionId>0;if(!standard||(bool)proof["interactiveSession"]==false)throw new InvalidOperationException("limited-interactive-required");
            string[] before=Loopback();string self=Process.GetCurrentProcess().MainModule.FileName;
            relay=new TcpListener(IPAddress.Loopback,0);relay.Start();int port=((IPEndPoint)relay.LocalEndpoint).Port;proof["relayPort"]=port;
            using(var pipe=new NamedPipeServerStream(Text(config,"pipeName"),PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.None)) {
                File.WriteAllText(Path.Combine(root,"ready.json"),Json.Serialize(new{pid=Process.GetCurrentProcess().Id,standardUser=standard,interactiveSession=true}));
                pipe.WaitForConnection();
                using(var reader=new StreamReader(pipe,new UTF8Encoding(false,true),false,4096,true))
                using(var writer=new StreamWriter(pipe,new UTF8Encoding(false),4096,true){AutoFlush=true}) {
                    var hello=Read(reader);if(Text(hello,"type")!="hello"||Text(hello,"token")!=Text(config,"token"))throw new InvalidDataException("hello");
                    string runtime=Path.Combine(root,"Runtime-111111111111111111111111"),runtimeImage=Path.Combine(runtime,"Claude.exe");
                    string request="install\t"+B64(runtime)+"\t"+port+"\t"+B64(runtimeImage);
                    if(mode!="legacy")request+="\t"+B64(Text(config,"containerName"))+"\t"+B64(Text(config,"jobName"))+"\t"+B64(mode=="wrong-image"?runtimeImage:self);
                    writer.WriteLine(request);var installed=Read(reader);proof["installed"]=installed;
                    if(mode=="wrong-image") {
                        proof["controllerImageMismatchDenied"]=Text(installed,"type")=="error"&&Text(installed,"kind")=="InvalidDataException";
                        IntPtr rejected=OpenJobObject(4,false,Text(config,"jobName"));int rejectedError=Marshal.GetLastWin32Error();if(rejected!=IntPtr.Zero)CloseHandle(rejected);proof["noJobOnRejectedController"]=rejected==IntPtr.Zero&&rejectedError==2;
                    } else if(Text(installed,"type")!="installed")throw new InvalidDataException("install");
                    if(mode!="legacy"&&mode!="wrong-image") {
                        var code=(Dictionary<string,object>)installed["code"];string jobName=Text(config,"jobName");
                        proof["codeProofExact"]=(code.Count==3&&Text(code,"jobName")==jobName&&Convert.ToInt32(code["filters"])==10&&Text(code,"sid").StartsWith("S-1-15-2-",StringComparison.Ordinal));
                        var during=new List<string>(Loopback());proof["ownExemptionAdded"]=during.Remove(Text(code,"sid")+":0");during.Sort(StringComparer.Ordinal);proof["otherExemptionsPreserved"]=String.Join("\n",before)==String.Join("\n",during.ToArray());
                        job=OpenJobObject(ControllerRights,false,jobName);Check(job!=IntPtr.Zero);uint flags;Check(GetHandleInformation(job,out flags));proof["handleNotInherited"]=(flags&1)==0;
                        IntPtr limits=Marshal.AllocHGlobal(64);try{uint returned;Check(QueryInformationJobObject(job,2,limits,64,out returned));proof["killOnCloseWithoutBreakaway"]=returned==64&&Marshal.ReadInt32(limits,16)==0x2000;}finally{Marshal.FreeHGlobal(limits);}
                        proof["setAttributesDenied"]=Denied(jobName,2);proof["terminateDenied"]=Denied(jobName,8);proof["writeDaclDenied"]=Denied(jobName,0x40000);proof["writeOwnerDenied"]=Denied(jobName,0x80000);
                        var startup=new Startup{size=(uint)Marshal.SizeOf(typeof(Startup))};Check(CreateProcess(self,new StringBuilder("\""+self+"\" --child"),IntPtr.Zero,IntPtr.Zero,false,0x08000004,IntPtr.Zero,root,ref startup,out child));
                        Check(AssignProcessToJobObject(job,child.process));proof["limitedAssignSucceeded"]=true;
                        CloseHandle(job);job=IntPtr.Zero;Check(ResumeThread(child.thread)!=0xffffffff);proof["childAliveBeforeClose"]=WaitForSingleObject(child.process,100)==258;
                    }
                    if(mode!="eof"&&mode!="wrong-image") {
                        writer.WriteLine("remove-after-job-exit");var removed=Read(reader);proof["removed"]=Text(removed,"type")=="removed"&&(bool)removed["removed"];
                        if(child.process!=IntPtr.Zero)proof["jobDrainedBeforeRemoved"]=WaitForSingleObject(child.process,0)==0;
                    }
                }
                if(mode=="eof") {
                    pipe.Dispose();proof["jobKilledAfterEof"]=WaitForSingleObject(child.process,10000)==0;
                    for(int i=0;i<200;i++){if(String.Join("\n",before)==String.Join("\n",Loopback()))break;Thread.Sleep(25);}
                }
            }
            proof["loopbackRestoredExactly"]=String.Join("\n",before)==String.Join("\n",Loopback());proof["pass"]=true;
            foreach(var item in proof)if(item.Value is bool&&!(bool)item.Value){proof["pass"]=false;break;}
        } catch(Exception error) { proof["pass"]=false;proof["errorType"]=error.GetType().Name;proof["win32"]=error is Win32Exception?((Win32Exception)error).NativeErrorCode:0; }
        finally {
            if(job!=IntPtr.Zero)CloseHandle(job);if(child.process!=IntPtr.Zero){if(WaitForSingleObject(child.process,0)==258)TerminateProcess(child.process,1);CloseHandle(child.process);}if(child.thread!=IntPtr.Zero)CloseHandle(child.thread);if(relay!=null)relay.Stop();
            File.WriteAllText(Path.Combine(root,"proof.json"),Json.Serialize(proof));
        }
        return (bool)proof["pass"]?0:1;
    }
}
