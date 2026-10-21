using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

// Administrator-only package policy. Identity is the actual AppContainer SID,
// so an inherited token keeps this policy across different executable images.
// No permit, network capability, or loopback exemption is created here.
public static class CodeNetworkFence {
    const uint NotFound=0x80320003, AlreadyExists=0x80320009, Block=0x1001;
    const string Owner="gate-claude-code-package-wfp-v1";
    static readonly object ApplyLock=new object();
    sealed class Binding { public IntPtr job; public int port; public string image; public bool committed; }
    static readonly Dictionary<string,Binding> Bindings=new Dictionary<string,Binding>(StringComparer.Ordinal);
    static IntPtr SecurityDescriptor=IntPtr.Zero;
    static readonly Guid SubLayer=new Guid("9a2870fb-a8c6-4d8b-9e34-18e40849712a");
    static readonly Guid Connect4=new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"), Connect6=new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    static readonly Guid Accept4=new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), Accept6=new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");
    static readonly Guid Listen4=new Guid("88bb5dad-76d7-4227-9c71-df0a3ed7be7e"), Listen6=new Guid("7ac9de24-17dd-4814-b4bd-a9fbc95a321b");
    static readonly Guid Bind4=new Guid("1247d66d-0b60-4a15-8d44-7155d0f53a0c"), Bind6=new Guid("55a650e1-5f0a-4eca-a653-88f53b26aa8c");
    static readonly Guid PackageId=new Guid("71bc78fa-f17c-4997-a602-6abb261f351c"), AppId=new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
    static readonly Guid Protocol=new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"), RemoteAddress=new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    static readonly Guid RemotePort=new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b"), LocalPort=new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b");
    static readonly string[] OpenKinds={"package-protocol","package-address","package-port","package-v6","package-in4","package-in6"};
    static readonly string[] SealedKinds={"sealed-out4","sealed-out6","sealed-in4","sealed-in6"};
    static readonly string[] RelayKinds={"relay-bind4","relay-bind6","relay-listen4","relay-listen6"};
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Display { public string name,description; }
    [StructLayout(LayoutKind.Sequential)] struct Blob { public uint size; public IntPtr data; }
    [StructLayout(LayoutKind.Explicit,Size=16)] struct Value { [FieldOffset(0)] public uint type; [FieldOffset(8)] public ulong scalar; [FieldOffset(8)] public IntPtr pointer; }
    [StructLayout(LayoutKind.Sequential)] struct Condition { public Guid key; public uint match; public Value value; }
    [StructLayout(LayoutKind.Sequential)] struct Action { public uint type; public Guid filterType; }
    [StructLayout(LayoutKind.Explicit,Size=16)] struct Context { [FieldOffset(0)] public ulong raw; [FieldOffset(0)] public Guid key; }
    [StructLayout(LayoutKind.Sequential)] struct Filter {
        public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob providerData;
        public Guid layer,subLayer; public Value weight; public uint count; public IntPtr conditions; public Action action;
        public Context context; public IntPtr reserved; public ulong id; public Value effectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)] struct Layer { public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob providerData; public ushort weight; }
    [StructLayout(LayoutKind.Sequential)] struct JobAccounting { public long user,kernel,periodUser,periodKernel; public uint pageFaults,totalProcesses,activeProcesses,terminatedProcesses; }
    sealed class Spec { public string kind; public Guid layer; public Condition[] conditions; public Spec(string k,Guid l,params Condition[] c){kind=k;layer=l;conditions=c;} }
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine,ref Layer layer,IntPtr security);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerGetByKey0(IntPtr engine,ref Guid key,out IntPtr layer);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerGetSecurityInfoByKey0(IntPtr engine,ref Guid key,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine,ref Filter filter,IntPtr security,out ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr engine,ref Guid key,out IntPtr filter);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine,ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetSecurityInfoByKey0(IntPtr engine,ref Guid key,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string file,out IntPtr blob);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint size);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll")] static extern bool IsValidSid(IntPtr sid);
    [DllImport("advapi32.dll")] static extern uint GetLengthSid(IntPtr sid);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int type,out JobAccounting info,int length,out uint returned);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int type,IntPtr info,int length,out uint returned);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetHandleInformation(IntPtr handle,out uint flags);
    static void Check(uint code){if(code!=0)throw new Win32Exception(unchecked((int)code));}
    static void RequireAdmin(){if(IntPtr.Size!=8 || !new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))throw new UnauthorizedAccessException();}
    static string ValidateSid(string text){
        if(text==null || text.Length>192)throw new ArgumentException("code-package-identity");
        SecurityIdentifier sid;try{sid=new SecurityIdentifier(text);}catch{throw new ArgumentException("code-package-identity");}
        // A unique AppContainer package SID, not a capability or ALL_PACKAGES SID.
        byte[] b=new byte[sid.BinaryLength];sid.GetBinaryForm(b,0);
        if(!text.StartsWith("S-1-15-2-",StringComparison.Ordinal) || b.Length!=40 || b[1]!=8 || b[7]!=15 || BitConverter.ToUInt32(b,8)!=2 || sid.Value!=text)throw new ArgumentException("code-package-identity");
        return sid.Value;
    }
    static string ValidateImage(string image){
        if(String.IsNullOrEmpty(image)||image.Length>1024||image.IndexOfAny(new char[]{'\0','\r','\n','"'})>=0||!Path.IsPathRooted(image)||image.StartsWith(@"\\")||!String.Equals(Path.GetExtension(image),".exe",StringComparison.OrdinalIgnoreCase))throw new ArgumentException("code-relay-image");
        string full=Path.GetFullPath(image);if(!String.Equals(image,full,StringComparison.OrdinalIgnoreCase)||!File.Exists(full))throw new ArgumentException("code-relay-image");return full;
    }
    static Guid Key(string sid,string kind){byte[] bytes;using(var hash=SHA256.Create())bytes=hash.ComputeHash(Encoding.UTF8.GetBytes(Owner+"\n"+sid+"\n"+kind));byte[] key=new byte[16];Array.Copy(bytes,key,16);return new Guid(key);}
    static Condition Identity(IntPtr sid){return new Condition{key=PackageId,match=0,value=new Value{type=13,pointer=sid}};}
    static Condition Number(Guid key,uint type,ulong value,uint match){return new Condition{key=key,match=match,value=new Value{type=type,scalar=value}};}
    static Spec[] Specs(IntPtr sid,IntPtr app,int port,bool seal){
        var p=Identity(sid);var specs=new List<Spec>();
        if(seal){specs.Add(new Spec(SealedKinds[0],Connect4,p));specs.Add(new Spec(SealedKinds[1],Connect6,p));specs.Add(new Spec(SealedKinds[2],Accept4,p));specs.Add(new Spec(SealedKinds[3],Accept6,p));}
        else{
            specs.Add(new Spec(OpenKinds[0],Connect4,p,Number(Protocol,1,6,10)));
            specs.Add(new Spec(OpenKinds[1],Connect4,p,Number(RemoteAddress,3,0x7f000001,10)));
            specs.Add(new Spec(OpenKinds[2],Connect4,p,Number(RemotePort,2,(uint)port,10)));
            specs.Add(new Spec(OpenKinds[3],Connect6,p));specs.Add(new Spec(OpenKinds[4],Accept4,p));specs.Add(new Spec(OpenKinds[5],Accept6,p));
        }
        // Cover wildcard binds as well as 127.0.0.1. A wildcard address is FWP_EMPTY,
        // so an address==127 condition would leave a port-hijack hole. No IP_PROTOCOL
        // condition belongs on AUTH_LISTEN (which authorizes TCP listen already).
        var foreignImage=new Condition{key=AppId,match=10,value=new Value{type=12,pointer=app}};
        var localPort=Number(LocalPort,2,(uint)port,0);
        specs.Add(new Spec(RelayKinds[0],Bind4,foreignImage,localPort));specs.Add(new Spec(RelayKinds[1],Bind6,foreignImage,localPort));
        specs.Add(new Spec(RelayKinds[2],Listen4,foreignImage,localPort));specs.Add(new Spec(RelayKinds[3],Listen6,foreignImage,localPort));
        return specs.ToArray();
    }
    static void VerifySecurity(IntPtr engine,Guid key,bool sublayer){
        IntPtr descriptor=IntPtr.Zero,owner,group,dacl,sacl;
        try{
            Check(sublayer?FwpmSubLayerGetSecurityInfoByKey0(engine,ref key,5,out owner,out group,out dacl,out sacl,out descriptor):FwpmFilterGetSecurityInfoByKey0(engine,ref key,5,out owner,out group,out dacl,out sacl,out descriptor));
            uint length=GetSecurityDescriptorLength(descriptor);if(length==0||length>65536)throw new InvalidDataException("code-policy-security");
            byte[] bytes=new byte[length];Marshal.Copy(descriptor,bytes,0,bytes.Length);var security=new RawSecurityDescriptor(bytes,0);
            var admins=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);var system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
            if(!admins.Equals(security.Owner)||(security.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0||security.DiscretionaryAcl==null||security.DiscretionaryAcl.Count!=2)throw new InvalidDataException("code-policy-security");
            bool ba=false,sy=false;foreach(GenericAce entry in security.DiscretionaryAcl){var ace=entry as CommonAce;
                if(ace==null||ace.IsCallback||ace.AceQualifier!=AceQualifier.AccessAllowed||ace.AceFlags!=AceFlags.None||ace.AccessMask!=0x000f07ff)throw new InvalidDataException("code-policy-security");
                if(admins.Equals(ace.SecurityIdentifier))ba=true;else if(system.Equals(ace.SecurityIdentifier))sy=true;else throw new InvalidDataException("code-policy-security");
            }if(!ba||!sy)throw new InvalidDataException("code-policy-security");
        }finally{if(descriptor!=IntPtr.Zero)FwpmFreeMemory0(ref descriptor);}
    }
    static void VerifySubLayer(IntPtr engine){Guid key=SubLayer;IntPtr found=IntPtr.Zero;try{
        Check(FwpmSubLayerGetByKey0(engine,ref key,out found));var s=(Layer)Marshal.PtrToStructure(found,typeof(Layer));
        if(s.key!=SubLayer||s.display.description!=Owner||s.flags!=1||s.provider!=IntPtr.Zero||s.providerData.size!=0||s.weight==0)throw new InvalidDataException("code-sublayer-mismatch");
        VerifySecurity(engine,key,true);
    }finally{if(found!=IntPtr.Zero)FwpmFreeMemory0(ref found);}}
    static bool ExistsOwned(IntPtr engine,Guid key){IntPtr found=IntPtr.Zero;uint code=FwpmFilterGetByKey0(engine,ref key,out found);if(code==NotFound)return false;Check(code);try{
        var f=(Filter)Marshal.PtrToStructure(found,typeof(Filter));if(f.subLayer!=SubLayer||f.display.description!=Owner||f.action.type!=Block)throw new InvalidDataException("code-filter-ownership");return true;
    }finally{if(found!=IntPtr.Zero)FwpmFreeMemory0(ref found);}}
    static void DeleteOwned(IntPtr engine,Guid key){if(ExistsOwned(engine,key))Check(FwpmFilterDeleteByKey0(engine,ref key));}
    static void Add(IntPtr engine,string sid,Spec spec){int size=Marshal.SizeOf(typeof(Condition));IntPtr buffer=Marshal.AllocHGlobal(size*spec.conditions.Length);try{
        for(int i=0;i<spec.conditions.Length;i++)Marshal.StructureToPtr(spec.conditions[i],IntPtr.Add(buffer,size*i),false);
        var f=new Filter{key=Key(sid,spec.kind),display=new Display{name="Claude Proxy Guard Code: "+spec.kind,description=Owner},flags=1,layer=spec.layer,subLayer=SubLayer,weight=new Value{type=1,scalar=15},count=(uint)spec.conditions.Length,conditions=buffer,action=new Action{type=Block}};ulong id;Check(FwpmFilterAdd0(engine,ref f,SecurityDescriptor,out id));
    }finally{Marshal.FreeHGlobal(buffer);}}
    static void EqualValue(Value actual,Value expected){
        if(actual.type!=expected.type)throw new InvalidDataException("code-condition-type");
        if(expected.type==13){if(!IsValidSid(actual.pointer)||!IsValidSid(expected.pointer))throw new InvalidDataException("code-condition-sid");uint n=GetLengthSid(expected.pointer);if(n>192||GetLengthSid(actual.pointer)!=n)throw new InvalidDataException("code-condition-sid");for(int i=0;i<n;i++)if(Marshal.ReadByte(actual.pointer,i)!=Marshal.ReadByte(expected.pointer,i))throw new InvalidDataException("code-condition-sid");}
        else if(expected.type==12){var a=(Blob)Marshal.PtrToStructure(actual.pointer,typeof(Blob));var e=(Blob)Marshal.PtrToStructure(expected.pointer,typeof(Blob));if(a.size!=e.size||a.size>65536)throw new InvalidDataException("code-condition-image");for(int i=0;i<a.size;i++)if(Marshal.ReadByte(a.data,i)!=Marshal.ReadByte(e.data,i))throw new InvalidDataException("code-condition-image");}
        else if(actual.scalar!=expected.scalar)throw new InvalidDataException("code-condition-tuple");
    }
    static void Verify(IntPtr engine,string sid,Spec spec){Guid key=Key(sid,spec.kind);IntPtr found=IntPtr.Zero;try{
        Check(FwpmFilterGetByKey0(engine,ref key,out found));var f=(Filter)Marshal.PtrToStructure(found,typeof(Filter));
        if(f.key!=key||f.subLayer!=SubLayer||f.layer!=spec.layer||f.action.type!=Block||f.display.description!=Owner||(f.flags&~0x40u)!=1||f.provider!=IntPtr.Zero||f.providerData.size!=0||f.weight.type!=1||f.weight.scalar!=15||f.count!=spec.conditions.Length)throw new InvalidDataException("code-filter-mismatch");
        int size=Marshal.SizeOf(typeof(Condition));for(int i=0;i<spec.conditions.Length;i++){var c=(Condition)Marshal.PtrToStructure(IntPtr.Add(f.conditions,i*size),typeof(Condition));var e=spec.conditions[i];if(c.key!=e.key||c.match!=e.match)throw new InvalidDataException("code-condition-mismatch");EqualValue(c.value,e.value);}
        VerifySecurity(engine,key,false);
    }finally{if(found!=IntPtr.Zero)FwpmFreeMemory0(ref found);}}
    static bool IsSealed(IntPtr engine,string sid){foreach(string k in SealedKinds)if(ExistsOwned(engine,Key(sid,k)))return true;return false;}
    static int ApplyCore(string suppliedSid,int relayPort,string suppliedImage,string mode,IntPtr job){
        RequireAdmin();string sid=ValidateSid(suppliedSid),image=ValidateImage(suppliedImage);if(relayPort<1024||relayPort>65535)throw new ArgumentException("code-relay-port");
        if(mode!="Install"&&mode!="Verify"&&mode!="Seal"&&mode!="VerifySealed"&&mode!="Retire")throw new ArgumentException("code-policy-mode");
        if(mode=="Seal"){Binding own;if(!Bindings.TryGetValue(sid,out own)||!own.committed||own.port!=relayPort||!String.Equals(own.image,image,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("code-job-not-owned");}
        IntPtr engine=IntPtr.Zero,package=IntPtr.Zero,app=IntPtr.Zero;bool transaction=false;
        try{
            byte[] bytes=new byte[new SecurityIdentifier(sid).BinaryLength];new SecurityIdentifier(sid).GetBinaryForm(bytes,0);package=Marshal.AllocHGlobal(bytes.Length);Marshal.Copy(bytes,0,package,bytes.Length);
            uint size;if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)",1,out SecurityDescriptor,out size))throw new Win32Exception(Marshal.GetLastWin32Error());
            Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine));Check(FwpmGetAppIdFromFileName0(image,out app));
            bool seal=mode=="Seal"||mode=="VerifySealed"||mode=="Retire";Spec[] specs=Specs(package,app,relayPort,seal);
            if(mode=="Retire"){
                Binding bound;if(!Bindings.TryGetValue(sid,out bound)||!bound.committed||bound.job!=job||bound.port!=relayPort||!String.Equals(bound.image,image,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("code-job-not-owned");
                VerifySubLayer(engine);foreach(var spec in specs)Verify(engine,sid,spec);
                JobAccounting info;uint returned;if(job==IntPtr.Zero||job==new IntPtr(-1)||!QueryInformationJobObject(job,1,out info,Marshal.SizeOf(typeof(JobAccounting)),out returned)||returned!=Marshal.SizeOf(typeof(JobAccounting))||info.activeProcesses!=0)throw new InvalidOperationException("code-job-not-drained");
            }
            if(mode=="Install"||mode=="Seal"||mode=="Retire"){
                Check(FwpmTransactionBegin0(engine,0));transaction=true;
                if(mode!="Retire"){
                    var sub=new Layer{key=SubLayer,display=new Display{name="Guard Code package deny",description=Owner},flags=1,weight=65535};uint status=FwpmSubLayerAdd0(engine,ref sub,SecurityDescriptor);if(status!=AlreadyExists)Check(status);VerifySubLayer(engine);
                }
                if(mode=="Install"){foreach(string kind in OpenKinds)if(ExistsOwned(engine,Key(sid,kind)))throw new InvalidOperationException("code-package-previous-owner");foreach(string kind in SealedKinds)if(ExistsOwned(engine,Key(sid,kind)))throw new InvalidOperationException("code-package-previous-owner");foreach(string kind in RelayKinds)if(ExistsOwned(engine,Key(sid,kind)))throw new InvalidOperationException("code-package-previous-owner");}
                foreach(string kind in OpenKinds)DeleteOwned(engine,Key(sid,kind));foreach(string kind in SealedKinds)DeleteOwned(engine,Key(sid,kind));foreach(string kind in RelayKinds)DeleteOwned(engine,Key(sid,kind));
                if(mode!="Retire")foreach(var spec in specs)Add(engine,sid,spec);
                Check(FwpmTransactionCommit0(engine));transaction=false;
                if(mode=="Install"){Binding installed;if(Bindings.TryGetValue(sid,out installed))installed.committed=true;}
            }
            if(mode!="Retire"){VerifySubLayer(engine);foreach(var spec in specs)Verify(engine,sid,spec);foreach(string kind in seal?OpenKinds:SealedKinds)if(ExistsOwned(engine,Key(sid,kind)))throw new InvalidDataException("code-policy-state-mismatch");}
            if(mode=="Retire")Bindings.Remove(sid);
            return mode=="Retire"?0:specs.Length;
        }finally{if(transaction)FwpmTransactionAbort0(engine);if(engine!=IntPtr.Zero)FwpmEngineClose0(engine);if(app!=IntPtr.Zero)FwpmFreeMemory0(ref app);if(package!=IntPtr.Zero)Marshal.FreeHGlobal(package);if(SecurityDescriptor!=IntPtr.Zero){LocalFree(SecurityDescriptor);SecurityDescriptor=IntPtr.Zero;}}
    }
    public static int Apply(string packageSid,int relayPort,string trustedRelayExecutable,string mode){lock(ApplyLock){if(mode=="Install"||mode=="Retire")throw new InvalidOperationException("code-owned-job-required");return ApplyCore(packageSid,relayPort,trustedRelayExecutable,mode,IntPtr.Zero);}}
    // Bind the broker's sole non-inherited global Job handle before admitting any
    // child. Never duplicate that handle: KILL_ON_JOB_CLOSE must survive broker loss.
    public static int BindAndInstall(string packageSid,int relayPort,string trustedRelayExecutable,IntPtr ownJob){lock(ApplyLock){
        RequireAdmin();string sid=ValidateSid(packageSid),image=ValidateImage(trustedRelayExecutable);uint flags,returned;JobAccounting accounting;
        if(ownJob==IntPtr.Zero||ownJob==new IntPtr(-1)||!GetHandleInformation(ownJob,out flags)||(flags&1)!=0||!QueryInformationJobObject(ownJob,1,out accounting,Marshal.SizeOf(typeof(JobAccounting)),out returned)||returned!=Marshal.SizeOf(typeof(JobAccounting)))throw new InvalidOperationException("code-job-invalid");
        Binding bound;if(Bindings.TryGetValue(sid,out bound)){
            if(bound.job!=ownJob||bound.port!=relayPort||!String.Equals(bound.image,image,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("code-job-already-bound");
            return ApplyCore(sid,relayPort,image,"Verify",IntPtr.Zero);
        }
        if(accounting.activeProcesses!=0)throw new InvalidOperationException("code-job-not-empty");
        IntPtr limits=Marshal.AllocHGlobal(64);try{
            if(!QueryInformationJobObject(ownJob,2,limits,64,out returned)||returned!=64)throw new InvalidOperationException("code-job-limits");
            uint jobFlags=unchecked((uint)Marshal.ReadInt32(limits,16));if((jobFlags&0x2000)==0||(jobFlags&0x1800)!=0)throw new InvalidOperationException("code-job-limits");
        }finally{Marshal.FreeHGlobal(limits);}
        // Retain ownership even if post-commit verification fails; the caller must
        // Seal/Terminate/drain/Retire conservatively. A process restart cannot retire
        // a previous broker's policy from an unrelated empty Job.
        Bindings.Add(sid,new Binding{job=ownJob,port=relayPort,image=image});
        try{return ApplyCore(sid,relayPort,image,"Install",IntPtr.Zero);}catch{Binding failed;if(Bindings.TryGetValue(sid,out failed)&&!failed.committed)Bindings.Remove(sid);throw;}
    }}
    // Trusted broker calls this with its still-open own Job only after TerminateJobObject
    // and drain. Failure to query, active descendants or unknown ownership retains deny.
    public static int RetireAfterJobExit(string packageSid,int relayPort,string trustedRelayExecutable,IntPtr ownJob){lock(ApplyLock){return ApplyCore(packageSid,relayPort,trustedRelayExecutable,"Retire",ownJob);}}
}
