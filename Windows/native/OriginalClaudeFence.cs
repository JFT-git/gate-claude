using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Text;

// Administrator-only persistent image deny policy. No loopback exception.
public static class OriginalClaudeFence {
    const uint NotFound=0x80320003, AlreadyExists=0x80320009;
    const string Owner="gate-claude-original-wfp-v1";
    static IntPtr SecurityDescriptor=IntPtr.Zero;
    static readonly object ApplyLock=new object();
    static readonly Guid SubLayer=new Guid("d3a5f6e4-8d14-4077-8b72-9a173511d673");
    static readonly Guid Connect4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    static readonly Guid Connect6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    static readonly Guid Accept4 = new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    static readonly Guid Accept6 = new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");
    static readonly Guid AppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
    static readonly string[] Kinds={"out-v4","out-v6","in-v4","in-v6"};
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Display { public string name,description; }
    [StructLayout(LayoutKind.Sequential)] struct Blob { public uint size; public IntPtr data; }
    // The WFP value union is pointer-sized. This broker supports x64 only.
    [StructLayout(LayoutKind.Explicit, Size=16)] struct Value {
        [FieldOffset(0)] public uint type;
        [FieldOffset(8)] public ulong scalar;
        [FieldOffset(8)] public IntPtr pointer;
    }
    [StructLayout(LayoutKind.Sequential)] struct Condition { public Guid key; public uint match; public Value value; }
    [StructLayout(LayoutKind.Sequential)] struct Action { public uint type; public Guid filterType; }
    [StructLayout(LayoutKind.Explicit, Size=16)] struct Context { [FieldOffset(0)] public ulong raw; [FieldOffset(0)] public Guid key; }
    [StructLayout(LayoutKind.Sequential)] struct Filter {
        public Guid key; public Display display; public uint flags; public IntPtr provider;
        public Blob providerData; public Guid layer,subLayer; public Value weight;
        public uint count; public IntPtr conditions; public Action action; public Context context;
        public IntPtr reserved; public ulong id; public Value effectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)] struct Layer {
        public Guid key; public Display display; public uint flags; public IntPtr provider;
        public Blob providerData; public ushort weight;
    }
    [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine,ref Layer layer,IntPtr security);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine,ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine,ref Filter filter,IntPtr security,out ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr engine,ref Guid key,out IntPtr filter);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine,ref Guid key);
    [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string file,out IntPtr blob);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint size);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerGetByKey0(IntPtr engine,ref Guid key,out IntPtr layer);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerGetSecurityInfoByKey0(IntPtr engine,ref Guid key,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    static void Check(uint code) { if (code != 0) throw new Win32Exception(unchecked((int)code)); }
    static Guid Key(string file,string kind) {
        byte[] bytes; using (var hash=SHA256.Create()) bytes=hash.ComputeHash(Encoding.UTF8.GetBytes(Owner+"\n"+file.ToLowerInvariant()+"\n"+kind));
        byte[] key = new byte[16]; Array.Copy(bytes,key,16); return new Guid(key);
    }
    static Condition Identity(IntPtr app) { return new Condition { key=AppId,match=0,value=new Value { type=12,pointer=app } }; }
    static void DeleteOwned(IntPtr engine,Guid key) {
        IntPtr found=IntPtr.Zero; uint code=FwpmFilterGetByKey0(engine,ref key,out found);
        if (code==NotFound) return; Check(code);
        try {
            var filter=(Filter)Marshal.PtrToStructure(found,typeof(Filter));
            if (filter.subLayer!=SubLayer || filter.action.type!=0x1001 || filter.display.description!=Owner) throw new InvalidDataException();
        } finally { if (found!=IntPtr.Zero) FwpmFreeMemory0(ref found); }
        Check(FwpmFilterDeleteByKey0(engine,ref key));
    }
    static void Add(IntPtr engine,string file,string kind,Guid layer,params Condition[] conditions) {
        int size=Marshal.SizeOf(typeof(Condition)); IntPtr buffer=Marshal.AllocHGlobal(size*conditions.Length);
        try {
            for(int i=0;i<conditions.Length;i++) Marshal.StructureToPtr(conditions[i],IntPtr.Add(buffer,size*i),false);
            var filter=new Filter { key=Key(file,kind),display=new Display { name="Claude Proxy Guard original: "+kind,description=Owner },flags=1,layer=layer,subLayer=SubLayer,
                weight=new Value { type=1,scalar=15 },count=(uint)conditions.Length,conditions=buffer,action=new Action { type=0x1001 } };
            ulong id; Check(FwpmFilterAdd0(engine,ref filter,SecurityDescriptor,out id));
        } finally { Marshal.FreeHGlobal(buffer); }
    }
    static void Verify(IntPtr engine,string file,string kind,Guid layer) {
        Guid key=Key(file,kind); IntPtr found=IntPtr.Zero,app=IntPtr.Zero;
        try {
            Check(FwpmFilterGetByKey0(engine,ref key,out found));
            var f=(Filter)Marshal.PtrToStructure(found,typeof(Filter));
            if(f.subLayer!=SubLayer || f.layer!=layer || f.action.type!=0x1001 || f.display.description!=Owner || (f.flags&1)==0 || (f.flags&0x20)!=0 || f.count!=1) throw new InvalidDataException("deny-filter-mismatch");
            var c=(Condition)Marshal.PtrToStructure(f.conditions,typeof(Condition));
            if(c.key!=AppId || c.match!=0 || c.value.type!=12) throw new InvalidDataException("deny-identity-mismatch");
            Check(FwpmGetAppIdFromFileName0(file,out app));
            var expected=(Blob)Marshal.PtrToStructure(app,typeof(Blob));
            var actual=(Blob)Marshal.PtrToStructure(c.value.pointer,typeof(Blob));
            if(actual.size!=expected.size || actual.size>65536) throw new InvalidDataException("deny-path-mismatch");
            for(int i=0;i<(int)actual.size;i++) if(Marshal.ReadByte(actual.data,i)!=Marshal.ReadByte(expected.data,i)) throw new InvalidDataException("deny-path-mismatch");
        } finally {if(found!=IntPtr.Zero)FwpmFreeMemory0(ref found);if(app!=IntPtr.Zero)FwpmFreeMemory0(ref app);}
    }
    static void VerifySubLayer(IntPtr engine) {
        Guid key=SubLayer;IntPtr found=IntPtr.Zero,descriptor=IntPtr.Zero,owner,group,dacl,sacl;
        try{
            Check(FwpmSubLayerGetByKey0(engine,ref key,out found));
            var layer=(Layer)Marshal.PtrToStructure(found,typeof(Layer));
            // BFE may assign the nearest available weight when 65535 is occupied.
            if(layer.display.description!=Owner || (layer.flags&1)==0 || layer.weight==0)throw new InvalidDataException("deny-sublayer-mismatch");
            Check(FwpmSubLayerGetSecurityInfoByKey0(engine,ref key,5,out owner,out group,out dacl,out sacl,out descriptor));
            uint length=GetSecurityDescriptorLength(descriptor);if(length==0 || length>65536)throw new InvalidDataException();
            byte[] bytes=new byte[(int)length];Marshal.Copy(descriptor,bytes,0,bytes.Length);var security=new RawSecurityDescriptor(bytes,0);
            var admins=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);var system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
            if(!admins.Equals(security.Owner) || (security.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 || security.DiscretionaryAcl==null || security.DiscretionaryAcl.Count!=2)throw new InvalidDataException("deny-sublayer-security");
            bool hasAdmins=false,hasSystem=false;
            foreach(GenericAce entry in security.DiscretionaryAcl){var ace=entry as CommonAce;if(ace==null || ace.IsCallback || ace.AceQualifier!=AceQualifier.AccessAllowed || ace.AceFlags!=AceFlags.None)throw new InvalidDataException("deny-sublayer-security");if(admins.Equals(ace.SecurityIdentifier))hasAdmins=true;else if(system.Equals(ace.SecurityIdentifier))hasSystem=true;else throw new InvalidDataException("deny-sublayer-security");}
            if(!hasAdmins || !hasSystem)throw new InvalidDataException("deny-sublayer-security");
        }finally{if(found!=IntPtr.Zero)FwpmFreeMemory0(ref found);if(descriptor!=IntPtr.Zero)FwpmFreeMemory0(ref descriptor);}
    }
    public static int Apply(string[] supplied,string mode) {lock(ApplyLock){return ApplyCore(supplied,mode);}}
    static int ApplyCore(string[] supplied,string mode) {
        if(IntPtr.Size!=8 || !new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))throw new UnauthorizedAccessException();
        if(mode!="Install" && mode!="Verify" && mode!="Remove")throw new ArgumentException();
        if(supplied==null || supplied.Length==0 || supplied.Length>512)throw new ArgumentException();
        var files=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(string file in supplied){
            if(String.IsNullOrEmpty(file) || file.Length>1024 || file.IndexOfAny(new char[]{'\0','\r','\n'})>=0 || !Path.IsPathRooted(file) || file.StartsWith(@"\\") || !String.Equals(Path.GetExtension(file),".exe",StringComparison.OrdinalIgnoreCase))throw new ArgumentException();
            string full=Path.GetFullPath(file);if(!String.Equals(full,file,StringComparison.OrdinalIgnoreCase))throw new ArgumentException();files.Add(full);
        }
        IntPtr engine=IntPtr.Zero;bool transaction=false;
        try{
            uint size;if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)",1,out SecurityDescriptor,out size))throw new Win32Exception(Marshal.GetLastWin32Error());
            Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine));
            Guid[] layers={Connect4,Connect6,Accept4,Accept6};
            if(mode!="Verify"){
                Check(FwpmTransactionBegin0(engine,0));transaction=true;
                if(mode=="Install"){
                    var sub=new Layer{key=SubLayer,display=new Display{name="Guard original Claude deny",description=Owner},flags=1,weight=65535};
                    uint status=FwpmSubLayerAdd0(engine,ref sub,SecurityDescriptor);if(status!=AlreadyExists)Check(status);else VerifySubLayer(engine);
                }
                foreach(string file in files){
                    IntPtr app=IntPtr.Zero;
                    try{
                        if(mode=="Install")Check(FwpmGetAppIdFromFileName0(file,out app));
                        for(int i=0;i<4;i++){DeleteOwned(engine,Key(file,Kinds[i]));if(mode=="Install")Add(engine,file,Kinds[i],layers[i],Identity(app));}
                    }finally{if(app!=IntPtr.Zero)FwpmFreeMemory0(ref app);}
                }
                Check(FwpmTransactionCommit0(engine));transaction=false;
            }
            if(mode!="Remove")VerifySubLayer(engine);
            if(mode!="Remove")foreach(string file in files)for(int i=0;i<4;i++)Verify(engine,file,Kinds[i],layers[i]);
            return files.Count*4;
        }finally{if(transaction)FwpmTransactionAbort0(engine);if(engine!=IntPtr.Zero)FwpmEngineClose0(engine);if(SecurityDescriptor!=IntPtr.Zero){LocalFree(SecurityDescriptor);SecurityDescriptor=IntPtr.Zero;}}
    }
}
