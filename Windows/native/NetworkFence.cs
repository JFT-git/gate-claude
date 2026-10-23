using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

// Elevated WFP policy broker. Claude is never launched by this process.
// BLOCK filters are persistent, deliberately NOT a dynamic WFP session: a
// broker/controller crash must leave the private executable paths fenced.
// This is a per-image-path fence, NOT a process-tree/AppContainer boundary.
// External child executables and RPC/service-based networking are outside its
// scope; callers must not describe it as complete inherited network isolation.
internal static class NetworkFence {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct ShellExecuteInfo {
        public uint size,mask; public IntPtr window;
        public string verb,file,parameters,directory; public int show;
        public IntPtr instance,idList; public string className;
        public IntPtr classKey; public uint hotKey; public IntPtr icon,process;
    }
    [DllImport("shell32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] static extern bool ShellExecuteEx(ref ShellExecuteInfo info);
    [DllImport("user32.dll")] [return:MarshalAs(UnmanagedType.Bool)] static extern bool IsWindow(IntPtr window);
    [DllImport("ole32.dll")] static extern int CoInitializeEx(IntPtr reserved,uint flags);
    [DllImport("ole32.dll")] static extern void CoUninitialize();

    // This branch runs with Guard's ordinary token. It requests consent only
    // for this exact broker image; it cannot launch a supplied image/command.
    // Windows owns the consent UI. Claude is never started from this branch.
    static int RequestElevation(string[] args) {
        int code=87; bool launched=false;
        try {
            if(IntPtr.Size!=8 || args.Length!=7 || args[1]!="--owner" || args[3]!="--pipe" || args[5]!="--token" ||
                !Regex.IsMatch(args[2],@"\A[0-9a-f]{1,16}\z") || !Regex.IsMatch(args[4],@"\Agate-network-fence-[a-f0-9]{32}\z") || !Regex.IsMatch(args[6],@"\A[a-f0-9]{64}\z")) throw new Win32Exception(87);
            ulong raw=Convert.ToUInt64(args[2],16);
            if(raw>Int64.MaxValue) throw new Win32Exception(87);
            IntPtr owner=new IntPtr((long)raw);
            if(owner!=IntPtr.Zero && !IsWindow(owner)) throw new Win32Exception(1400);
            string self=System.Reflection.Assembly.GetExecutingAssembly().Location;
            var info=new ShellExecuteInfo { size=(uint)Marshal.SizeOf(typeof(ShellExecuteInfo)),
                // NOCLOSEPROCESS | NOASYNC | FLAG_NO_UI: errors are reported
                // below; the real secure-desktop consent prompt is not hidden.
                mask=0x00000540,window=owner,verb="runas",file=self,
                // Hide only the broker's console, never the Windows consent UI.
                parameters="--pipe "+args[4]+" --token "+args[6],directory=Path.GetDirectoryName(self),show=0 };
            bool comReady=false;
            try {
                if(CoInitializeEx(IntPtr.Zero,0x6)<0) throw new Win32Exception(31);
                comReady=true;
                if(!ShellExecuteEx(ref info)) throw new Win32Exception(Marshal.GetLastWin32Error());
                if(info.process==IntPtr.Zero) throw new Win32Exception(31);
                launched=true;code=0;
            } finally { if(info.process!=IntPtr.Zero) CloseHandle(info.process); if(comReady)CoUninitialize(); }
        } catch(Win32Exception error) { code=error.NativeErrorCode; if(code<=0 || code>65535)code=31; }
        catch { code=31; }
        Console.WriteLine("{\"version\":1,\"launched\":"+(launched?"true":"false")+",\"code\":"+code+"}");
        return 0;
    }
    const uint NotFound = 0x80320003, AlreadyExists = 0x80320009;
    const string Owner = "gate-claude-network-fence-v1";
    static IntPtr SecurityDescriptor=IntPtr.Zero;
    static readonly Guid SubLayer = new Guid("a780b549-2ce9-4e1b-a7bd-e4a08e163675");
    static readonly Guid Connect4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    static readonly Guid Connect6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    static readonly Guid Accept4 = new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    static readonly Guid Accept6 = new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");
    static readonly Guid AppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
    static readonly Guid Protocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
    static readonly Guid RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    static readonly Guid RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    static readonly string[] Kinds = { "out-nontcp", "out-address", "out-port", "out-v6", "in-v4", "in-v6" };

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
    [StructLayout(LayoutKind.Sequential)] struct FileInformation {
        public uint attributes,createdLow,createdHigh,accessLow,accessHigh,writtenLow,writtenHigh,volume,sizeHigh,sizeLow,links,indexHigh,indexLow;
    }
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {
        public int length; public IntPtr descriptor; public int inherit;
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
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr process,uint flags,StringBuilder file,ref uint size);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateMutex(ref SecurityAttributes attributes,bool initialOwner,string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReleaseMutex(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr handle,out FileInformation information);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint size);

    static void Check(uint code) { if (code != 0) throw new Win32Exception(unchecked((int)code)); }
    static Guid Key(string file,string kind) {
        byte[] bytes; using (var hash=SHA256.Create()) bytes=hash.ComputeHash(Encoding.UTF8.GetBytes(Owner+"\n"+file.ToLowerInvariant()+"\n"+kind));
        byte[] key = new byte[16]; Array.Copy(bytes,key,16); return new Guid(key);
    }
    static string MutexName(string root) {
        byte[] bytes; using(var hash=SHA256.Create()) bytes=hash.ComputeHash(Encoding.UTF8.GetBytes(root.ToLowerInvariant()));
        return @"Global\gate-claude-fence-"+BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant();
    }
    static bool Under(string root,string file) { return file.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase); }
    static string LocalPath(string value) {
        if (String.IsNullOrEmpty(value) || value.Length > 240 || !Regex.IsMatch(value,@"^[A-Za-z]:\\") || value.IndexOfAny(new char[] {'\0','\r','\n','\t'}) >= 0 || value.IndexOf(':',2)>=0) throw new InvalidDataException();
        string full=Path.GetFullPath(value).TrimEnd(Path.DirectorySeparatorChar);
        if (!String.Equals(value,full,StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
        string cursor=full;
        while (!String.IsNullOrEmpty(cursor) && cursor.Length>3) {
            if ((File.GetAttributes(cursor)&FileAttributes.ReparsePoint)!=0) throw new InvalidDataException();
            cursor=Path.GetDirectoryName(cursor);
        }
        return full;
    }
    static void Walk(string root,string dir,List<string> result) {
        foreach (string entry in Directory.GetFileSystemEntries(dir)) {
            if ((File.GetAttributes(entry)&FileAttributes.ReparsePoint)!=0) throw new InvalidDataException();
            if (Directory.Exists(entry)) Walk(root,entry,result);
            else if (String.Equals(Path.GetExtension(entry),".exe",StringComparison.OrdinalIgnoreCase)) {
                string file=LocalPath(entry);
                if (!Under(root,file) || new FileInfo(file).Length<16 || result.Count>=512) throw new InvalidDataException();
                using(var opened=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)) {
                    FileInformation information;
                    if(!GetFileInformationByHandle(opened.SafeFileHandle.DangerousGetHandle(),out information) || information.links!=1) throw new InvalidDataException();
                }
                result.Add(file);
            }
        }
    }
    static List<string> Validate(string root,string[] supplied) {
        root=LocalPath(root);
        if (!Regex.IsMatch(Path.GetFileName(root),@"^Runtime-[a-f0-9]{24}$") || !File.Exists(Path.Combine(root,"guard-manifest.json")) || !File.Exists(Path.Combine(root,"Claude.exe"))) throw new InvalidDataException();
        var actual=new List<string>(); Walk(root,root,actual); actual.Sort(StringComparer.OrdinalIgnoreCase);
        var expected=new List<string>(); foreach (string value in supplied) {
            string file=LocalPath(value); if (!Under(root,file) || !String.Equals(Path.GetExtension(file),".exe",StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException(); expected.Add(file);
        }
        expected.Sort(StringComparer.OrdinalIgnoreCase);
        if (expected.Count!=actual.Count || actual.Count==0) throw new InvalidDataException();
        for (int i=0;i<actual.Count;i++) if (!String.Equals(actual[i],expected[i],StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
        return actual;
    }
    static bool NoProcesses(List<string> files) {
        var full=new HashSet<string>(files,StringComparer.OrdinalIgnoreCase);
        var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(string file in files) names.Add(Path.GetFileNameWithoutExtension(file));
        foreach (Process process in Process.GetProcesses()) using(process) {
            try {
                if (!names.Contains(process.ProcessName)) continue;
                IntPtr handle=OpenProcess(0x1000,false,process.Id);
                if (handle==IntPtr.Zero) { if (Marshal.GetLastWin32Error()==87) continue; return false; }
                try {
                    uint length=32768; var image=new StringBuilder((int)length);
                    if (!QueryFullProcessImageName(handle,0,image,ref length)) return false;
                    if (full.Contains(Path.GetFullPath(image.ToString()))) return false;
                } finally { CloseHandle(handle); }
            } catch (InvalidOperationException) { /* Process exited during snapshot. */ }
            catch (ArgumentException) { /* Process exited during snapshot. */ }
            catch { return false; }
        }
        return true;
    }
    static Condition Identity(IntPtr app) { return new Condition { key=AppId,match=0,value=new Value { type=12,pointer=app } }; }
    static Condition Different(Guid key,uint type,ulong value) { return new Condition { key=key,match=10,value=new Value { type=type,scalar=value } }; }
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
            var filter=new Filter { key=Key(file,kind),display=new Display { name="Claude Proxy Guard: "+kind,description=Owner },flags=1,layer=layer,subLayer=SubLayer,
                weight=new Value { type=1,scalar=15 },count=(uint)conditions.Length,conditions=buffer,action=new Action { type=0x1001 } };
            ulong id; Check(FwpmFilterAdd0(engine,ref filter,SecurityDescriptor,out id));
        } finally { Marshal.FreeHGlobal(buffer); }
    }
    static void Install(IntPtr engine,List<string> files,ushort port) {
        if (!NoProcesses(files)) throw new InvalidOperationException("runtime-active");
        Check(FwpmTransactionBegin0(engine,0)); bool committed=false;
        try {
            var layer=new Layer { key=SubLayer,display=new Display { name="Claude Proxy Guard private runtime",description=Owner },flags=1,weight=65535 };
            uint result=FwpmSubLayerAdd0(engine,ref layer,SecurityDescriptor); if (result!=AlreadyExists) Check(result);
            foreach(string file in files) foreach(string kind in Kinds) DeleteOwned(engine,Key(file,kind));
            foreach(string file in files) {
                IntPtr app=IntPtr.Zero; Check(FwpmGetAppIdFromFileName0(file,out app));
                try {
                    Condition who=Identity(app);
                    // De Morgan: block every member of the complement of the only
                    // permitted tuple, without a PERMIT overriding another firewall.
                    Add(engine,file,Kinds[0],Connect4,who,Different(Protocol,1,6));
                    Add(engine,file,Kinds[1],Connect4,who,Different(RemoteAddress,3,0x7f000001));
                    Add(engine,file,Kinds[2],Connect4,who,Different(RemotePort,2,port));
                    Add(engine,file,Kinds[3],Connect6,who);
                    // Incoming flows must not create a reply path to another peer.
                    Add(engine,file,Kinds[4],Accept4,who);
                    Add(engine,file,Kinds[5],Accept6,who);
                } finally { if(app!=IntPtr.Zero) FwpmFreeMemory0(ref app); }
            }
            Check(FwpmTransactionCommit0(engine)); committed=true;
        } finally { if(!committed) FwpmTransactionAbort0(engine); }
    }
    static bool Remove(IntPtr engine,List<string> files) {
        // GuardHost must already have closed its job. Independent image checks
        // reject premature cleanup; uncertainty always leaves BLOCK installed.
        bool stopped=false;
        for(int i=0;i<50;i++) { if(NoProcesses(files)) { stopped=true; break; } Thread.Sleep(100); }
        if(!stopped) return false;
        Check(FwpmTransactionBegin0(engine,0)); bool committed=false;
        try {
            foreach(string file in files) foreach(string kind in Kinds) DeleteOwned(engine,Key(file,kind));
            Guid subLayer=SubLayer; uint removedLayer=FwpmSubLayerDeleteByKey0(engine,ref subLayer);
            // Another fenced runtime can legitimately share our metadata layer.
            if(removedLayer!=0x8032000A && removedLayer!=0x80320007) Check(removedLayer);
            Check(FwpmTransactionCommit0(engine)); committed=true; return true;
        } finally { if(!committed) FwpmTransactionAbort0(engine); }
    }
    static string ReadLine(StreamReader reader) {
        var text=new StringBuilder(); int c;
        while((c=reader.Read())!=-1) { if(c=='\n') return text.ToString().TrimEnd('\r'); if(text.Length>=262144) throw new InvalidDataException(); text.Append((char)c); }
        return text.Length==0 ? null : text.ToString();
    }
    [STAThread] public static int Main(string[] args) {
        if(args.Length>0 && args[0]=="--request-elevation") return RequestElevation(args);
        IntPtr engine=IntPtr.Zero,mutex=IntPtr.Zero; bool ownsMutex=false;
        CodeFenceSession codeSession=null;
        try {
            if(IntPtr.Size!=8 || args.Length!=4 || args[0]!="--pipe" || args[2]!="--token" || !Regex.IsMatch(args[1],@"^gate-network-fence-[a-f0-9]{32}$") || !Regex.IsMatch(args[3],@"^[a-f0-9]{64}$")) return 64;
            if(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return 5;
            // The standard user's SID must not own these objects: object owners
            // can rewrite a DACL even without an explicit allow ACE. Both owner
            // and protected DACL therefore belong to privileged principals.
            uint descriptorSize;
            if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)",1,out SecurityDescriptor,out descriptorSize)) throw new Win32Exception(Marshal.GetLastWin32Error());
            using(var pipe=new NamedPipeClientStream(".",args[1],PipeDirection.InOut,PipeOptions.None)) {
                pipe.Connect(120000);
                using(var reader=new StreamReader(pipe,new UTF8Encoding(false,true),false,4096,true))
                using(var writer=new StreamWriter(pipe,new UTF8Encoding(false),4096,true) { AutoFlush=true }) {
                    writer.WriteLine("{\"type\":\"hello\",\"version\":1,\"token\":\""+args[3]+"\"}");
                    try {
                        string request=ReadLine(reader); if(request==null) return 1;
                        string[] parts=request.Split('\t'); ushort port;
                        if((parts.Length!=4 && parts.Length!=7) || parts[0]!="install" || !UInt16.TryParse(parts[2],out port) || port==0) throw new InvalidDataException();
                        string root=Encoding.UTF8.GetString(Convert.FromBase64String(parts[1]));
                        string[] supplied=Encoding.UTF8.GetString(Convert.FromBase64String(parts[3])).Split('\n');
                        List<string> files=Validate(root,supplied);
                        // Deterministic filter keys are shared across recoveries.
                        // Hold one OS lock for the entire broker lifetime, including
                        // normal removal and crash cleanup, so an old broker cannot
                        // delete a newer session's rules between install and spawn.
                        var attributes=new SecurityAttributes { length=Marshal.SizeOf(typeof(SecurityAttributes)),descriptor=SecurityDescriptor,inherit=0 };
                        mutex=CreateMutex(ref attributes,false,MutexName(LocalPath(root)));
                        if(mutex==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                        uint acquired=WaitForSingleObject(mutex,120000);
                        if(acquired==0 || acquired==0x80) ownsMutex=true;
                        else if(acquired==0x102) throw new TimeoutException();
                        else throw new Win32Exception(Marshal.GetLastWin32Error());
                        // WAIT_ABANDONED grants ownership, but does not establish
                        // that the previous runtime exited. Install still checks
                        // all protected images before atomically replacing BLOCK.
                        Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine));
                        Install(engine,files,port);
                        if(parts.Length==7) {
                            // Derive package identity and controller SID natively.
                            var strictUtf8=new UTF8Encoding(false,true);
                            string containerName=strictUtf8.GetString(Convert.FromBase64String(parts[4]));
                            string codeJobName=strictUtf8.GetString(Convert.FromBase64String(parts[5]));
                            string relayImage=strictUtf8.GetString(Convert.FromBase64String(parts[6]));
                            codeSession=CodeFenceSession.Open(pipe,containerName,codeJobName,relayImage,port);
                        }
                        writer.WriteLine("{\"type\":\"installed\",\"version\":1,\"paths\":"+files.Count+",\"filters\":"+(files.Count*6)+",\"persistent\":true,\"coverage\":\"private-runtime-executables\""+(codeSession==null?"":",\"code\":"+codeSession.ProofJson())+"}");
                        string command=ReadLine(reader);
                        if(command!="remove-after-job-exit") return 0; // EOF/crash => retain filters.
                        if(codeSession!=null)codeSession.CloseAndRetire();
                        bool removed=Remove(engine,files);
                        writer.WriteLine("{\"type\":\"removed\",\"removed\":"+(removed ? "true" : "false")+"}");
                        return removed ? 0 : 2;
                    } catch(Exception error) {
                        // Paths, arguments, account information and network payloads
                        // are intentionally absent from privilege-broker diagnostics.
                        writer.WriteLine("{\"type\":\"error\",\"kind\":\""+error.GetType().Name+"\",\"code\":"+(error is Win32Exception ? ((Win32Exception)error).NativeErrorCode : 0)+"}");
                        return 1;
                    }
                }
            }
        } catch { return 1; }
        finally {
            if(codeSession!=null)codeSession.Dispose();
            if(engine!=IntPtr.Zero) FwpmEngineClose0(engine);
            if(ownsMutex) ReleaseMutex(mutex);
            if(mutex!=IntPtr.Zero) CloseHandle(mutex);
            if(SecurityDescriptor!=IntPtr.Zero) LocalFree(SecurityDescriptor);
        }
    }
}
