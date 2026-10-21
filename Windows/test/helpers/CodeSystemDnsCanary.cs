// Independent system-resolver fixture. Only synthetic names are accepted;
// addresses, network settings, credentials, and DNS cache entries are never logged.
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

internal static class CodeSystemDnsCanary {
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int type,IntPtr data,uint size,out uint needed);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertSidToStringSid(IntPtr sid,out IntPtr text);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    static IntPtr Info(IntPtr token,int type) {
        uint needed;GetTokenInformation(token,type,IntPtr.Zero,0,out needed);
        if(needed<4||needed>65536)throw new InvalidOperationException("token-size");
        IntPtr data=Marshal.AllocHGlobal((int)needed);
        if(!GetTokenInformation(token,type,data,needed,out needed)){Marshal.FreeHGlobal(data);throw new InvalidOperationException("token-query");}
        return data;
    }
    public static int Main(string[] args) {
        if(args.Length!=2||!Regex.IsMatch(args[1],"^gate-dns-[0-9a-f]{16}-(before|confined|after)\\.example\\.com\\.$"))return 2;
        IntPtr token=IntPtr.Zero,info=IntPtr.Zero,text=IntPtr.Zero;
        try {
            if(!OpenProcessToken(Process.GetCurrentProcess().Handle,8,out token))return 3;
            info=Info(token,29);bool ac=Marshal.ReadInt32(info)!=0;Marshal.FreeHGlobal(info);info=IntPtr.Zero;
            info=Info(token,30);int capabilities=Marshal.ReadInt32(info);Marshal.FreeHGlobal(info);info=IntPtr.Zero;
            string sid="null";
            if(ac){info=Info(token,31);if(!ConvertSidToStringSid(Marshal.ReadIntPtr(info),out text))return 4;sid="\""+Marshal.PtrToStringUni(text)+"\"";LocalFree(text);text=IntPtr.Zero;Marshal.FreeHGlobal(info);info=IntPtr.Zero;}
            string identity="\"pid\":"+Process.GetCurrentProcess().Id+",\"isAppContainer\":"+(ac?"true":"false")+",\"capabilityCount\":"+capabilities+",\"sid\":"+sid;
            File.WriteAllText(args[0]+".started","{"+identity+"}");
            int count=0,error=0;bool completed=false;var clock=Stopwatch.StartNew();
            try {
                IAsyncResult query=Dns.BeginGetHostAddresses(args[1],null,null);
                completed=query.AsyncWaitHandle.WaitOne(20000);
                if(completed)count=Dns.EndGetHostAddresses(query).Length;
            } catch(SocketException problem){completed=true;error=problem.ErrorCode;}
            File.WriteAllText(args[0],"{"+identity+",\"completed\":"+(completed?"true":"false")+",\"addressCount\":"+count+",\"socketError\":"+error+",\"elapsedMs\":"+clock.ElapsedMilliseconds+"}");
            return 0;
        }catch{return 5;}
        finally{if(text!=IntPtr.Zero)LocalFree(text);if(info!=IntPtr.Zero)Marshal.FreeHGlobal(info);if(token!=IntPtr.Zero)CloseHandle(token);}
    }
}
