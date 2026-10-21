// No-auth fixture. All endpoints are independent loopback receivers supplied by
// the test. This executable and the real PowerShell child run with the same token.
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
internal static class CodeSocketCanary {
    static int[] Ports;
    static string Output;
    static TcpClient Held;
    static NetworkStream HeldStream;
    static bool Tcp(string host,int port,bool proxy){
        using(var client=new TcpClient(host.IndexOf(':')>=0?AddressFamily.InterNetworkV6:AddressFamily.InterNetwork))try{
            if(client.Client.AddressFamily==AddressFamily.InterNetworkV6)client.Client.DualMode=true;
            client.Client.SendTimeout=700;client.Client.ReceiveTimeout=700;client.Connect(IPAddress.Parse(host),port);if(!client.Connected)return false;
            var stream=client.GetStream();stream.ReadTimeout=700;stream.WriteTimeout=700;
            byte[] request=Encoding.ASCII.GetBytes(proxy?"CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n":"probe");
            stream.Write(request,0,request.Length);byte[] answer=new byte[256];int n=0,needed=proxy?Encoding.ASCII.GetByteCount("HTTP/1.1 200 Connection Established\r\n\r\nfixture"):1;while(n<needed){int read=stream.Read(answer,n,answer.Length-n);if(read<=0)return false;n+=read;}
            return proxy?Encoding.ASCII.GetString(answer,0,n).StartsWith("HTTP/1.1 200 Connection Established\r\n\r\nfixture",StringComparison.Ordinal):n>0;
        }catch{return false;}
    }
    static void Udp(AddressFamily family,string host,int port,byte[] bytes){
        using(var client=new UdpClient(family))try{client.Send(bytes,bytes.Length,new IPEndPoint(IPAddress.Parse(host),port));}catch{}
    }
    static string Bool(bool value){return value?"true":"false";}
    static string Matrix(){
        File.WriteAllText(Output+".stage","tcp-relay-before");bool relay=Tcp("127.0.0.1",Ports[0],true);File.WriteAllText(Output+".stage","tcp-relay-after");bool other4=Tcp("127.0.0.1",Ports[1],false);File.WriteAllText(Output+".stage","tcp4-after");bool other6=Tcp("::1",Ports[2],false);File.WriteAllText(Output+".stage","tcp6-after");bool mapped=Tcp("::ffff:127.0.0.1",Ports[1],false);File.WriteAllText(Output+".stage","mapped-after");
        byte[] payload=Encoding.ASCII.GetBytes("fixture-datagram");
        for(int i=0;i<3;i++){Udp(AddressFamily.InterNetwork,"127.0.0.1",Ports[3],payload);Udp(AddressFamily.InterNetworkV6,"::1",Ports[4],payload);}
        // Exact synthetic DNS query to a counted fixture, not the OS DNS service.
        // System DNS attribution is a separate production integration assertion.
        byte[] dns={0x47,0x43,1,0,0,1,0,0,0,0,0,0,7,102,105,120,116,117,114,101,7,105,110,118,97,108,105,100,0,0,1,0,1};
        Udp(AddressFamily.InterNetwork,"127.0.0.1",Ports[5],dns);Thread.Sleep(100);
        return "{\"relay\":"+Bool(relay)+",\"other4\":"+Bool(other4)+",\"other6\":"+Bool(other6)+",\"mapped\":"+Bool(mapped)+"}";
    }
    static Process PowerShell(out string result){
        string script="$ErrorActionPreference='Stop';function T([string]$h,[int]$p,[bool]$proxy){$af=if($h.Contains(':')){[System.Net.Sockets.AddressFamily]::InterNetworkV6}else{[System.Net.Sockets.AddressFamily]::InterNetwork};$c=[System.Net.Sockets.TcpClient]::new($af);try{$c.Connect([System.Net.IPAddress]::Parse($h),$p);if(!$c.Connected){return $false};$s=$c.GetStream();$s.ReadTimeout=700;$txt=if($proxy){\"CONNECT fixture.invalid:443 HTTP/1.1`r`nHost: fixture.invalid:443`r`n`r`n\"}else{'probe'};$b=[System.Text.Encoding]::ASCII.GetBytes($txt);$s.Write($b,0,$b.Length);$b=New-Object byte[] 256;$n=$s.Read($b,0,$b.Length);if($proxy){return [System.Text.Encoding]::ASCII.GetString($b,0,$n).StartsWith(\"HTTP/1.1 200 Connection Established`r`n`r`nfixture\")};return $n-gt 0}catch{return $false}finally{$c.Dispose()}};$r=@{relay=(T '127.0.0.1' "+Ports[0]+" $true);other4=(T '127.0.0.1' "+Ports[1]+" $false);other6=(T '::1' "+Ports[2]+" $false)};[Console]::WriteLine(($r|ConvertTo-Json -Compress));[Console]::Out.Flush();[System.Threading.Thread]::Sleep(30000)";
        var info=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),@"System32\WindowsPowerShell\v1.0\powershell.exe"),"-NoLogo -NoProfile -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
        info.UseShellExecute=false;info.CreateNoWindow=true;info.RedirectStandardOutput=true;info.RedirectStandardError=true;
        var child=Process.Start(info);result=child.StandardOutput.ReadLine();
        if(result==null||result.Length>256||result.IndexOf("\"relay\"",StringComparison.Ordinal)<0){result="{\"launchFailed\":true}";}
        return child;
    }
    static bool Hold(){
        try{Held=new TcpClient();Held.Connect(IPAddress.Loopback,Ports[0]);HeldStream=Held.GetStream();HeldStream.ReadTimeout=700;HeldStream.WriteTimeout=700;
            byte[] q=Encoding.ASCII.GetBytes("CONNECT keep.fixture.invalid:443 HTTP/1.1\r\nHost: keep.fixture.invalid:443\r\n\r\n");HeldStream.Write(q,0,q.Length);byte[] a=new byte[256];return HeldStream.Read(a,0,a.Length)>0;
        }catch{return false;}
    }
    static bool Tick(){try{byte[] q=Encoding.ASCII.GetBytes("tick");HeldStream.Write(q,0,q.Length);byte[] a=new byte[16];return HeldStream.Read(a,0,a.Length)>0;}catch{try{Held.Close();}catch{}return false;}}
    public static int Main(string[] args){
        try{
            if(args.Length!=8)return 2;Output=args[0];Ports=new int[6];for(int i=0;i<6;i++)Ports[i]=Int32.Parse(args[i+1]);
            File.WriteAllText(Output+".stage","native-start");string matrix=Matrix();
            if(args[7]=="baseline"){File.WriteAllText(Output,"{\"node\":"+matrix+"}");return 0;}
            string powershell;Process child=PowerShell(out powershell);bool held=Hold();
            File.WriteAllText(Output,"{\"node\":"+matrix+",\"powershell\":"+powershell+",\"held\":"+Bool(held)+"}");
            for(;;){
                if(held)held=Tick();
                if(File.Exists(Output+".seal")){
                    bool permitted=Tcp("127.0.0.1",Ports[0],true);
                    if(held)held=Tick();
                    File.WriteAllText(Output+".sealed","{\"relay\":"+Bool(permitted)+",\"heldClosed\":"+Bool(!held)+",\"childAlive\":"+Bool(!child.HasExited)+"}");
                }
                Thread.Sleep(50);
            }
        }catch(Exception error){try{File.WriteAllText(Output+".stage","native-error:"+error.GetType().Name);}catch{}return 3;}
    }
}
