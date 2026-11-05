using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

internal static class GuardFreezeCanary {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    static void Counter(string path) {
        long value = 0,churnValue = 0;
        var churn = new Thread(() => {
            while (true) {
                var worker = new Thread(() => {});
                worker.Start(); worker.Join(10);
                File.WriteAllText(path + ".churn",Interlocked.Increment(ref churnValue).ToString(CultureInfo.InvariantCulture));
                Thread.Sleep(5);
            }
        });
        churn.IsBackground = true; churn.Start();
        while (true) {
            string temp = path + ".tmp";
            File.WriteAllText(temp,value.ToString(CultureInfo.InvariantCulture));
            File.Copy(temp,path,true);
            value++; Thread.Sleep(40);
        }
    }
    static Process Start(string output,string mode) {
        var start = new ProcessStartInfo {
            FileName = Process.GetCurrentProcess().MainModule.FileName,
            Arguments = "\"" + output.Replace("\"","\\\"") + "\" " + mode,
            UseShellExecute = false, CreateNoWindow = true
        };
        return Process.Start(start);
    }
    public static int Main(string[] args) {
        if (args.Length == 2 && (args[1] == "child" || args[1] == "nested")) { Counter(args[0] + "." + args[1]); return 0; }
        if (args.Length != 1) return 64;
        IntPtr nestedJob = IntPtr.Zero;
        try {
            var child = Start(args[0],"child");
            var nested = Start(args[0],"nested");
            nestedJob = CreateJobObject(IntPtr.Zero,null);
            if (nestedJob == IntPtr.Zero || !AssignProcessToJobObject(nestedJob,nested.Handle)) return 70;
            string manifest = "{\"root\":" + Process.GetCurrentProcess().Id + ",\"leaf\":" + child.Id + ",\"nested\":" + nested.Id + "}";
            File.WriteAllText(args[0] + ".tmp",manifest); File.Copy(args[0] + ".tmp",args[0],true);
            Counter(args[0] + ".root"); return 0;
        } finally { if (nestedJob != IntPtr.Zero) CloseHandle(nestedJob); }
    }
}
