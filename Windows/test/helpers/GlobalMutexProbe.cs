using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

internal static class GlobalMutexProbe {
    const string Name = @"Global\ClaudeProxyGuard.Management.v1";
    const uint Needed = 0x100001;
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int length; public IntPtr descriptor; public int inherit; }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateMutex(ref SecurityAttributes attributes, bool initialOwner, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenMutex(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReleaseMutex(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    static int Error(string stage) {
        int code = Marshal.GetLastWin32Error();
        Console.WriteLine("{\"stage\":\"" + stage + "\",\"win32\":" + code + "}");
        return code;
    }
    public static int Main(string[] args) {
        IntPtr handle = IntPtr.Zero, descriptor = IntPtr.Zero;
        try {
            handle = OpenMutex(Needed, false, Name);
            if (handle == IntPtr.Zero) {
                if (Marshal.GetLastWin32Error() != 2) return Error("open");
                uint size;
                if (!ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100001;;;AU)", 1, out descriptor, out size)) return Error("sddl");
                var attributes = new SecurityAttributes { length = Marshal.SizeOf(typeof(SecurityAttributes)), descriptor = descriptor, inherit = 0 };
                handle = CreateMutex(ref attributes, false, Name);
                if (handle == IntPtr.Zero && Marshal.GetLastWin32Error() == 5) handle = OpenMutex(Needed, false, Name);
                if (handle == IntPtr.Zero) return Error("create");
            }
            uint acquired = WaitForSingleObject(handle, 10000);
            if (acquired != 0 && acquired != 0x80) return acquired == 0x102 ? Error("timeout") : Error("wait");
            if (args.Length == 1 && args[0] == "--hold") Thread.Sleep(15000);
            if (!ReleaseMutex(handle)) return Error("release");
            Console.WriteLine("{\"stage\":\"acquire-release\",\"win32\":0}");
            return 0;
        } finally {
            if (handle != IntPtr.Zero) CloseHandle(handle);
            if (descriptor != IntPtr.Zero) LocalFree(descriptor);
        }
    }
}
