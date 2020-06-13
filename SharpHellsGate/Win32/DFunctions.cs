using System;
using System.Runtime.InteropServices;

namespace SharpHellsGate.Win32 {
    public class DFunctions {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtCreateMutant(
            ref IntPtr handle,
            UInt32 DesiredAccess,
            IntPtr ObjectAtytribute,
            bool owner
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            UInt32 AllocationType,
            UInt32 Protect
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            UInt32 NewProtect,
            out UInt32 OldProtect
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtCreateThreadEx(
            ref IntPtr hThread,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            uint StackZeroBits,
            uint SizeOfStackCommit,
            uint SizeOfStackReserve,
            IntPtr lpBytesBuffer
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWaitForSingleObject(
            IntPtr ObjectHandle,
            bool Alertable,
            ref Structures.LARGE_INTEGER TimeOut
        );
    }
}
