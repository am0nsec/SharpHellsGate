using System;

namespace SharpHellsGate.Win32 {
    public static class Macros {

        // NTSTATUS 
        public static bool NT_SUCCESS(UInt32 ntstatus) => ntstatus <= 0x3FFFFFFF;
        public static bool NT_INFORMATION(UInt32 ntstatus) => ntstatus >= 0x40000000 && ntstatus <= 0x7FFFFFFF;
        public static bool NT_WARNING(UInt32 ntstatus) => ntstatus >= 0x80000000 && ntstatus <= 0xBFFFFFFF;
        public static bool NT_ERROR(UInt32 ntstatus) => ntstatus >= 0xC0000000 && ntstatus <= 0xFFFFFFFF;

        // Common NTSTATUS
        public static UInt32 S_OK { get; } = 0x00000000;

        // Portable Executable
        public static Int16 IMAGE_DOS_SIGNATURE { get; } = 0x5a00 | 0x4D;          // MZ
        public static Int32 IMAGE_NT_SIGNATURE { get; } = 0x00004500 | 0x00000050; // PE00

        // Pseudo-Handles
        public static UIntPtr GetCurrentProcess() => new UIntPtr(0xffffffffffffffff);
        public static UIntPtr GetCurrentThread() => new UIntPtr(0xfffffffffffffffe);
        public static UIntPtr GetCurrentProcessToken() => new UIntPtr(0xfffffffffffffffc);
        public static UIntPtr GetCurrentThreadToken() => new UIntPtr(0xfffffffffffffffb);
        public static UIntPtr GetCurrentThreadEffectiveToken() => new UIntPtr(0xfffffffffffffffa);
    }
}
