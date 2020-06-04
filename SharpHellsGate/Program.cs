using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SharpHellsGate {

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    public struct VxTableEntry {
        public ulong Hash;
        public byte Low;
        public byte high;
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
            int iRvaImageExportTable = ImageNTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress;
            ImageSection = GetSectionByRVA(ImageSectionHeaders, iRvaImageExportTable);
            long iOffsetImageExportDirectory = ConvertRvaToOffset(iRvaImageExportTable, ImageSection);

            Win32.IMAGE_EXPORT_DIRECTORY ImageExportDirectory = MemUtil.GetStructureFromBlob<Win32.IMAGE_EXPORT_DIRECTORY>(iOffsetImageExportDirectory);
            if (ImageExportDirectory.Equals(default(Win32.IMAGE_EXPORT_DIRECTORY))) {
                LogError("Invalid EAT.");
                return;
            }

            // Parse all functions
            long lPtrToFunctionNames = ConvertRvaToOffset(ImageExportDirectory.AddressOfNames, ImageSection);
            long lPtrToFunctions = ConvertRvaToOffset(ImageExportDirectory.AddressOfFunctions, ImageSection);
            long pPtrToFunctionNameOrdinals = ConvertRvaToOffset(ImageExportDirectory.AddressOfNameOrdinals, ImageSection);

            // Complete table
            VxTable Table = new VxTable();
            Table.NtAllocateVirtualMemory.Hash = 0xf5bd373480a6b89b;
            Table.NtCreateThreadEx.Hash = 0x64dc7db288c5015f;
            Table.NtProtectVirtualMemory.Hash = 0x858bcb1046fb6a37;
            Table.NtWaitForSingleObject.Hash = 0xc6a2fa174e551bcb;


            Console.WriteLine(String.Format("{0,-16}      {1}", "Hash", "Function Name"));
            for (int cx = 0; cx < ImageExportDirectory.NumberOfNames; cx++) {
                uint lPtrName = MemUtil.ReadPtr32(lPtrToFunctionNames + (sizeof(uint) * cx));
                string name = MemUtil.ReadAscii(ConvertRvaToOffset(lPtrName, ImageSection));

                Console.WriteLine(String.Format("0x{0,16}    {1}", Getdjb2Hash(name).ToString("x16"), name));
            }

#if DEBUG
            Console.ReadKey();
#endif
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

        public static ulong Getdjb2Hash(string FunctionName) {
            if (string.IsNullOrEmpty(FunctionName))
                return 0;

            ulong hash = 0x7734773477347734;
            foreach (char c in FunctionName)
                hash = ((hash << 0x5) + hash) + (byte)c;

            return hash;
        }
    }
}
