using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Xml;

namespace SharpHellsGate {
    class Program {

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
            byte[] bModuleBlob = File.ReadAllBytes(Environment.SystemDirectory + "\\ntdll.dll");
            MemoryUtil MemUtil = new MemoryUtil(bModuleBlob);

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
            List<Win32.IMAGE_SECTION_HEADER> ImageSectionHeaders = new List<Win32.IMAGE_SECTION_HEADER>(ImageNTHeaders.FileHeader.NumberOfSections);
            for (int cx = 0; cx < ImageNTHeaders.FileHeader.NumberOfSections; cx++) {
                int iSectionOffset = Generic.GetSectionOffset(ImageDOSHeader.e_lfanew, ImageNTHeaders.FileHeader.SizeOfOptionalHeader, cx);
                
                Win32.IMAGE_SECTION_HEADER ImageSection = MemUtil.GetStructureFromBlob<Win32.IMAGE_SECTION_HEADER>(iSectionOffset);
                if (!ImageSection.Equals(default(Win32.IMAGE_SECTION_HEADER))) {
                    ImageSectionHeaders.Add(ImageSection);
                }
            }

            Console.ReadKey();
        }
    }
}
