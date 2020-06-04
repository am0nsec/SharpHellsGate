using System;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SharpHellsGate {
    public class Generic {

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

        public static int ConvertRvaToOffset(int rva, Win32.IMAGE_SECTION_HEADER SectionHeader)
            => rva - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData;

        public static int ConvertRvaToOffset(int rva, in List<Win32.IMAGE_SECTION_HEADER> SectionHeaders)
            => ConvertRvaToOffset(rva, GetSectionByRVA(SectionHeaders, rva));

        public static Win32.IMAGE_SECTION_HEADER GetSectionByRVA(List<Win32.IMAGE_SECTION_HEADER> SectionHeaders, int rva)
            => SectionHeaders.Where(x => rva > x.VirtualAddress && rva <= x.VirtualAddress + x.SizeOfRawData).First();

        public static Win32.IMAGE_SECTION_HEADER GetSectionByName(in List<Win32.IMAGE_SECTION_HEADER> SectionHeaders, string SectionName)
            => SectionHeaders.Where(x => x.Name.Equals(SectionName)).First();

        public static int GetSectionOffset(in int e_lfanew, in int SizeOfOptionalHeader, in int cx)
            => e_lfanew 
            + Marshal.SizeOf<Win32.IMAGE_FILE_HEADER>() 
            + SizeOfOptionalHeader 
            + 4 
            + (Marshal.SizeOf<Win32.IMAGE_SECTION_HEADER>() * cx);
    }
}
