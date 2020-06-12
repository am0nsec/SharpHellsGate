using System;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;

using Structures = SharpHellsGate.Win32.Structures;

namespace SharpHellsGate {
    public class Generic {
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

        public static void GetVxTableEntry(ref MemoryUtil MemUtil, ref VxTableEntry Entry, ref List<Structures.IMAGE_SECTION_HEADER> Sections, long PtrFunctions, long PtrNames, uint NumberOfNames) {
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

        public static long ConvertRvaToOffset(long rva, Structures.IMAGE_SECTION_HEADER SectionHeader)
            => rva - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData;

        public static long ConvertRvaToOffset(long rva, List<Structures.IMAGE_SECTION_HEADER> SectionHeaders)
            => ConvertRvaToOffset(rva, GetSectionByRVA(SectionHeaders, rva));

        public static Structures.IMAGE_SECTION_HEADER GetSectionByRVA(List<Structures.IMAGE_SECTION_HEADER> SectionHeaders, long rva)
            => SectionHeaders.Where(x => rva > x.VirtualAddress && rva <= x.VirtualAddress + x.SizeOfRawData).First();

        public static Structures.IMAGE_SECTION_HEADER GetSectionByName(List<Structures.IMAGE_SECTION_HEADER> SectionHeaders, string SectionName)
            => SectionHeaders.Where(x => x.Name.Equals(SectionName)).First();

        public static long GetSectionOffset(UInt32 e_lfanew, int SizeOfOptionalHeader, int cx)
            => e_lfanew
            + Marshal.SizeOf<Structures.IMAGE_FILE_HEADER>()
            + SizeOfOptionalHeader
            + 4
            + (Marshal.SizeOf<Structures.IMAGE_SECTION_HEADER>() * cx);

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
            Trace.Write(new String(' ', indent));

            // Color and prefix
            Trace.Write(prefix);
            Console.ForegroundColor = color;
            Console.Write(prefix);
            Console.ResetColor();

            // Message
            Console.WriteLine($" {msg}");
            Trace.WriteLine($" {msg}");
        }
    }
}
