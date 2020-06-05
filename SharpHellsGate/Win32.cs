using System.Runtime.InteropServices;

namespace SharpHellsGate {
    public static class Win32 {

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IMAGE_DOS_HEADER {
            public short e_magic;       /*+0x000*/
            public short e_cblp;        /*+0x002*/
            public short e_cp;          /*+0x004*/
            public short e_crlc;        /*+0x006*/
            public short e_cparhdr;     /*+0x008*/
            public short e_minalloc;    /*+0x00a*/
            public short e_maxalloc;    /*+0x00c*/
            public short e_ss;          /*+0x00e*/
            public short e_sp;          /*+0x010*/
            public short e_csum;        /*+0x012*/
            public short e_ip;          /*+0x014*/
            public short e_cs;          /*+0x016*/
            public short e_lfarlc;      /*+0x018*/
            public short e_ovno;        /*+0x01a*/
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public short[] e_res;       /*+0x01c*/
            public short e_oemid;       /*+0x024*/
            public short e_oeminfo;     /*+0x026*/
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public short[] e_res2;      /*+0x028*/
            public int e_lfanew;        /*+0x03c*/
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IMAGE_FILE_HEADER {
            public short Machine;               /*+0x000*/
            public short NumberOfSections;      /*+0x002*/
            public int TimeDateStamp;           /*+0x004*/
            public int PointerToSymbolTable;    /*+0x008*/
            public int NumberOfSymbols;         /*+0x00c*/
            public short SizeOfOptionalHeader;  /*+0x010*/
            public short Characteristics;       /*+0x012*/
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IMAGE_DATA_DIRECTORY {
            public int VirtualAddress;  /*+0x000*/
            public int Size;            /*+0x004*/
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IMAGE_OPTIONAL_HEADER64 {
            public short Magic;                             /*+0x000*/
            public byte MajorLinkerVersion;                 /*+0x002*/
            public byte MinorLinkerVersion;                 /*+0x003*/
            public int SizeOfCode;                          /*+0x004*/
            public int SizeOfInitializedDatal;              /*+0x008*/
            public int SizeOfUninitializedData;             /*+0x00c*/
            public int AddressOfEntryPoint;                 /*+0x010*/
            public int BaseOfCode;                          /*+0x014*/
            public long ImageBasel;                         /*+0x018*/
            public int SectionAlignment;                    /*+0x020*/
            public int FileAlignment;                       /*+0x024*/
            public short MajorOperatingSystemVersion;       /*+0x028*/
            public short MinorOperatingSystemVersion;       /*+0x02a*/
            public short MajorImageVersion;                 /*+0x02c*/
            public short MinorImageVersion;                 /*+0x02e*/
            public short MajorSubsystemVersion;             /*+0x030*/
            public short MinorSubsystemVersion;             /*+0x032*/
            public int Win32VersionValue;                   /*+0x034*/
            public int SizeOfImage;                         /*+0x038*/
            public int SizeOfHeaders;                       /*+0x03c*/
            public int CheckSum;                            /*+0x040*/
            public short Subsystem;                         /*+0x044*/
            public short DllCharacteristics;                /*+0x046*/
            public long SizeOfStackReserve;                 /*+0x048*/
            public long SizeOfStackCommit;                  /*+0x050*/
            public long SizeOfHeapReserve;                  /*+0x058*/
            public long SizeOfHeapCommit;                   /*+0x060*/
            public int LoaderFlags;                         /*+0x068*/
            public int NumberOfRvaAndSizes;                 /*+0x06c*/
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;    /*+0x070*/
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IMAGE_NT_HEADERS64 {
            public int Signature;                           /*+0x000*/
            public IMAGE_FILE_HEADER FileHeader;            /*+0x004*/
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;  /*+0x018*/
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IMAGE_EXPORT_DIRECTORY {
            public int Characteristics;         /*+0x000*/
            public int TimeDateStamp;           /*+0x004*/
            public short MajorVersion;          /*+0x008*/
            public short MinorVersion;          /*+0x00a*/
            public int Name;                    /*+0x00c*/
            public int Base;                    /*+0x010*/
            public int NumberOfFunctions;       /*+0x014*/
            public int NumberOfNames;           /*+0x018*/
            public int AddressOfFunctions;      /*+0x01c*/
            public int AddressOfNames;          /*+0x020*/
            public int AddressOfNameOrdinals;   /*+0x024*/
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IMAGE_SECTION_HEADER {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string Name;                 /*+0x000*/
            public int Misc;                    /*+0x008*/
            public int VirtualAddress;          /*+0x00c*/
            public int SizeOfRawData;           /*+0x010*/
            public int PointerToRawData;        /*+0x014*/
            public int PointerToRelocations;    /*+0x018*/
            public int PointerToLinenumbers;    /*+0x01c*/
            public short NumberOfRelocations;   /*+0x020*/
            public short NumberOfLinenumbers;   /*+0x022*/
            public int Characteristics;         /*+0x024*/
        }

        [StructLayout(LayoutKind.Explicit, Size = 8)]
        public struct LARGE_INTEGER {
            [FieldOffset(0)] public long QuadPart;  /*+0x000*/
            [FieldOffset(0)] public uint LowPart;   /*+0x000*/
            [FieldOffset(4)] public int HighPart;   /*+0x004*/
        }
    }
}
