using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHellsGate {
    public class NtdllModule {

        public static string ModuleName { get; } = "ntdll.dll";

        private IntPtr IATPtr { get; set; } = IntPtr.Zero;
    }
}
