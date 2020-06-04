using System;
using System.IO;
using System.Runtime.InteropServices;

namespace SharpHellsGate {
    public class MemoryUtil {

        private Stream ModuleStream { get; set; }

        ~MemoryUtil() {
            if (this.ModuleStream.Length > 0) {
                this.ModuleStream.Close();
            }
        }

        public MemoryUtil(byte[] stream) {
            if (stream.Length != 0) {
                this.ModuleStream = new MemoryStream(stream);
            }
        }

        public bool InitialiseStream(byte[] stream) {
            if (stream.Length == 0)
                return false;

            this.ModuleStream = new MemoryStream(stream);
            return true;
        }

        public T GetStructureFromBlob<T>(in int offset) where T : struct {
            byte[] bytes = this.GetStructureBytesFromOffset<T>(in offset);
            if (Marshal.SizeOf<T>() != bytes.Length)
                return default(T);

            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
            Marshal.Copy(bytes, 0, ptr, bytes.Length);
            T s = Marshal.PtrToStructure<T>(ptr);

            Marshal.FreeHGlobal(ptr);
            return s;
        }

        private byte[] GetStructureBytesFromOffset<T>(in int offset) where T : struct {
            Span<byte> s = stackalloc byte[Marshal.SizeOf<T>()];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return s.ToArray();
        }

        private byte[] GetBytesFromOffset(in int offset, in int size) {
            Span<byte> s = stackalloc byte[size];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return s.ToArray();
        }
    }
}
