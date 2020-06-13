using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpHellsGate.Module {
    public class MemoryUtil : IDisposable {

        protected Stream ModuleStream { get; set; }

        ~MemoryUtil() => Dispose();

        public void Dispose() {
            this.ModuleStream.Dispose();
            this.ModuleStream.Close();
            GC.SuppressFinalize(this);
        }

        protected T GetStructureFromBlob<T>(Int64 offset) where T : struct {
            Span<byte> bytes = this.GetStructureBytesFromOffset<T>(offset);
            if (Marshal.SizeOf<T>() != bytes.Length)
                return default;

            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
            Marshal.Copy(bytes.ToArray(), 0, ptr, bytes.Length);
            T s = Marshal.PtrToStructure<T>(ptr);

            Marshal.FreeHGlobal(ptr);
            return s;
        }

        protected Span<byte> GetFunctionOpCode(Int64 offset) {
            Span<byte> s = stackalloc byte[24];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return s.ToArray();
        }

        protected UInt32 ReadPtr32(Int64 offset) {
            Span<byte> s = stackalloc byte[4];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return BitConverter.ToUInt32(s);
        }

        protected UInt64 ReadPtr64(Int64 offset) {
            Span<byte> s = stackalloc byte[8];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return BitConverter.ToUInt64(s);
        }

        protected UInt16 ReadUShort(Int64 offset) {
            Span<byte> s = stackalloc byte[2];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return BitConverter.ToUInt16(s);
        }

        protected string ReadAscii(Int64 offset) {
            int length = 0;
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            while (this.ModuleStream.ReadByte() != 0x00)
                length++;

            Span<byte> s = length <= 1024 ? stackalloc byte[length] : new byte[length];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return Encoding.ASCII.GetString(s);
        }

        protected Span<byte> GetStructureBytesFromOffset<T>(Int64 offset) where T : struct {
            Span<byte> s = stackalloc byte[Marshal.SizeOf<T>()];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return s.ToArray();
        }

        protected Span<byte> GetBytesFromOffset(Int64 offset, int size) {
            Span<byte> s = stackalloc byte[size];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return s.ToArray();
        }
    }
}
