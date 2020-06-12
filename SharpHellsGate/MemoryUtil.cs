using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpHellsGate {
    public class MemoryUtil : IDisposable {

        private Stream ModuleStream { get; set; }

        ~MemoryUtil() => Dispose();

        public void Dispose() {
            this.ModuleStream.Close();
            GC.SuppressFinalize(this);
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

        public T GetStructureFromBlob<T>(long offset) where T : struct {
            byte[] bytes = this.GetStructureBytesFromOffset<T>(in offset);
            if (Marshal.SizeOf<T>() != bytes.Length)
                return default;

            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
            Marshal.Copy(bytes, 0, ptr, bytes.Length);
            T s = Marshal.PtrToStructure<T>(ptr);

            Marshal.FreeHGlobal(ptr);
            return s;
        }

        public byte[] GetFunctionOpCode(long offset) {
            Span<byte> s = stackalloc byte[24];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return s.ToArray();
        }

        public uint ReadPtr32(long offset) {
            Span<byte> s = stackalloc byte[4];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return BitConverter.ToUInt32(s);
        }

        public ulong ReadPtr64(long offset) {
            Span<byte> s = stackalloc byte[8];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return BitConverter.ToUInt64(s);
        }

        public UInt16 ReadUShort(long offset) {
            Span<byte> s = stackalloc byte[2];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return BitConverter.ToUInt16(s);
        }

        public string ReadAscii(long offset) {
            int length = 0;
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            while (this.ModuleStream.ReadByte() != 0x00)
                length++;

            Span<byte> s = stackalloc byte[length];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return Encoding.ASCII.GetString(s);
        }

        private byte[] GetStructureBytesFromOffset<T>(in long offset) where T : struct {
            Span<byte> s = stackalloc byte[Marshal.SizeOf<T>()];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return s.ToArray();
        }

        private byte[] GetBytesFromOffset(in long offset, in int size) {
            Span<byte> s = stackalloc byte[size];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return s.ToArray();
        }
    }
}
