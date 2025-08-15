using Org.BouncyCastle.Crypto.Digests;

using System.Security.Cryptography;

namespace BugFree.Security.GM
{
    /// <summary>
    /// SM3 哈希算法实现，兼容 HashAlgorithm API，基于 Portable.BouncyCastle。
    /// </summary>
    public class SM3 : System.Security.Cryptography.HashAlgorithm
    {
        private SM3Digest _digest;
        private byte[] _buffer;
        private int _bufferLength;

        public SM3()
        {
            _digest = new SM3Digest();
            HashSizeValue = 256;
            _buffer = new byte[_digest.GetByteLength()];
            _bufferLength = 0;
        }

        /// <summary>
        /// 创建 SM3 实例，兼容 HashAlgorithm.Create() 习惯。
        /// </summary>
        public new static SM3 Create()
        {
            return new SM3();
        }
        public override void Initialize()
        {
            _digest.Reset();
            _bufferLength = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            _digest.BlockUpdate(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            byte[] result = new byte[_digest.GetDigestSize()];
            _digest.DoFinal(result, 0);
            return result;
        }

        public new static byte[] ComputeHash(byte[] data)
        {
            var sm3 = new SM3Digest();
            sm3.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[sm3.GetDigestSize()];
            sm3.DoFinal(result, 0);
            return result;
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }
}
