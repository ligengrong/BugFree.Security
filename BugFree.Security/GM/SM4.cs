using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

using System.Security.Cryptography;


namespace BugFree.Security.GM
{
    /// <summary>
    /// SM4 对称加密算法实现，兼容 SymmetricAlgorithm API，基于 Portable.BouncyCastle。
    /// 支持 ECB/CBC 模式，PKCS7 填充。
    /// </summary>
    public class SM4 : System.Security.Cryptography.SymmetricAlgorithm
    {
        /// <summary>
        /// 创建 SM4 实例，兼容 SymmetricAlgorithm.Create() 习惯。
        /// </summary>
        public new static SM4 Create()
        {
            return new SM4();
        }
        /// <summary>
        /// 构造函数，初始化 SM4 算法参数。
        /// </summary>
        public SM4()
        {
            // SM4 仅支持 128 位密钥和分组长度
            KeySizeValue = 128;
            BlockSizeValue = 128;
            Mode = CipherMode.ECB;
            Padding = PaddingMode.PKCS7;
            FeedbackSizeValue = 128;
            LegalKeySizesValue = new[] { new KeySizes(128, 128, 0) };
            LegalBlockSizesValue = new[] { new KeySizes(128, 128, 0) };
        }

        /// <summary>
        /// 创建加密器。
        /// </summary>
        /// <param name="rgbKey">加密密钥，16字节</param>
        /// <param name="rgbIV">初始向量，16字节（CBC模式下必需）</param>
        /// <returns>ICryptoTransform 实例</returns>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return CreateTransform(rgbKey, rgbIV, true);
        }

        /// <summary>
        /// 创建解密器。
        /// </summary>
        /// <param name="rgbKey">解密密钥，16字节</param>
        /// <param name="rgbIV">初始向量，16字节（CBC模式下必需）</param>
        /// <returns>ICryptoTransform 实例</returns>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return CreateTransform(rgbKey, rgbIV, false);
        }

        /// <summary>
        /// 随机生成 16 字节密钥。
        /// </summary>
        public override void GenerateKey()
        {
            KeyValue = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(KeyValue);
            }
        }

        /// <summary>
        /// 随机生成 16 字节初始向量（IV）。
        /// </summary>
        public override void GenerateIV()
        {
            IVValue = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(IVValue);
            }
        }

        /// <summary>
        /// 创建加密/解密转换器。
        /// </summary>
        /// <param name="key">密钥，16字节</param>
        /// <param name="iv">初始向量，16字节（CBC模式下必需）</param>
        /// <param name="forEncryption">true=加密，false=解密</param>
        /// <returns>ICryptoTransform 实例</returns>
        private ICryptoTransform CreateTransform(byte[] key, byte[] iv, bool forEncryption)
        {
            // 检查密钥长度
            if (key == null || key.Length != 16)
                throw new ArgumentException("SM4 密钥长度必须为 16 字节 (128 位)");

            IBlockCipher engine = new SM4Engine();
            IBlockCipherPadding padding = new Pkcs7Padding();
            BufferedBlockCipher cipher;

            if (Mode == CipherMode.ECB)
            {
                // ECB 模式不需要 IV
                cipher = new PaddedBufferedBlockCipher(engine, padding);
                cipher.Init(forEncryption, new KeyParameter(key));
            }
            else if (Mode == CipherMode.CBC)
            {
                // CBC 模式需要 IV
                if (iv == null || iv.Length != 16)
                    throw new ArgumentException("SM4 CBC 模式下 IV 长度必须为 16 字节");
                cipher = new PaddedBufferedBlockCipher(new Org.BouncyCastle.Crypto.Modes.CbcBlockCipher(engine), padding);
                cipher.Init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));
            }
            else
            {
                throw new NotSupportedException($"SM4 仅支持 ECB 和 CBC 模式，当前: {Mode}");
            }
            return new SM4CryptoTransform(cipher);
        }

        /// <summary>
        /// SM4 加密/解密转换器实现。
        /// </summary>
        private class SM4CryptoTransform : ICryptoTransform
        {
            private readonly BufferedBlockCipher _cipher;
            private bool _disposed;

            /// <summary>
            /// 构造函数，传入 BouncyCastle 的缓冲分组加解密器。
            /// </summary>
            /// <param name="cipher">缓冲分组加解密器</param>
            public SM4CryptoTransform(BufferedBlockCipher cipher)
            {
                _cipher = cipher;
            }

            /// <summary>
            /// 输入分组字节数
            /// </summary>
            public int InputBlockSize => _cipher.GetBlockSize();
            /// <summary>
            /// 输出分组字节数
            /// </summary>
            public int OutputBlockSize => _cipher.GetBlockSize();
            /// <summary>
            /// 是否支持多分组变换
            /// </summary>
            public bool CanTransformMultipleBlocks => true;
            /// <summary>
            /// 是否可重用
            /// </summary>
            public bool CanReuseTransform => false;

            /// <summary>
            /// 释放资源
            /// </summary>
            public void Dispose()
            {
                _disposed = true;
            }

            /// <summary>
            /// 处理输入数据块
            /// </summary>
            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                if (_disposed) throw new ObjectDisposedException(nameof(SM4CryptoTransform));
                return _cipher.ProcessBytes(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            }

            /// <summary>
            /// 处理最后一块数据，返回最终加解密结果
            /// </summary>
            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                if (_disposed) throw new ObjectDisposedException(nameof(SM4CryptoTransform));
                var outBytes = _cipher.DoFinal(inputBuffer, inputOffset, inputCount);
                return outBytes;
            }
        }
    }
}
