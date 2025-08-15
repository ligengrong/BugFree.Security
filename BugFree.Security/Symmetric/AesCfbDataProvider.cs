using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

using System.Security.Cryptography;
using System.Text;

namespace BugFree.Security.Symmetric
{
    /// <summary>
    /// AES-CFB（加密反馈模式）对称加密实现，依赖 BouncyCastle。
    /// CFB 适合流式加密，块大小为 16 字节，密钥为 SHA256(key)。
    /// </summary>
    public class AesCfbDataProvider : ISymmetricAlgorithm
    {
        /// <summary>使用 AES-CFB 模式加密明文。</summary>
        /// <param name="plainText">要加密的明文字符串。</param>
        /// <param name="key">密钥（任意字符串，内部用 SHA256 派生 32 字节密钥）。</param>
        /// <returns>Base64(IV+密文)。</returns>
        public string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText)) throw new ArgumentNullException(nameof(plainText));
            if (string.IsNullOrWhiteSpace(key)) throw new ArgumentNullException(nameof(key));
            // 派生 32 字节密钥
            var keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));
            var blockSize = 16; // AES 块大小
            // 生成 16 字节随机 IV
            var iv = RandomNumberGenerator.GetBytes(blockSize);
            // CFB 模式，分组大小为 128 位（16 字节）
            var cipher = new BufferedBlockCipher(new CfbBlockCipher(new AesEngine(), blockSize * 8));
            cipher.Init(true, new ParametersWithIV(new KeyParameter(keyBytes), iv));
            var input = Encoding.UTF8.GetBytes(plainText);
            var output = new byte[cipher.GetOutputSize(input.Length)];
            var len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            len += cipher.DoFinal(output, len);
            // 拼接 IV + 密文
            var result = new byte[iv.Length + len];
            Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
            Buffer.BlockCopy(output, 0, result, iv.Length, len);
            return Convert.ToBase64String(result);
        }

        /// <summary>使用 AES-CFB 模式解密密文。</summary>
        /// <param name="cipherText">Base64(IV+密文)。</param>
        /// <param name="key">密钥（需与加密时一致）。</param>
        /// <returns>解密后的明文字符串。</returns>
        public string Decrypt(string cipherText, string key)
        {
            if (string.IsNullOrEmpty(cipherText)) throw new ArgumentNullException(nameof(cipherText));
            if (string.IsNullOrWhiteSpace(key)) throw new ArgumentNullException(nameof(key));
            var keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));
            var blockSize = 16;
            var payload = Convert.FromBase64String(cipherText);
            if (payload.Length < blockSize) { throw new CryptographicException("Invalid payload length."); }
            // 提取 IV
            var iv = new byte[blockSize];
            Buffer.BlockCopy(payload, 0, iv, 0, blockSize);
            var cipher = new BufferedBlockCipher(new CfbBlockCipher(new AesEngine(), blockSize * 8));
            cipher.Init(false, new ParametersWithIV(new KeyParameter(keyBytes), iv));
            var input = new byte[payload.Length - blockSize];
            Buffer.BlockCopy(payload, blockSize, input, 0, input.Length);
            var output = new byte[cipher.GetOutputSize(input.Length)];
            var len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            len += cipher.DoFinal(output, len);
            return Encoding.UTF8.GetString(output, 0, len);
        }
    }
}