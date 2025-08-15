using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

using System.Security.Cryptography;
using System.Text;

namespace BugFree.Security.Symmetric
{
    /// <summary>
    /// Blowfish 对称加密算法实现（CBC模式，PKCS7填充，IV+密文Base64输出）。
    /// 依赖 BouncyCastle。Blowfish 支持 32-448 位密钥，块大小为 8 字节。
    /// </summary>
    public class BlowfishDataProvider : ISymmetricAlgorithm
    {
        /// <summary>
        /// 使用 Blowfish 算法加密明文。
        /// </summary>
        /// <param name="plainText">要加密的明文字符串。</param>
        /// <param name="key">密钥（建议长度 4-56 字节，超长会被截断）。</param>
        /// <returns>Base64(IV+密文)。</returns>
        public string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText)) throw new ArgumentNullException(nameof(plainText));
            if (string.IsNullOrWhiteSpace(key)) throw new ArgumentNullException(nameof(key));
            // Blowfish 密钥长度 4-56 字节，超长自动截断
            var keyBytes = Encoding.UTF8.GetBytes(key);
            if (keyBytes.Length > 56) keyBytes = keyBytes[..56];
            var engine = new BlowfishEngine();
            var blockSize = engine.GetBlockSize(); // 8 字节
            // 生成随机 IV
            var iv = RandomNumberGenerator.GetBytes(blockSize);
            // CBC + PKCS7 填充
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));
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

        /// <summary>
        /// 使用 Blowfish 算法解密密文。
        /// </summary>
        /// <param name="cipherText">Base64(IV+密文)。</param>
        /// <param name="key">密钥（需与加密时一致）。</param>
        /// <returns>解密后的明文字符串。</returns>
        public string Decrypt(string cipherText, string key)
        {
            if (string.IsNullOrEmpty(cipherText)) throw new ArgumentNullException(nameof(cipherText));
            if (string.IsNullOrWhiteSpace(key)) throw new ArgumentNullException(nameof(key));
            var keyBytes = Encoding.UTF8.GetBytes(key);
            if (keyBytes.Length > 56) keyBytes = keyBytes[..56];
            var engine = new BlowfishEngine();
            var blockSize = engine.GetBlockSize();
            var payload = Convert.FromBase64String(cipherText);
            if (payload.Length < blockSize) throw new CryptographicException("Invalid payload length.");
            // 提取 IV
            var iv = new byte[blockSize];
            Buffer.BlockCopy(payload, 0, iv, 0, blockSize);
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));
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