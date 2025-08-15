using System.Security.Cryptography;
using System.Text;

namespace BugFree.Security.Symmetric
{
    /// <summary>SM4数据提供者，使用国密SM4算法</summary>
    public class SM4DataProvider : ISymmetricAlgorithm
    {
        // 使用ThreadLocal缓存RC2实例以提高性能，确保线程安全。
        static readonly ThreadLocal<GM.SM4> _SM4 = new(() =>
        {
            var sm4 = GM.SM4.Create();
            return sm4;
        });
        /// <summary>SM4 密钥大小为 128 位，即 16 字节。</summary>
        public int KeySize { get;  } = 16;
        /// <summary>SM4 密钥大小为 128 位，即 16 字节。</summary>
        public int IVSize { get;  } = 16;
        /// <summary>使用 SM4 (CBC 模式) 加密明文。 </summary>
        /// <param name="plainText">要加密的明文字符串。</param>
        /// <param name="key">用于派生加密密钥的任意字符串。</param>
        /// <returns>一个 Base64 编码的字符串，格式为 "IV+CipherText"。</returns>
        public string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText)) { throw new ArgumentNullException(nameof(plainText)); }
            if (string.IsNullOrWhiteSpace(key)) { throw new ArgumentNullException(nameof(key)); }
            using var sm4 = _SM4.Value;
            sm4.Key = Convert.FromHexString(key)[..KeySize];
            sm4.GenerateIV();// 每次加密都生成新的、随机的 IV
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            // 在内存中直接执行加密操作
            using var encryptor = sm4.CreateEncryptor(sm4.Key, sm4.IV);
            var cipherBytes = encryptor.TransformFinalBlock(plainTextBytes, 0, plainTextBytes.Length);

            // 将 IV 和密文合并到一个字节数组中
            var resultBytes = new byte[sm4.IV.Length + cipherBytes.Length];
            Buffer.BlockCopy(sm4.IV, 0, resultBytes, 0, sm4.IV.Length);
            Buffer.BlockCopy(cipherBytes, 0, resultBytes, sm4.IV.Length, cipherBytes.Length);
            // 步骤 3: 返回一个包含了算法标识和组合后（IV+CipherText）的 Base64 字符串。
            return Convert.ToBase64String(resultBytes);
        }
        /// <summary>使用 SM4 (CBC 模式) 解密密文。</summary>
        /// <param name="cipherText">要解密的、格式为 "Aes$Base64(IV+CipherText)" 的自包含字符串。</param>
        /// <param name="key">用于派生解密密钥的任意字符串。</param>
        /// <returns>解密后的明文字符串。</returns>
        public string Decrypt(string cipherText, string key)
        {
            using var sm4 = _SM4.Value;
            var payload = Convert.FromBase64String(cipherText);
            var ivSize = sm4.BlockSize / 8; if (payload.Length < ivSize) { throw new CryptographicException("Invalid payload length. It must be at least the size of the IV."); }
            // 步骤 1: 从负载中提取 IV。
            var iv = new byte[ivSize];
            Buffer.BlockCopy(payload, 0, iv, 0, iv.Length);
            sm4.Key = Convert.FromHexString(key)[..KeySize];
            sm4.IV = iv;
            // 步骤 2: 提取真正的密文部分
            var cipherBytes = new byte[payload.Length - ivSize];
            Buffer.BlockCopy(payload, ivSize, cipherBytes, 0, cipherBytes.Length);

            // 在内存中直接执行解密操作
            using var decryptor = sm4.CreateDecryptor(sm4.Key, sm4.IV);
            var decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}
