using System.Security.Cryptography;
using System.Text;

namespace BugFree.Security.Symmetric
{

    /// <summary> 使用 RC2 (CBC 模式) 提供数据保护。 RC2 是一种分组对称加密算法，支持 8~128 位密钥。</summary>
    public class RC2DataProvider : ISymmetricAlgorithm
    {
        // 使用ThreadLocal缓存RC2实例以提高性能，确保线程安全。
        static readonly ThreadLocal<RC2> _RC2 = new(() =>
        {
            var rc2 = RC2.Create();
            rc2.Mode = CipherMode.CBC;
            rc2.Padding = PaddingMode.PKCS7;
            return rc2;
        });
        /// <summary>使用 RC2 (CBC 模式) 加密明文。 </summary>
        /// <param name="plainText">要加密的明文字符串。</param>
        /// <param name="key">用于派生加密密钥的任意字符串。</param>
        /// <returns>一个 Base64 编码的字符串，格式为 "IV+CipherText"。</returns>
        public string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText)) { throw new ArgumentNullException(nameof(plainText)); }
            if (string.IsNullOrWhiteSpace(key)) { throw new ArgumentNullException(nameof(key)); }
            using var rc2 = _RC2.Value;
            if (rc2 is null) { throw new InvalidOperationException("RC2 instance is not initialized."); }
            // RC2 支持 8~128位密钥，这里取 MD5(key) 前16字节
            rc2.Key = MD5.HashData(Encoding.UTF8.GetBytes(key))[..16];
            rc2.GenerateIV(); // 8字节IV
            using var memoryStream = new MemoryStream();
            memoryStream.Write(rc2.IV, 0, rc2.IV.Length);
            using var cryptoStream = new CryptoStream(memoryStream, rc2.CreateEncryptor(), CryptoStreamMode.Write);
            using var streamWriter = new StreamWriter(cryptoStream, Encoding.UTF8);
            streamWriter.Write(plainText);
            streamWriter.Flush();
            cryptoStream.FlushFinalBlock();
            return Convert.ToBase64String(memoryStream.ToArray());
        }
        /// <summary>使用 RC2 (CBC 模式) 解密密文。</summary>
        /// <param name="cipherText">要解密的 Base64 字符串（IV+密文）。</param>
        /// <param name="key">用于派生解密密钥的任意字符串。</param>
        /// <returns>解密后的明文字符串。</returns>
        public string Decrypt(string cipherText, string key)
        {
            if (string.IsNullOrEmpty(cipherText)) { throw new ArgumentNullException(nameof(cipherText)); }
            if (string.IsNullOrWhiteSpace(key)) { throw new ArgumentNullException(nameof(key)); }
            using var rc2 = _RC2.Value;
            if (rc2 is null) { throw new InvalidOperationException("RC2 instance is not initialized."); }
            var payload = Convert.FromBase64String(cipherText);
            var ivSize = rc2.BlockSize / 8; // 8字节
            if (payload.Length < ivSize) { throw new CryptographicException("Invalid payload length. It must be at least the size of the IV."); }
            var iv = new byte[ivSize];
            Buffer.BlockCopy(payload, 0, iv, 0, iv.Length);
            rc2.Key = MD5.HashData(Encoding.UTF8.GetBytes(key))[..16];
            rc2.IV = iv;
            using var memoryStream = new MemoryStream(payload, ivSize, payload.Length - ivSize);
            using var cryptoStream = new CryptoStream(memoryStream, rc2.CreateDecryptor(), CryptoStreamMode.Read);
            using var streamReader = new StreamReader(cryptoStream, Encoding.UTF8);
            return streamReader.ReadToEnd();
        }
    }
}
