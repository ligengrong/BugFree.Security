using System.Security.Cryptography;
using System.Text;

namespace BugFree.Security.Symmetric
{

    // <summary>使用 TripleDES (CBC 模式) 提供数据保护。</summary>
    public class TripleDESDataProvider : ISymmetricAlgorithm
    {
        // 使用ThreadLocal缓存TripleDES实例以提高性能，确保线程安全。
        static readonly ThreadLocal<TripleDES> _TripleDES = new(() =>
        {
            var tdes = TripleDES.Create();
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.PKCS7;
            return tdes;
        });
        /// <summary>使用 TripleDES (CBC 模式) 加密明文。</summary>
        /// <param name="plainText">要加密的明文字符串。</param>
        /// <param name="key">用于派生加密密钥的任意字符串。</param>
        /// <returns>一个 Base64 编码的字符串，格式为 "IV+CipherText"。</returns>
        public string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText)) { throw new ArgumentNullException(nameof(plainText)); }
            if (string.IsNullOrWhiteSpace(key)) { throw new ArgumentNullException(nameof(key)); }
            using var tdes = _TripleDES.Value;
            // TripleDES 支持 16 或 24 字节密钥，这里取 MD5(key) 前16字节
            tdes.Key = MD5.HashData(Encoding.UTF8.GetBytes(key))[..16];
            tdes.GenerateIV(); // 8字节IV
            using var memoryStream = new MemoryStream();
            memoryStream.Write(tdes.IV, 0, tdes.IV.Length);
            using var cryptoStream = new CryptoStream(memoryStream, tdes.CreateEncryptor(), CryptoStreamMode.Write);
            using var streamWriter = new StreamWriter(cryptoStream, Encoding.UTF8);
            streamWriter.Write(plainText);
            streamWriter.Flush();
            cryptoStream.FlushFinalBlock();
            return Convert.ToBase64String(memoryStream.ToArray());
        }

        /// <summary>使用 TripleDES (CBC 模式) 解密密文。</summary>
        /// <param name="cipherText">要解密的Base64字符串。</param>
        /// <param name="key">用于派生解密密钥的任意字符串。</param>
        /// <returns>解密后的明文字符串。</returns>
        public string Decrypt(string cipherText, string key)
        {
            if (string.IsNullOrEmpty(cipherText)) { throw new ArgumentNullException(nameof(cipherText)); }
            if (string.IsNullOrWhiteSpace(key)) { throw new ArgumentNullException(nameof(key)); }
            using var tdes = _TripleDES.Value;
            var payload = Convert.FromBase64String(cipherText);
            var ivSize = tdes.BlockSize / 8; // 8字节
            if (payload.Length < ivSize) { throw new CryptographicException("Invalid payload length. It must be at least the size of the IV."); }
            var iv = new byte[ivSize];
            Buffer.BlockCopy(payload, 0, iv, 0, iv.Length);
            tdes.Key = MD5.HashData(Encoding.UTF8.GetBytes(key))[..16];
            tdes.IV = iv;
            using var memoryStream = new MemoryStream(payload, ivSize, payload.Length - ivSize);
            using var cryptoStream = new CryptoStream(memoryStream, tdes.CreateDecryptor(), CryptoStreamMode.Read);
            using var streamReader = new StreamReader(cryptoStream, Encoding.UTF8);
            return streamReader.ReadToEnd();
        }
    }
}
