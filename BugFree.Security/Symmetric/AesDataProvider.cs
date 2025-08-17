using System.Security.Cryptography;
using System.Text;

namespace BugFree.Security.Symmetric
{
    /// <summary>
    /// 使用 AES (CBC 模式) 提供数据保护。
    /// CBC 模式是一种传统且广泛使用的分组密码工作模式。
    /// </summary>
    public class AesDataProvider : ISymmetricAlgorithm
    {
        //使用ThreadLocal缓存Aes实例以提高性能，确保线程安全。
        static readonly ThreadLocal<Aes> _Aes = new(() =>
        {
            var aes = Aes.Create();
            // 强制执行安全的、固定的加密参数，这是提供程序的职责。
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            return aes;
        });
        /// <summary>使用 AES (CBC 模式) 加密明文。 </summary>
        /// <param name="plainText">要加密的明文字符串。</param>
        /// <param name="key">用于派生加密密钥的任意字符串。</param>
        /// <returns>一个 Base64 编码的字符串，格式为 "IV+CipherText"。</returns>
        public string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText)) { throw new ArgumentNullException(nameof(plainText)); }
            if (string.IsNullOrWhiteSpace(key)) { throw new ArgumentNullException(nameof(key)); }
            using var aes = _Aes.Value;
            if (aes is null) { throw new InvalidOperationException("AES instance is not initialized."); }
            aes.Key = SHA256.HashData(Encoding.UTF8.GetBytes(key));
            aes.GenerateIV(); // 每次加密都生成新的、随机的 IV
            using var memoryStream = new MemoryStream();
            // 步骤 1: 将 IV 作为前缀直接写入流中，无需创建多余的局部变量。
            memoryStream.Write(aes.IV, 0, aes.IV.Length);
            // 步骤 2: 将密文写入流中，跟在 IV 后面。
            using var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            using var streamWriter = new StreamWriter(cryptoStream, Encoding.UTF8);
            streamWriter.Write(plainText);
            streamWriter.Flush();
            cryptoStream.FlushFinalBlock();
            // 步骤 3: 返回一个包含了算法标识和组合后（IV+CipherText）的 Base64 字符串。
            return Convert.ToBase64String(memoryStream.ToArray());
        }
        /// <summary>使用 AES (CBC 模式) 解密密文。</summary>
        /// <param name="cipherText">要解密的Base64字符串。</param>
        /// <param name="key">用于派生解密密钥的任意字符串。</param>
        /// <returns>解密后的明文字符串。</returns>
        public string Decrypt(string cipherText, string key)
        {
            if (string.IsNullOrEmpty(cipherText)) { throw new ArgumentNullException(nameof(cipherText)); }
            if (string.IsNullOrWhiteSpace(key)) { throw new ArgumentNullException(nameof(key)); }
            using var aes = _Aes.Value;
            if (aes is null) { throw new InvalidOperationException("AES instance is not initialized."); }
            var payload = Convert.FromBase64String(cipherText);
            var ivSize = aes.BlockSize / 8;
            if (payload.Length < ivSize) { throw new CryptographicException("Invalid payload length. It must be at least the size of the IV."); }
            // 步骤 1: 从负载中提取 IV。
            var iv = new byte[ivSize];
            Buffer.BlockCopy(payload, 0, iv, 0, iv.Length);
            aes.Key = SHA256.HashData(Encoding.UTF8.GetBytes(key));
            aes.IV = iv;
            // 步骤 2: 使用剩余的负载作为密文进行解密。
            using var memoryStream = new MemoryStream(payload, ivSize, payload.Length - ivSize);
            using var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var streamReader = new StreamReader(cryptoStream, Encoding.UTF8);
            return streamReader.ReadToEnd();
        }
    }
}
