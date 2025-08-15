using System.Security.Cryptography;
using System.Text;

namespace BugFree.Security.Symmetric
{
    /// <summary>
    /// 使用 AES-GCM 认证加密模式提供对称数据保护。
    /// AES-GCM 是一种现代、高效且安全的加密模式，它在加密数据的同时提供了身份验证，能有效防止数据篡改。
    /// </summary>
    public class AesGcmDataProvider : ISymmetricAlgorithm
    {
        /// <summary>Key（密钥）的大小（字节）。AES-GCM 支持 16 (AES-128), 24 (AES-192), 或 32 (AES-256)。</summary>
        public int KeySize { get; set; } = 32;
        /// <summary>Nonce（随机数）的大小（字节）。标准推荐 12 字节以获得最佳性能和安全性。</summary>
        public int NonceSize { get; set; } = 12;
        /// <summary>Tag（认证标签）的大小（字节）。通常为 16 字节（128位）。</summary>
        public int TagSize { get; set; } = 16;
        /// <summary>AAD（附加认证数据）的大小（字节）。AAD 用于保护元数据的完整性，它本身不被加密。</summary>
        public int AADSize { get; set; } = 13;
        /// <summary>使用 AES-GCM 加密明文。</summary>
        /// <param name="plainText">要加密的明文字符串。</param>
        /// <param name="key">用于派生加密密钥的任意字符串。</param>
        /// <returns>一个自包含的 Base64 编码字符串，格式为 "AesGcm$Base64(Nonce+Tag+AAD+CipherText)"。</returns>
        public string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText)) { throw new ArgumentNullException(nameof(plainText)); }
            if (string.IsNullOrWhiteSpace(key)) { throw new ArgumentNullException(nameof(key)); }
            // 1. 派生密钥并初始化 AesGcm
            var keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));
            if (keyBytes.Length < KeySize) throw new ArgumentException($"密钥派生后的长度不足 {KeySize} 字节。", nameof(key));
            using var aesGcm = new AesGcm(keyBytes[..KeySize], TagSize);

            // 2. 准备加密所需的组件
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            var cipherTextBytes = new byte[plainTextBytes.Length];
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var tag = new byte[TagSize];
            var aad = RandomNumberGenerator.GetBytes(AADSize); // 生成随机的 AAD

            // 3. 执行加密，并传入 AAD
            aesGcm.Encrypt(nonce, plainTextBytes, cipherTextBytes, tag, aad);

            // 4. 组合输出：将 Nonce, Tag, AAD 和密文打包
            var payload = new byte[nonce.Length + tag.Length + aad.Length + cipherTextBytes.Length];
            int offset = 0;
            Buffer.BlockCopy(nonce, 0, payload, offset, nonce.Length);
            offset += nonce.Length;
            Buffer.BlockCopy(tag, 0, payload, offset, tag.Length);
            offset += tag.Length;
            Buffer.BlockCopy(aad, 0, payload, offset, aad.Length);
            offset += aad.Length;
            Buffer.BlockCopy(cipherTextBytes, 0, payload, offset, cipherTextBytes.Length);

            return Convert.ToBase64String(payload);
        }
        /// <summary>使用 AES-GCM 解密密文。</summary>
        /// <param name="cipherText">要解密的、格式为 "AesGcm$Base64(Nonce+Tag+AAD+CipherText)" 的自包含字符串。</param>
        /// <param name="key">用于派生解密密钥的任意字符串。</param>
        /// <returns>解密后的明文字符串。</returns>
        public string Decrypt(string cipherText, string key)
        {
            if (string.IsNullOrEmpty(cipherText)) { throw new ArgumentNullException(nameof(cipherText)); }
            if (string.IsNullOrWhiteSpace(key)) { throw new ArgumentNullException(nameof(key)); }

            // 1. 派生密钥并初始化 AesGcm
            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));
            if (keyBytes.Length < KeySize) throw new ArgumentException($"密钥派生后的长度不足 {KeySize} 字节。", nameof(key));
            using var aesGcm = new AesGcm(keyBytes[..KeySize], TagSize);

            byte[] payload = Convert.FromBase64String(cipherText);
            if (payload.Length < NonceSize + TagSize + AADSize) { throw new CryptographicException("无效的加密负载，长度不足以包含 Nonce、Tag 和 AAD。"); }

            // 2. 从负载中分解出各个部分
            int offset = 0;
            byte[] nonce = new byte[NonceSize];
            Buffer.BlockCopy(payload, offset, nonce, 0, nonce.Length);
            offset += nonce.Length;

            byte[] tag = new byte[TagSize];
            Buffer.BlockCopy(payload, offset, tag, 0, tag.Length);
            offset += tag.Length;

            byte[] aad = new byte[AADSize];
            Buffer.BlockCopy(payload, offset, aad, 0, aad.Length);
            offset += aad.Length;

            byte[] cipherTextBytes = new byte[payload.Length - offset];
            Buffer.BlockCopy(payload, offset, cipherTextBytes, 0, cipherTextBytes.Length);

            // 3. 执行解密，并传入 AAD 进行验证
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];
            aesGcm.Decrypt(nonce, cipherTextBytes, tag, plainTextBytes, aad);

            return Encoding.UTF8.GetString(plainTextBytes);
        }


    }
}
