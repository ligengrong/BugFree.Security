using BugFree.Security.Symmetric;

using System.Collections.Concurrent;

namespace BugFree.Security
{
    /// <summary>对称加密（Symmetric Encryption）提供者</summary>
    public static class SymmetricProvider
    {
        static readonly ConcurrentDictionary<SymmetricAlgorithm, ISymmetricAlgorithm> _Providers = new ConcurrentDictionary<SymmetricAlgorithm, ISymmetricAlgorithm>();
        /// <summary>加密</summary>
        /// <param name="plainText">明文文本</param>
        /// <param name="algorithm">算法</param>
        /// <param name="key">密钥</param>
        public static string EncryptSymmetric(this string plainText, SymmetricAlgorithm algorithm = SymmetricAlgorithm.Aes, string key = null!)
        {
            if (string.IsNullOrEmpty(plainText)) { throw new ArgumentNullException(nameof(plainText)); }
            if (string.IsNullOrWhiteSpace(key)) { throw new ArgumentNullException(nameof(key)); }
            var provider = CreateDataProvider(algorithm);
            return $"{(int)algorithm}${provider.Encrypt(plainText, key)}";
        }
        /// <summary>解密</summary>
        /// <param name="cipherText">密文文本</param>
        /// 
        public static string DecryptSymmetric(this string cipherText, string key = null!)
        {
            if (string.IsNullOrEmpty(cipherText)) { throw new ArgumentNullException(nameof(cipherText)); }
            if (string.IsNullOrWhiteSpace(key)) { throw new ArgumentNullException(nameof(key)); }
            var parts = cipherText.Split('$');
            if (parts.Length != 2) { throw new ArgumentException("无效的加密文本格式。", nameof(cipherText)); }
            if (!Enum.TryParse(parts[0], out SymmetricAlgorithm algorithm)) { throw new ArgumentException("无效算法"); }
            var provider = CreateDataProvider(algorithm);
            return provider.Decrypt(parts[1], key);
        }
        static ISymmetricAlgorithm CreateDataProvider(SymmetricAlgorithm algorithm = SymmetricAlgorithm.Aes)
        {
            return _Providers.GetOrAdd(algorithm, algorithm =>
            {
                return algorithm switch
                {
                    SymmetricAlgorithm.Aes => new AesDataProvider(),
                    SymmetricAlgorithm.AesGcm => new AesGcmDataProvider(),
                    SymmetricAlgorithm.AesCtr => new AesCtrDataProvider(),
                    SymmetricAlgorithm.AesCfb => new AesCfbDataProvider(),
                    SymmetricAlgorithm.AesOfb => new AesOfbDataProvider(),
                    SymmetricAlgorithm.Des => new DesDataProvider(),
                    SymmetricAlgorithm.TripleDES => new TripleDESDataProvider(),
                    SymmetricAlgorithm.RC2 => new RC2DataProvider(),
                    SymmetricAlgorithm.Blowfish => new BlowfishDataProvider(),
                    SymmetricAlgorithm.Twofish => new TwofishDataProvider(),
                    SymmetricAlgorithm.Camellia => new CamelliaDataProvider(),
                    SymmetricAlgorithm.SM4 => new SM4DataProvider(),
                    _ => throw new NotSupportedException($"不支持的算法类型：{algorithm}"),
                };
            });
        }
    }
    /// <summary>对称加密算法</summary>
    public enum SymmetricAlgorithm
    {
        /// <summary>AES（CBC 模式）- 最常用的标准模式之一。</summary>
        Aes,
        /// <summary>AES-GCM（带认证标签的现代加密）。</summary>
        AesGcm,
        /// <summary>AES-CTR（计数器模式，常用于流加密）</summary>
        AesCtr,
        /// <summary>AES-CFB（加密反馈模式）</summary>
        AesCfb,
        /// <summary>AES-OFB（输出反馈模式）</summary>
        AesOfb,
        /// <summary>DES（已过时，不建议用于新系统）。</summary>
        Des,
        /// <summary>3DES（三重 DES）对称加密算法。比 DES 更安全，但性能较低。</summary>
        TripleDES,
        /// <summary>RC2 对称加密算法。</summary>
        RC2,
        /// <summary>Blowfish（对称加密，常见于嵌入式/老系统）</summary>
        Blowfish,
        /// <summary>Twofish（Blowfish 后继者，安全性高）</summary>
        Twofish,
        /// <summary>Camellia（日本 NTT 设计，安全性接近 AES）</summary>
        Camellia,
        /// <summary>国密 SM4 对称加密算法。中国的商用密码标准。</summary>
        SM4,
    }
}
