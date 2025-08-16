using BugFree.Security.Asymmetric;

using System.Collections.Concurrent;

namespace BugFree.Security
{
    /// <summary>
    /// 非对称加密（Asymmetric Encryption）提供者。
    /// 提供统一的密钥对生成、加解密、签名/验签、密钥交换等非对称密码学操作入口。
    /// 支持多种主流算法（RSA、DSA、ECDSA、ECDH、Ed25519、X25519、SM2）。
    /// </summary>
    public static class AsymmetricProvider
    {
        // 算法类型与实现的映射缓存，提升性能，避免重复创建实例。
        static readonly ConcurrentDictionary<AsymmetricAlgorithm, IKeyPairGenerator> _Providers = new ConcurrentDictionary<AsymmetricAlgorithm, IKeyPairGenerator>();

        /// <summary>
        /// 生成指定算法的一对公钥和私钥。
        /// </summary>
        /// <param name="algorithm">非对称算法类型</param>
        /// <returns>密钥对（PEM 格式）</returns>
        public static KeyPair GenerateKeyPair(AsymmetricAlgorithm algorithm = AsymmetricAlgorithm.RSA)
        {
            var provider = CreateDataProvider(algorithm);
            return provider.GenerateKeyPair();
        }

        /// <summary>
        /// 使用公钥加密明文，仅支持 RSA/SM2。
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="pubKey">公钥（PEM 格式）</param>
        /// <param name="algorithm">算法类型</param>
        /// <returns>格式为 "算法编号$Base64密文" 的字符串</returns>
        public static string EncryptAsymmetric(this string plainText, string pubKey = null!, AsymmetricAlgorithm algorithm = AsymmetricAlgorithm.RSA)
        {
            if (string.IsNullOrEmpty(plainText)) { throw new ArgumentNullException(nameof(plainText)); }
            if (string.IsNullOrWhiteSpace(pubKey)) { throw new ArgumentNullException(nameof(pubKey)); }
            if (algorithm is not AsymmetricAlgorithm.RSA and not AsymmetricAlgorithm.SM2) { throw new ArgumentException($"无效算法/{algorithm} 不支持加解密"); }
            var provider = (IAsymmetricEncryption)CreateDataProvider(algorithm);
            // 调用具体算法的加密实现
            return $"{(int)algorithm}${provider.Encrypt(plainText, pubKey)}";
        }

        /// <summary>
        /// 使用私钥解密密文，仅支持 RSA/SM2。
        /// </summary>
        /// <param name="cipherText">格式为 "算法编号$Base64密文" 的字符串</param>
        /// <param name="priKey">私钥（PEM 格式）</param>
        /// <returns>解密后的明文</returns>
        public static string DecryptAsymmetric(this string cipherText, string priKey = null!)
        {
            if (string.IsNullOrEmpty(cipherText)) { throw new ArgumentNullException(nameof(cipherText)); }
            if (string.IsNullOrWhiteSpace(priKey)) { throw new ArgumentNullException(nameof(priKey)); }
            var parts = cipherText.Split('$');
            if (parts.Length != 2) { throw new ArgumentException("无效的加密文本格式。", nameof(cipherText)); }
            if (!Enum.TryParse(parts[0], out AsymmetricAlgorithm algorithm) || algorithm is not AsymmetricAlgorithm.RSA and not AsymmetricAlgorithm.SM2) { throw new ArgumentException($"无效算法/{algorithm} 不支持加解密"); }
            var provider = (IAsymmetricEncryption)CreateDataProvider(algorithm);
            // 调用具体算法的解密实现
            return provider.Decrypt(parts[1], priKey);
        }

        /// <summary>
        /// 使用私钥对数据进行签名。
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="priKey">私钥（PEM 格式）</param>
        /// <param name="algorithm">算法类型</param>
        /// <returns>格式为 "算法编号$Base64签名" 的字符串</returns>
        public static string SignAsymmetric(this string data, string priKey = null!, AsymmetricAlgorithm algorithm = AsymmetricAlgorithm.RSA)
        {
            if (string.IsNullOrEmpty(data)) { throw new ArgumentNullException(nameof(data)); }
            if (string.IsNullOrWhiteSpace(priKey)) { throw new ArgumentNullException(nameof(priKey)); }
            if (algorithm is not AsymmetricAlgorithm.RSA and not AsymmetricAlgorithm.DSA and not AsymmetricAlgorithm.ECDSA and not AsymmetricAlgorithm.Ed25519 and not AsymmetricAlgorithm.SM2) { throw new Exception($"{algorithm} 不支持签名"); }
            var provider = (IAsymmetricSignature)CreateDataProvider(algorithm);
            // 调用具体算法的签名实现
            return $"{(int)algorithm}${provider.Sign(data, priKey)}";
        }

        /// <summary>
        /// 使用公钥验签。
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名（格式为 "算法编号$Base64签名"）</param>
        /// <param name="pubKey">公钥（PEM 格式）</param>
        /// <returns>验签结果</returns>
        public static bool VerifyAsymmetric(this string data, string signature, string pubKey = null!)
        {
            if (string.IsNullOrEmpty(data)) { throw new ArgumentNullException(nameof(data)); }
            if (string.IsNullOrWhiteSpace(signature)) { throw new ArgumentNullException(nameof(signature)); }
            if (string.IsNullOrWhiteSpace(pubKey)) { throw new ArgumentNullException(nameof(pubKey)); }
            var parts = signature.Split('$');
            if (parts.Length != 2) { throw new ArgumentException("无效签名格式。", nameof(signature)); }
            if (!Enum.TryParse(parts[0], out AsymmetricAlgorithm algorithm) || algorithm is not AsymmetricAlgorithm.RSA and not AsymmetricAlgorithm.DSA and not AsymmetricAlgorithm.ECDSA and not AsymmetricAlgorithm.Ed25519 and not AsymmetricAlgorithm.SM2) { throw new Exception($"{algorithm} 不支持验签"); }
            var provider = (IAsymmetricSignature)CreateDataProvider(algorithm);
            // 调用具体算法的验签实现
            return provider.Verify(data, parts[1], pubKey);
        }

        /// <summary>
        /// 生成共享密钥（密钥交换），如 ECDH/X25519。
        /// </summary>
        /// <param name="priKey">己方私钥（PEM 格式）</param>
        /// <param name="pubKey">对方公钥（PEM 格式）</param>
        /// <param name="algorithm">算法类型</param>
        /// <returns>Base64 编码的共享密钥</returns>
        public static string GenerateSharedSecret(this string priKey, string pubKey, AsymmetricAlgorithm algorithm = AsymmetricAlgorithm.ECDH)
        {
            if (string.IsNullOrWhiteSpace(pubKey)) { throw new ArgumentNullException(nameof(pubKey)); }
            if (string.IsNullOrWhiteSpace(priKey)) { throw new ArgumentNullException(nameof(priKey)); }
            if (algorithm is not AsymmetricAlgorithm.ECDH and not AsymmetricAlgorithm.X25519 and not AsymmetricAlgorithm.SM2) { throw new Exception($"{algorithm} 不支持密钥交换"); }
            var provider = (IKeyExchange)CreateDataProvider(algorithm);
            // 调用具体算法的密钥交换实现
            return provider.GenerateSharedSecret(priKey, pubKey);
        }

        /// <summary>
        /// 工厂方法：根据算法类型获取对应的实现实例。
        /// </summary>
        /// <param name="algorithm">算法类型</param>
        /// <returns>实现 IKeyPairGenerator 的实例</returns>
        static IKeyPairGenerator CreateDataProvider(AsymmetricAlgorithm algorithm = AsymmetricAlgorithm.RSA)
        {
            return _Providers.GetOrAdd(algorithm, algorithm =>
            {
                return algorithm switch
                {
                    AsymmetricAlgorithm.RSA => new RsaDataProvider(),
                    AsymmetricAlgorithm.DSA => new DsaDataProvider(),
                    AsymmetricAlgorithm.ECDSA => new EcdsaDataProvider(),
                    AsymmetricAlgorithm.ECDH => new EcdhDataProvider(),
                    AsymmetricAlgorithm.Ed25519 => new Ed25519DataProvider(),
                    AsymmetricAlgorithm.X25519 => new X25519DataProvider(),
                    AsymmetricAlgorithm.SM2 => new SM2DataProvider(),
                    _ => throw new NotSupportedException($"不支持的算法类型：{algorithm}"),
                };
            });
        }
    }
    /// <summary>
    /// 非对称加密算法类型枚举。
    /// 标注每种算法支持的功能和典型用途。
    /// </summary>
    public enum AsymmetricAlgorithm
    {
        /// <summary>
        /// RSA 算法。
        /// 支持：加解密、签名/验签。
        /// 用途：通用最广泛，适合数据加密、数字签名、密钥交换（如 TLS）。
        /// </summary>
        RSA,
        /// <summary>
        /// DSA（数字签名算法）。
        /// 支持：签名/验签。
        /// 用途：仅用于数字签名，不支持加解密。
        /// </summary>
        DSA,
        /// <summary>
        /// ECDSA（椭圆曲线数字签名算法）。
        /// 支持：签名/验签。
        /// 用途：现代数字签名，性能高于 DSA/RSA，不支持加解密。
        /// </summary>
        ECDSA,
        /// <summary>
        /// ECDH（椭圆曲线 Diffie-Hellman）。
        /// 支持：密钥交换。
        /// 用途：安全协商对称密钥，不支持加解密或签名。
        /// </summary>
        ECDH,
        /// <summary>
        /// Ed25519。
        /// 支持：签名/验签。
        /// 用途：高性能椭圆曲线签名，适合 JWT/WebAuthn/区块链等，不支持加解密。
        /// </summary>
        Ed25519,
        /// <summary>
        /// X25519。
        /// 支持：密钥交换。
        /// 用途：高性能椭圆曲线密钥交换，与 Ed25519 同族，不支持加解密或签名。
        /// </summary>
        X25519,
        /// <summary>
        /// SM2（国密算法）。
        /// 支持：加解密、签名/验签、密钥交换。
        /// 用途：中国商用密码标准，适合国产密码应用。
        /// </summary>
        SM2,
    }
}
