using System.Security.Cryptography;
using System.Text;

namespace BugFree.Security.Asymmetric
{
    /// <summary>
    /// RSA（Rivest–Shamir–Adleman）非对称加密算法数据提供者。
    /// 支持密钥对生成、公钥加密/私钥解密、签名/验签。
    /// 推荐使用 2048 位密钥，PEM 格式密钥，OAEP 填充。
    /// </summary>
    public class RsaDataProvider : IKeyPairGenerator, IAsymmetricEncryption, IAsymmetricSignature
    {
        /// <summary>
        /// 获取或设置加密时使用的填充模式。
        /// OAEP (Optimal Asymmetric Encryption Padding) 是推荐的、更安全的模式。
        /// </summary>
        public RSAEncryptionPadding Padding { get; set; } = RSAEncryptionPadding.OaepSHA256;

        /// <summary>
        /// 生成一对 RSA 公钥和私钥（PEM 格式，2048 位）。
        /// </summary>
        /// <returns>密钥对（KeyPair），公钥和私钥均为 PEM 格式字符串</returns>
        public KeyPair GenerateKeyPair()
        {
            // 1. 创建新的 RSA 密钥对（2048位，安全性较高）
            using var rsa = RSA.Create(2048);
            // 2. 导出 PEM 格式的公钥和私钥
            var publicKey = rsa.ExportRSAPublicKeyPem();
            var privateKey = rsa.ExportRSAPrivateKeyPem();
            // 3. 返回 KeyPair 实例
            return new KeyPair
            {
                PublicKey = publicKey,
                PrivateKey = privateKey
            };
        }

        /// <summary>
        /// 使用 RSA 公钥加密明文。
        /// </summary>
        /// <param name="plainText">要加密的明文字符串（UTF-8 编码）</param>
        /// <param name="pubKey">PEM 格式公钥</param>
        /// <returns>Base64 编码的密文字符串</returns>
        public string Encrypt(string plainText, string pubKey)
        {
            if (string.IsNullOrEmpty(plainText)) throw new ArgumentNullException(nameof(plainText));
            if (string.IsNullOrWhiteSpace(pubKey)) throw new ArgumentNullException(nameof(pubKey));
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pubKey);
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            // 使用指定填充模式加密
            byte[] cipherTextBytes = rsa.Encrypt(plainTextBytes, Padding);
            return Convert.ToBase64String(cipherTextBytes);
        }

        /// <summary>
        /// 使用 RSA 私钥解密密文。
        /// </summary>
        /// <param name="cipherText">Base64 编码的密文字符串</param>
        /// <param name="priKey">PEM 格式私钥</param>
        /// <returns>解密后的明文字符串（UTF-8 编码）</returns>
        public string Decrypt(string cipherText, string priKey)
        {
            if (string.IsNullOrEmpty(cipherText)) throw new ArgumentNullException(nameof(cipherText));
            if (string.IsNullOrWhiteSpace(priKey)) throw new ArgumentNullException(nameof(priKey));
            using var rsa = RSA.Create();
            rsa.ImportFromPem(priKey);
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
            // 使用指定填充模式解密
            byte[] plainTextBytes = rsa.Decrypt(cipherTextBytes, Padding);
            return Encoding.UTF8.GetString(plainTextBytes);
        }

        /// <summary>
        /// 使用 RSA 私钥对数据进行签名。
        /// 默认使用 HashAlgorithmName.SHA256、RSASignaturePadding.Pkcs1。
        /// </summary>
        /// <param name="data">待签名数据（原文字符串，UTF-8 编码）</param>
        /// <param name="priKey">PEM 格式私钥</param>
        /// <returns>Base64 编码的签名字符串</returns>
        public string Sign(string data, string priKey = null)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrWhiteSpace(priKey)) throw new ArgumentNullException(nameof(priKey));
            using var rsa = RSA.Create();
            rsa.ImportFromPem(priKey);
            var bytes = Encoding.UTF8.GetBytes(data);
            // 推荐 SHA-256 哈希算法，PKCS#1 v1.5 签名填充
            var signature = rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signature);
        }

        /// <summary>
        /// 使用 RSA 公钥验证签名。
        /// 默认使用 HashAlgorithmName.SHA256、RSASignaturePadding.Pkcs1。
        /// </summary>
        /// <param name="data">原文字符串（UTF-8 编码）</param>
        /// <param name="signature">Base64 编码的签名字符串</param>
        /// <param name="pubKey">PEM 格式公钥</param>
        /// <returns>验签是否通过，true 表示签名有效</returns>
        public bool Verify(string data, string signature, string pubKey = null)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrWhiteSpace(signature)) throw new ArgumentNullException(nameof(signature));
            if (string.IsNullOrWhiteSpace(pubKey)) throw new ArgumentNullException(nameof(pubKey));
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pubKey);
            var bytes = Encoding.UTF8.GetBytes(data);
            var sigBytes = Convert.FromBase64String(signature);
            // 推荐 SHA-256 哈希算法，PKCS#1 v1.5 签名填充
            return rsa.VerifyData(bytes, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
}
