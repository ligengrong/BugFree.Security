using System.Security.Cryptography;
using System.Text;

namespace BugFree.Security.Asymmetric
{
    /// <summary>
    /// DSA（Digital Signature Algorithm，数字签名算法）密钥对生成与签名/验签实现。
    /// 仅支持签名/验签，不支持加解密。适用于需要数字签名的场景。
    /// 默认签名和验签均使用 HashAlgorithmName.SHA256。
    /// </summary>
    internal class DsaDataProvider : IKeyPairGenerator, IAsymmetricSignature
    {
        /// <summary>
        /// 生成 DSA 公钥和私钥对（PEM 格式，2048 位）。
        /// </summary>
        /// <returns>密钥对（KeyPair），公钥和私钥均为 PEM 格式字符串</returns>
        public KeyPair GenerateKeyPair()
        {
            using var dsa = DSA.Create(2048);
            var publicKey = dsa.ExportSubjectPublicKeyInfoPem();
            var privateKey = dsa.ExportPkcs8PrivateKeyPem();
            return new KeyPair { PublicKey = publicKey, PrivateKey = privateKey };
        }

        /// <summary>
        /// 使用 DSA 私钥对数据进行签名。
        /// 默认使用 HashAlgorithmName.SHA256。
        /// </summary>
        /// <param name="data">待签名数据（原文字符串，UTF-8 编码）</param>
        /// <param name="priKey">PEM 格式私钥</param>
        /// <returns>Base64 编码的签名字符串</returns>
        /// <exception cref="ArgumentNullException">参数为空时抛出</exception>
        public string Sign(string data, string priKey = null)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrWhiteSpace(priKey)) throw new ArgumentNullException(nameof(priKey));
            using var dsa = DSA.Create();
            dsa.ImportFromPem(priKey);
            var bytes = Encoding.UTF8.GetBytes(data);
            // DSA 只支持 SHA-1、SHA-256、SHA-384、SHA-512，默认使用 SHA-256
            var signature = dsa.SignData(bytes, HashAlgorithmName.SHA256);
            return Convert.ToBase64String(signature);
        }

        /// <summary>
        /// 使用 DSA 公钥验证签名。
        /// 默认使用 HashAlgorithmName.SHA256。
        /// </summary>
        /// <param name="data">原文字符串（UTF-8 编码）</param>
        /// <param name="signature">Base64 编码的签名字符串</param>
        /// <param name="pubKey">PEM 格式公钥</param>
        /// <returns>验签是否通过，true 表示签名有效</returns>
        /// <exception cref="ArgumentNullException">参数为空时抛出</exception>
        public bool Verify(string data, string signature, string pubKey = null)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrWhiteSpace(signature)) throw new ArgumentNullException(nameof(signature));
            if (string.IsNullOrWhiteSpace(pubKey)) throw new ArgumentNullException(nameof(pubKey));
            using var dsa = DSA.Create();
            dsa.ImportFromPem(pubKey);
            var bytes = Encoding.UTF8.GetBytes(data);
            var sigBytes = Convert.FromBase64String(signature);
            // 默认使用 SHA-256 验签
            return dsa.VerifyData(bytes, sigBytes, HashAlgorithmName.SHA256);
        }
    }
}
