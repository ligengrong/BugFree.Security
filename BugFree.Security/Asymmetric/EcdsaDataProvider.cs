using System.Security.Cryptography;
using System.Text;

namespace BugFree.Security.Asymmetric
{
    /// <summary>
    /// ECDSA（Elliptic Curve Digital Signature Algorithm，椭圆曲线数字签名算法）密钥对生成与签名/验签实现。
    /// 仅支持签名/验签，不支持加解密。适用于高性能数字签名场景。
    /// </summary>
    internal class EcdsaDataProvider : IKeyPairGenerator, IAsymmetricSignature
    {
        /// <summary>
        /// 生成 ECDSA 公钥和私钥对（PEM 格式，使用 NIST P-256 曲线）。
        /// </summary>
        /// <returns>密钥对（KeyPair），公钥和私钥均为 PEM 格式字符串</returns>
        public KeyPair GenerateKeyPair()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var publicKey = ecdsa.ExportSubjectPublicKeyInfoPem();
            var privateKey = ecdsa.ExportPkcs8PrivateKeyPem();
            return new KeyPair { PublicKey = publicKey, PrivateKey = privateKey };
        }

        /// <summary>
        /// 使用 ECDSA 私钥对数据进行签名。
        /// 默认使用 HashAlgorithmName.SHA256。
        /// </summary>
        /// <param name="data">待签名数据（原文字符串，UTF-8 编码）</param>
        /// <param name="priKey">PEM 格式私钥</param>
        /// <returns>Base64 编码的签名字符串</returns>
        /// <exception cref="ArgumentNullException">参数为空时抛出</exception>
        public string Sign(string data, string priKey)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrWhiteSpace(priKey)) throw new ArgumentNullException(nameof(priKey));
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(priKey);
            var bytes = Encoding.UTF8.GetBytes(data);
            var signature = ecdsa.SignData(bytes, HashAlgorithmName.SHA256);
            return Convert.ToBase64String(signature);
        }

        /// <summary>
        /// 使用 ECDSA 公钥验证签名。
        /// 默认使用 HashAlgorithmName.SHA256。
        /// </summary>
        /// <param name="data">原文字符串（UTF-8 编码）</param>
        /// <param name="signature">Base64 编码的签名字符串</param>
        /// <param name="pubKey">PEM 格式公钥</param>
        /// <returns>验签是否通过，true 表示签名有效</returns>
        /// <exception cref="ArgumentNullException">参数为空时抛出</exception>
        public bool Verify(string data, string signature, string pubKey)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrWhiteSpace(signature)) throw new ArgumentNullException(nameof(signature));
            if (string.IsNullOrWhiteSpace(pubKey)) throw new ArgumentNullException(nameof(pubKey));
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pubKey);
            var bytes = Encoding.UTF8.GetBytes(data);
            var sigBytes = Convert.FromBase64String(signature);
            return ecdsa.VerifyData(bytes, sigBytes, HashAlgorithmName.SHA256);
        }
    }
}
