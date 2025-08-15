using System;
using System.Security.Cryptography;

namespace BugFree.Security.Asymmetric
{
    /// <summary>
    /// ECDH（Elliptic Curve Diffie-Hellman，椭圆曲线密钥协商）密钥对生成实现。
    /// 仅用于密钥协商，不支持直接加解密或签名。
    /// 适用于安全协商对称密钥的场景。
    /// </summary>
    internal class EcdhDataProvider : IKeyPairGenerator, IKeyExchange
    {
        /// <summary>
        /// 生成 ECDH 公钥和私钥对（PEM 格式，使用 NIST P-256 曲线）。
        /// </summary>
        /// <returns>密钥对（KeyPair），公钥和私钥均为 PEM 格式字符串</returns>
        public KeyPair GenerateKeyPair()
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var publicKey = ecdh.ExportSubjectPublicKeyInfoPem();
            var privateKey = ecdh.ExportPkcs8PrivateKeyPem();
            return new KeyPair { PublicKey = publicKey, PrivateKey = privateKey };
        }
        /// <summary>
        /// 生成共享密钥（密钥交换）。
        /// </summary>
        /// <param name="priKey">己方私钥（PEM 格式）</param>
        /// <param name="pubKey">对方公钥（PEM 格式）</param>
        /// <returns>Base64 编码的共享密钥</returns>
        public string GenerateSharedSecret(string priKey, string pubKey)
        {
            if (string.IsNullOrWhiteSpace(priKey)) throw new ArgumentNullException(nameof(priKey));
            if (string.IsNullOrWhiteSpace(pubKey)) throw new ArgumentNullException(nameof(pubKey));
            using var ecdh = ECDiffieHellman.Create();
            ecdh.ImportFromPem(priKey);
            using var otherEcdh = ECDiffieHellman.Create();
            otherEcdh.ImportFromPem(pubKey);
            var otherPubKey = otherEcdh.PublicKey;
            var sharedSecret = ecdh.DeriveKeyMaterial(otherPubKey);
            return Convert.ToBase64String(sharedSecret);
        }
    }
}
