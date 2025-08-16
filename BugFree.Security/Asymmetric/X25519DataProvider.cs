using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;

using System.Security.Cryptography;
using System.Text;

namespace BugFree.Security.Asymmetric
{
    /// <summary>
    /// X25519 密钥对生成与密钥协商实现（基于 BouncyCastle）。
    /// 仅用于密钥协商，不支持直接加解密或签名。
    /// </summary>
    internal class X25519DataProvider : IKeyPairGenerator, IKeyExchange
    {
        /// <summary>
        /// 生成 X25519 公钥和私钥对（PEM 格式，RFC 8410）。
        /// </summary>
        public KeyPair GenerateKeyPair()
        {
            // 生成原始 32 字节私钥与公钥
            var rng = RandomNumberGenerator.Create();
            var seed = new byte[32];
            rng.GetBytes(seed);

            var priv = new X25519PrivateKeyParameters(seed, 0);
            var pub = priv.GeneratePublicKey();

            var pubBytes = pub.GetEncoded();   // 32 bytes
            var priBytes = priv.GetEncoded();  // 32 bytes

            // PublicKey: SubjectPublicKeyInfo(id-X25519, 无参数)
            var spki = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), // 1.3.101.110
                pubBytes);
            var spkiDer = spki.GetDerEncoded();
            var pubPem = PemEncode("PUBLIC KEY", spkiDer);

            // PrivateKey: PKCS#8 PrivateKeyInfo(id-X25519, privateKey=OCTET STRING 32 bytes)
            var pki = new PrivateKeyInfo(
                new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519),
                new DerOctetString(priBytes));
            var pkiDer = pki.GetDerEncoded();
            var priPem = PemEncode("PRIVATE KEY", pkiDer);

            return new KeyPair { PublicKey = pubPem, PrivateKey = priPem };
        }

        /// <summary>
        /// 通过本地私钥和对方公钥生成共享密钥（Base64）。
        /// </summary>
        public string GenerateSharedSecret(string priKey, string pubKey)
        {
            if (string.IsNullOrWhiteSpace(priKey)) throw new ArgumentNullException(nameof(priKey));
            if (string.IsNullOrWhiteSpace(pubKey)) throw new ArgumentNullException(nameof(pubKey));
            // 解析公钥（SPKI）
            var spkiDer = DecodePem(pubKey, "PUBLIC KEY");
            var spki = SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(spkiDer));
            var pubBytes = spki.PublicKey.GetOctets();
            if (pubBytes == null || pubBytes.Length != 32)
                throw new CryptographicException("无效的 X25519 公钥");

            // 解析私钥（PKCS#8）
            var pkiDer = DecodePem(priKey, "PRIVATE KEY");
            var pki = PrivateKeyInfo.GetInstance(Asn1Object.FromByteArray(pkiDer));
            var privateOctet = Asn1OctetString.GetInstance(pki.ParsePrivateKey());
            var priBytes = privateOctet.GetOctets();
            if (priBytes == null || priBytes.Length != 32)
                throw new CryptographicException("无效的 X25519 私钥");

            var priv = new X25519PrivateKeyParameters(priBytes, 0);
            var pub = new X25519PublicKeyParameters(pubBytes, 0);

            var agree = new X25519Agreement();
            agree.Init(priv);
            var shared = new byte[32];
            agree.CalculateAgreement(pub, shared, 0);

            return Convert.ToBase64String(shared);
        }

        // --- helpers ---

        static string PemEncode(string label, byte[] der)
        {
            var b64 = Convert.ToBase64String(der);
            var sb = new StringBuilder();
            sb.AppendLine($"-----BEGIN {label}-----");
            for (int i = 0; i < b64.Length; i += 64)
            {
                sb.AppendLine(b64.AsSpan(i, Math.Min(64, b64.Length - i)).ToString());
            }
            sb.AppendLine($"-----END {label}-----");
            return sb.ToString();
        }

        static byte[] DecodePem(string pem, string expectedLabel)
        {
            var begin = $"-----BEGIN {expectedLabel}-----";
            var end = $"-----END {expectedLabel}-----";
            var start = pem.IndexOf(begin, StringComparison.Ordinal);
            if (start < 0) throw new CryptographicException($"未找到 {begin}");
            start += begin.Length;
            var stop = pem.IndexOf(end, start, StringComparison.Ordinal);
            if (stop < 0) throw new CryptographicException($"未找到 {end}");
            var base64 = pem.Substring(start, stop - start).Replace("\r", "").Replace("\n", "").Trim();
            return Convert.FromBase64String(base64);
        }
    }
}
