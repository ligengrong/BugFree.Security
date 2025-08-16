using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

using System.Security.Cryptography;
using System.Text;

namespace BugFree.Security.Asymmetric
{
    /// <summary>
    /// Ed25519 密钥对生成与签名/验签实现（基于 BouncyCastle，跨平台稳定）。
    /// 仅支持签名/验签，不支持加解密。
    /// </summary>
    internal class Ed25519DataProvider : IKeyPairGenerator, IAsymmetricSignature
    {
        /// <summary>
        /// 生成 Ed25519 公钥和私钥对（PEM，RFC 8410）。
        /// </summary>
        public KeyPair GenerateKeyPair()
        {
            var seed = new byte[32];
            RandomNumberGenerator.Fill(seed);

            var priv = new Ed25519PrivateKeyParameters(seed, 0);
            var pub = priv.GeneratePublicKey();

            var pubBytes = pub.GetEncoded();   // 32 bytes
            var priBytes = priv.GetEncoded();  // 32 bytes

            // PublicKey: SubjectPublicKeyInfo(id-Ed25519, 无参数)
            var spki = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                pubBytes);
            var spkiDer = spki.GetDerEncoded();
            var pubPem = PemEncode("PUBLIC KEY", spkiDer);

            // PrivateKey: PKCS#8 PrivateKeyInfo(id-Ed25519, privateKey=OCTET STRING 32 bytes)
            var pki = new PrivateKeyInfo(
                new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                new DerOctetString(priBytes));
            var pkiDer = pki.GetDerEncoded();
            var priPem = PemEncode("PRIVATE KEY", pkiDer);

            return new KeyPair { PublicKey = pubPem, PrivateKey = priPem };
        }

        /// <summary>
        /// 使用 Ed25519 私钥对数据进行签名（原生 Ed25519，内部使用 SHA-512，无需额外指定哈希）。
        /// </summary>
        public string Sign(string data, string priKey)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrWhiteSpace(priKey)) throw new ArgumentNullException(nameof(priKey));

            var pkiDer = DecodePem(priKey, "PRIVATE KEY");
            var pki = PrivateKeyInfo.GetInstance(Asn1Object.FromByteArray(pkiDer));
            if (!pki.PrivateKeyAlgorithm.Algorithm.Equals(EdECObjectIdentifiers.id_Ed25519))
                throw new CryptographicException("不是 Ed25519 私钥");

            var octet = Asn1OctetString.GetInstance(pki.ParsePrivateKey());
            var priBytes = octet.GetOctets();
            if (priBytes is null || priBytes.Length != 32)
                throw new CryptographicException("无效的 Ed25519 私钥");

            var signer = new Ed25519Signer();
            signer.Init(true, new Ed25519PrivateKeyParameters(priBytes, 0));
            var msg = Encoding.UTF8.GetBytes(data);
            signer.BlockUpdate(msg, 0, msg.Length);
            var sig = signer.GenerateSignature();
            return Convert.ToBase64String(sig);
        }

        /// <summary>
        /// 使用 Ed25519 公钥验证签名。
        /// </summary>
        public bool Verify(string data, string signature, string pubKey)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrWhiteSpace(signature)) throw new ArgumentNullException(nameof(signature));
            if (string.IsNullOrWhiteSpace(pubKey)) throw new ArgumentNullException(nameof(pubKey));

            var spkiDer = DecodePem(pubKey, "PUBLIC KEY");
            var spki = SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(spkiDer));
            if (!spki.Algorithm.Algorithm.Equals(EdECObjectIdentifiers.id_Ed25519))
                throw new CryptographicException("不是 Ed25519 公钥");

            var pubBytes = spki.PublicKey.GetOctets();
            if (pubBytes is null || pubBytes.Length != 32)
                throw new CryptographicException("无效的 Ed25519 公钥");

            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(pubBytes, 0));
            var msg = Encoding.UTF8.GetBytes(data);
            verifier.BlockUpdate(msg, 0, msg.Length);
            var sigBytes = Convert.FromBase64String(signature);
            return verifier.VerifySignature(sigBytes);
        }

        // --- helpers ---
        private static string PemEncode(string label, byte[] der)
        {
            var b64 = Convert.ToBase64String(der);
            var sb = new StringBuilder();
            sb.AppendLine($"-----BEGIN {label}-----");
            for (int i = 0; i < b64.Length; i += 64)
            {
                int len = Math.Min(64, b64.Length - i);
                sb.Append(b64, i, len);
                sb.AppendLine();
            }
            sb.AppendLine($"-----END {label}-----");
            return sb.ToString();
        }

        private static byte[] DecodePem(string pem, string expectedLabel)
        {
            var begin = $"-----BEGIN {expectedLabel}-----";
            var end = $"-----END {expectedLabel}-----";
            var s = pem.IndexOf(begin, StringComparison.Ordinal);
            if (s < 0) throw new CryptographicException($"未找到 {begin}");
            s += begin.Length;
            var e = pem.IndexOf(end, s, StringComparison.Ordinal);
            if (e < 0) throw new CryptographicException($"未找到 {end}");
            var base64 = pem.Substring(s, e - s).Replace("\r", "").Replace("\n", "").Trim();
            return Convert.FromBase64String(base64);
        }
    }
}
