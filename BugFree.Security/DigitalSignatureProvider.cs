namespace BugFree.Security
{
    /// <summary>数字签名（Digital Signature）提供者</summary>
    internal class DigitalSignatureProvider
    {
    }
    public enum DigitalSignatureAlgorithm
    {
        /// <summary>RSA 签名算法</summary>
        RSA,
        /// <summary>DSA 签名算法</summary>
        DSA,
        /// <summary>ECDSA 签名算法</summary>
        ECDSA,
        /// <summary>SM2 签名算法</summary>
        SM2
    }
}
