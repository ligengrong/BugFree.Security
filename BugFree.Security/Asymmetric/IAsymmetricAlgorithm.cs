namespace BugFree.Security.Asymmetric
{
    /// <summary>
    /// 定义非对称加密相关接口，包括密钥对生成、加解密、签名/验签、密钥交换。
    /// 适用于多种主流非对称算法的统一抽象。
    /// </summary>
    internal interface IKeyPairGenerator {
        /// <summary>生成一对公钥和私钥。</summary>
        /// <returns>密钥对（KeyPair），公钥和私钥均为 PEM 格式字符串</returns>
        KeyPair GenerateKeyPair();
    }
    /// <summary>
    /// 非对称加密接口，定义公钥加密和私钥解密方法。
    /// </summary>
    internal interface IAsymmetricEncryption
    {
        /// <summary>公钥加密明文。</summary>
        /// <param name="plainText">要加密的明文字符串。</param>
        /// <param name="pubKey">公钥（PEM 格式）</param>
        /// <returns>Base64 编码的密文字符串</returns>
        string Encrypt(string plainText, string pubKey);
        /// <summary>私钥解密密文。</summary>
        /// <param name="cipherText">要解密的、经过 Base64 编码的密文字符串。</param>
        /// <param name="priKey">私钥（PEM 格式）</param>
        /// <returns>解密后的明文字符串</returns>
        string Decrypt(string cipherText, string priKey);
    }
    /// <summary>
    /// 非对称签名接口，定义签名和验签方法。
    /// </summary>
    internal interface IAsymmetricSignature {
        /// <summary>使用私钥对数据进行签名。</summary>
        /// <param name="data">待签名数据</param>
        /// <param name="priKey">PEM 格式私钥</param>
        /// <returns>Base64 编码的签名字符串</returns>
    string Sign(string data, string priKey);
        /// <summary>使用公钥验证签名。</summary>
        /// <param name="data">原文字符串</param>
        /// <param name="signature">Base64 编码的签名</param>
        /// <param name="pubKey">PEM 格式公钥</param>
        /// <returns>验签是否通过</returns>
    bool Verify(string data, string signature, string pubKey);
    }
    /// <summary>
    /// 密钥交换接口，定义通过本地私钥和对方公钥生成共享密钥的方法。
    /// </summary>
    internal interface IKeyExchange
    {
        /// <summary>
        /// 密钥交换（Key Exchange）是一种密码学协议，允许通信双方在不安全的网络上安全地协商出一个共同的“对称密钥”，而无需直接传输这个密钥本身。
        /// 典型算法如 ECDH、X25519、DH、SM2。
        /// </summary>
        /// <param name="pubKey">对方公钥（PEM 格式）</param>
        /// <param name="priKey">本地私钥（PEM 格式）</param>
        /// <returns>Base64 编码的共享密钥</returns>
        string GenerateSharedSecret(string pubKey, string priKey);
    }
    /// <summary>
    /// 密钥对结构，包含 PEM 格式的公钥和私钥。
    /// </summary>
    public class KeyPair {
        /// <summary>公钥（PEM 格式字符串）</summary>
        public string PublicKey { get; set; } = string.Empty;
        /// <summary>私钥（PEM 格式字符串）</summary>
        public string PrivateKey { get; set; } = string.Empty;
    }
}
