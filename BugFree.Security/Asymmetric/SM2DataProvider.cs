using System.Text;
using BugFree.Security.GM; // 复用 GM/SM2.cs

namespace BugFree.Security.Asymmetric
{
    /// <summary>
    /// SM2 数据提供者（最小封装）。
    /// 直接委托 <see cref="GM.SM2"/> 完成所有密码学运算，不引入 PEM/DER 密钥包装或额外的 API。
    /// </summary>
    /// <remarks>
    /// 约定与默认值：
    /// - 密钥与密文的对外表示：
    ///   - 公钥：Base64 的原始点编码；可为未压缩点(0x04||X||Y)或压缩点，长度自动识别；
    ///   - 私钥：Base64 的 32 字节大端标量；
    ///   - 密文：Base64 的 SM2Engine 输出；
    /// - 加解密模式：默认 C1C3C2（与 <see cref="SM2.Encrypt"/> 默认一致）；
    /// - 文本编码：<see cref="Encoding.UTF8"/>；
    /// - 签名：返回 DER 编码后再 Base64；验签需传入相同格式；
    /// - UserID：未暴露参数时使用 <see cref="SM2.DefaultUserId"/>（标准默认 "1234567812345678"）。
    ///
    /// 错误与异常：
    /// - 传入空字符串将抛出 <see cref="ArgumentNullException"/>；
    /// - Base64 解析失败将抛出 <see cref="FormatException"/>；
    /// - 密钥格式不匹配可能抛出底层 BouncyCastle 异常。
    ///
    /// 兼容性提示：如需切换到 PEM/DER 封装或 SM2 KEP（密钥协商）全流程，请直接使用/扩展 GM/SM2 或外部工具完成转换。
    /// </remarks>
    /// <summary>
    /// SM2 数据提供者（最小封装）：直接调用 GM/SM2.cs。
    /// - 密钥与密文采用 Base64 表示原始字节：
    ///   公钥=未压缩点(0x04||X||Y)或压缩点；私钥=32字节大端；密文=SM2Engine 输出（默认 C1C3C2）。
    /// - 签名为 DER 编码后 Base64；验签输入同样为 Base64(DER)。
    /// </summary>
    internal class SM2DataProvider : IKeyPairGenerator, IAsymmetricEncryption, IAsymmetricSignature, IKeyExchange
    {
        /// <summary>
        /// 生成 SM2 密钥对。
        /// </summary>
        /// <returns>
        /// <see cref="KeyPair"/>：PublicKey 与 PrivateKey 分别为 Base64 编码的原始字节
        /// （公钥点编码；私钥 32 字节）。
        /// </returns>
        public KeyPair GenerateKeyPair()
        {
            var sm2 = SM2.Create();
            var (pub, pri) = sm2.GenerateKeyPair();
            return new KeyPair
            {
                PublicKey = Convert.ToBase64String(pub),
                PrivateKey = Convert.ToBase64String(pri)
            };
        }

        /// <summary>
        /// 使用对方公钥加密明文（UTF-8）。
        /// </summary>
        /// <param name="plainText">明文字符串，将按 UTF-8 编码。</param>
        /// <param name="pubKey">对方公钥（Base64 的点编码，支持压缩/未压缩）。</param>
        /// <returns>Base64 的 SM2 密文（默认 C1C3C2 排列）。</returns>
        /// <exception cref="ArgumentNullException">参数为空。</exception>
        /// <exception cref="FormatException">公钥不是合法的 Base64。</exception>
        public string Encrypt(string plainText, string pubKey)
        {
            if (string.IsNullOrEmpty(plainText)) throw new ArgumentNullException(nameof(plainText));
            if (string.IsNullOrWhiteSpace(pubKey)) throw new ArgumentNullException(nameof(pubKey));
            var sm2 = SM2.Create();
            var pubRaw = Convert.FromBase64String(pubKey);
            var cipher = sm2.Encrypt(Encoding.UTF8.GetBytes(plainText), pubRaw);
            return Convert.ToBase64String(cipher);
        }

        /// <summary>
        /// 使用自己的私钥解密密文。
        /// </summary>
        /// <param name="cipherText">Base64 的 SM2 密文（需与 Encrypt 输出匹配）。</param>
        /// <param name="priKey">自己的私钥（Base64 的 32 字节）。</param>
        /// <returns>UTF-8 解码后的明文字符串。</returns>
        /// <exception cref="ArgumentNullException">参数为空。</exception>
        /// <exception cref="FormatException">密文/私钥不是合法的 Base64。</exception>
        public string Decrypt(string cipherText, string priKey)
        {
            if (string.IsNullOrWhiteSpace(cipherText)) throw new ArgumentNullException(nameof(cipherText));
            if (string.IsNullOrWhiteSpace(priKey)) throw new ArgumentNullException(nameof(priKey));
            var sm2 = SM2.Create();
            var priRaw = Convert.FromBase64String(priKey);
            var plain = sm2.Decrypt(Convert.FromBase64String(cipherText), priRaw);
            return Encoding.UTF8.GetString(plain);
        }

        /// <summary>
        /// 使用私钥对数据进行 SM2 签名（SM3withSM2，DER 编码输出）。
        /// </summary>
        /// <param name="data">待签名数据（UTF-8 编码）。</param>
        /// <param name="priKey">私钥（Base64 的 32 字节）。</param>
        /// <returns>Base64(DER) 的签名值。</returns>
        /// <remarks>
        /// - UserID 使用 <see cref="SM2.DefaultUserId"/>；
        /// - 若需 RAW r||s 输出或自定义 UserID，可直接调用 <see cref="SM2.Sign"/>。
        /// </remarks>
        /// <exception cref="ArgumentNullException">参数为空。</exception>
        /// <exception cref="FormatException">私钥不是合法的 Base64。</exception>
        public string Sign(string data, string priKey = null!)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrWhiteSpace(priKey)) throw new ArgumentNullException(nameof(priKey));
            var sm2 = SM2.Create();
            var priRaw = Convert.FromBase64String(priKey);
            var sig = sm2.Sign(Encoding.UTF8.GetBytes(data), priRaw, userId: null, der: true);
            return Convert.ToBase64String(sig);
        }

        /// <summary>
        /// 使用公钥验证签名（SM3withSM2，签名需为 Base64(DER)）。
        /// </summary>
        /// <param name="data">原文（UTF-8 编码）。</param>
        /// <param name="signature">Base64(DER) 签名。</param>
        /// <param name="pubKey">公钥（Base64 的点编码）。</param>
        /// <returns>true=验签通过；false=不通过。</returns>
        /// <remarks>
        /// - UserID 使用 <see cref="SM2.DefaultUserId"/>；若签名时使用了不同的 UserID，这里会返回 false。
        /// </remarks>
        /// <exception cref="ArgumentNullException">参数为空。</exception>
        /// <exception cref="FormatException">签名/公钥不是合法的 Base64。</exception>
        public bool Verify(string data, string signature, string pubKey = null!)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrWhiteSpace(signature)) throw new ArgumentNullException(nameof(signature));
            if (string.IsNullOrWhiteSpace(pubKey)) throw new ArgumentNullException(nameof(pubKey));
            var sm2 = SM2.Create();
            var pubRaw = Convert.FromBase64String(pubKey);
            var sig = Convert.FromBase64String(signature);
            return sm2.Verify(Encoding.UTF8.GetBytes(data), sig, pubRaw, userId: null);
        }

        /// <summary>
        /// 基于 ECDH+SM3-KDF 的共享密钥派生（非严格 SM2 KEP 流程）。
        /// </summary>
        /// <param name="pubKey">对端公钥（Base64）。</param>
        /// <param name="priKey">本端私钥（Base64）。</param>
        /// <returns>Base64 的 16 字节派生密钥（适合作为 SM4-128 密钥）。</returns>
        /// <remarks>
        /// - 行为与 <see cref="SM2.DeriveSharedKey"/> 一致；
        /// - 如需 32 字节或自定义 salt，请直接调用 GM/SM2 对应方法。
        /// </remarks>
        /// <exception cref="ArgumentNullException">参数为空。</exception>
        /// <exception cref="FormatException">公钥/私钥不是合法的 Base64。</exception>
        public string GenerateSharedSecret(string priKey, string pubKey)
        {
            if (string.IsNullOrWhiteSpace(priKey)) throw new ArgumentNullException(nameof(priKey));
            if (string.IsNullOrWhiteSpace(pubKey)) throw new ArgumentNullException(nameof(pubKey));
            var sm2 = SM2.Create();
            var pubRaw = Convert.FromBase64String(pubKey);
            var priRaw = Convert.FromBase64String(priKey);
            var key = sm2.DeriveSharedKey(priRaw, pubRaw, keySizeBytes: 16, kdfSalt: null);
            return Convert.ToBase64String(key);
        }
    }
}
