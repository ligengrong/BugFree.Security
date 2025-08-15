namespace BugFree.Security.Asymmetric
{
    /// <summary>
    /// X25519 密钥对生成与密钥协商实现。
    /// 仅用于密钥协商，不支持直接加解密或签名。
    /// 依赖第三方库（如 NSec），.NET 8 标准库暂不支持。
    /// </summary>
    internal class X25519DataProvider : IKeyPairGenerator, IKeyExchange
    {
        /// <summary>
        /// 生成 X25519 公钥和私钥对（PEM 格式）。
        /// </summary>
        /// <returns>密钥对（KeyPair），公钥和私钥均为 PEM 格式字符串</returns>
        /// <exception cref="NotSupportedException">.NET 8 标准库暂不支持 X25519</exception>
        public KeyPair GenerateKeyPair()
        {
            // .NET 8 标准库暂不支持 X25519，需第三方库（如 NSec）支持
            throw new NotSupportedException("X25519 仅在引入第三方库（如 NSec）时支持，.NET 8 标准库暂不支持");
        }

        /// <summary>
        /// 通过本地私钥和对方公钥生成共享密钥。
        /// </summary>
        /// <param name="pubKey">对方公钥（PEM 格式）</param>
        /// <param name="priKey">本地私钥（PEM 格式）</param>
        /// <returns>Base64 编码的共享密钥</returns>
        /// <exception cref="NotSupportedException">.NET 8 标准库暂不支持 X25519</exception>
        public string GenerateSharedSecret(string pubKey, string priKey)
        {
            throw new NotSupportedException("X25519 仅在引入第三方库（如 NSec）时支持，.NET 8 标准库暂不支持");
        }
    }
}
