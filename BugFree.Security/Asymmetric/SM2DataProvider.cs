namespace BugFree.Security.Asymmetric
{
    /// <summary>
    /// SM2（国密算法）密钥对生成、加解密、签名/验签实现（占位，未实现）。
    /// 适用于国产密码应用。当前所有方法均未实现。
    /// </summary>
    internal class SM2DataProvider : IKeyPairGenerator, IAsymmetricEncryption, IAsymmetricSignature
    {
        /// <summary>生成 SM2 公钥和私钥对（PEM 格式）。</summary>
        /// <returns>密钥对（KeyPair），公钥和私钥均为 PEM 格式字符串</returns>
        /// <exception cref="NotImplementedException">始终抛出</exception>
        public KeyPair GenerateKeyPair()
        {
            throw new NotImplementedException();
        }
        /// <summary>使用 SM2 私钥解密密文。</summary>
        /// <param name="cipherText">Base64 编码的密文字符串</param>
        /// <param name="priKey">PEM 格式私钥</param>
        /// <returns>解密后的明文字符串</returns>
        /// <exception cref="NotImplementedException">始终抛出</exception>
        public string Decrypt(string cipherText, string priKey)
        {
            throw new NotImplementedException();
        }
        /// <summary>使用 SM2 公钥加密明文。</summary>
        /// <param name="plainText">要加密的明文字符串</param>
        /// <param name="pubKey">PEM 格式公钥</param>
        /// <returns>Base64 编码的密文字符串</returns>
        /// <exception cref="NotImplementedException">始终抛出</exception>
        public string Encrypt(string plainText, string pubKey)
        {
            throw new NotImplementedException();
        }
        /// <summary>使用 SM2 私钥对数据进行签名。</summary>
        /// <param name="data">待签名数据</param>
        /// <param name="priKey">PEM 格式私钥</param>
        /// <returns>Base64 编码的签名字符串</returns>
        /// <exception cref="NotImplementedException">始终抛出</exception>
        public string Sign(string data, string priKey = null)
        {
            throw new NotImplementedException();
        }
        /// <summary>使用 SM2 公钥验证签名。</summary>
        /// <param name="data">原文字符串</param>
        /// <param name="signature">Base64 编码的签名</param>
        /// <param name="pubKey">PEM 格式公钥</param>
        /// <returns>验签是否通过</returns>
        /// <exception cref="NotImplementedException">始终抛出</exception>
        public bool Verify(string data, string signature, string pubKey = null)
        {
            throw new NotImplementedException();
        }
    }
}
