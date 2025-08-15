namespace BugFree.Security.Symmetric
{
    /// <summary>对称加解密接口</summary>
    internal interface ISymmetricAlgorithm {
        /// <summary>使用指定的密钥对明文数据进行加密。</summary>
        /// <param name="plainText">要加密的明文字符串。</param>
        /// <param name="key">用于加密的密钥。密钥的格式和要求由具体实现决定。</param>
        /// <returns>一个表示已加密数据（密文）的字符串，通常为 Base64 编码。</returns>
        string Encrypt(string plainText, string key);
        /// <summary>使用指定的密钥对密文数据进行解密。</summary>
        /// <param name="cipherText">要解密的、经过 Base64 编码的密文字符串。</param>
        /// <param name="key">用于解密的密钥。必须与加密时使用的密钥相同。</param>
        /// <returns>解密后的明文字符串。</returns>
        string Decrypt(string cipherText, string key);
    }
}
