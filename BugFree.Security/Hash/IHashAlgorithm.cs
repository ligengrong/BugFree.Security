namespace BugFree.Security.Hash
{
    internal interface IHashAlgorithm
    {
        /// <summary>使用指定的盐（salt）对给定的字符串数据进行哈希计算</summary>
        /// <param name="data">要进行哈希计算的明文字符。</param>
        /// <param name="salt">用于哈希计算的盐值。盐的格式（如 Base64 字符串或普通字符串）由具体实现决定</param>
        /// <returns>计算出的哈希结果字符串。</returns>
        string Hash(string data, string salt);
        /// <summary>
        /// 验证一个明文数据是否与给定的自包含哈希字符串匹配
        /// 此方法适用于那些将所有验证参数（如盐、迭代次数等）编码在哈希字符串内的现代哈希算法（如 Argon2, PBKDF2）。
        /// </summary>
        /// <param name="data">要验证的明文字符串</param>
        /// <param name="hash">一个自包含的哈希字符串，包含了哈希值及所有必要的验证参数</param>
        /// <returns>如果数据与哈希匹配，则为 <c>true</c>；否则为 <c>false</c></returns>
        bool Verify(string data, string hash);
    }
}
