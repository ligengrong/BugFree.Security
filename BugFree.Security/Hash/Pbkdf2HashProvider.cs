using System.Security.Cryptography;

namespace BugFree.Security.Hash
{
    /// <summary>
    /// 使用 PBKDF2 (Password-Based Key Derivation Function 2) 算法提供哈希计算和验证功能。
    /// PBKDF2 通过应用伪随机函数（例如 HMAC）到输入密码和盐上，并重复多次来“拉伸”密钥，
    /// 从而显著增加暴力破解的成本。
    /// 这种方法非常适合用于存储用户密码等安全敏感信息。
    /// </summary>
    internal class Pbkdf2HashProvider : IHashAlgorithm
    {
        /// <summary>
        /// 获取或设置盐（Salt）的字节大小。
        /// 盐是一个随机值，用于确保即使相同的密码也会产生不同的哈希值。
        /// 默认值为 16 字节（128位），这是一个常见的安全推荐值。
        /// </summary>
        public int SaltSize { get; set; } = 16; // 128-bit salt
        /// <summary>
        /// 获取或设置派生密钥（即哈希）的字节大小。
        /// 默认值为 32 字节（256位），与 SHA-256 的输出大小相匹配。
        /// </summary>
        public int KeySize { get; set; } = 32;  // 256-bit hash
        /// <summary>
        /// 获取或设置 PBKDF2 算法的迭代次数。
        /// 迭代次数越高，哈希计算所需时间越长，从而使暴力破解更加困难。
        /// 这个值应根据服务器硬件性能进行调整，以在安全性和响应时间之间取得平衡。
        /// OWASP 建议对 PBKDF2-HMAC-SHA512 使用至少 120,000 次迭代。当前值较低，建议在生产环境中提高。
        /// </summary>
        public int Iterations { get; set; } = 120_000; // 迭代次数，可以根据硬件性能调整
        /// <summary>
        /// 获取或设置在 PBKDF2 内部使用的哈希算法。
        /// 默认使用 SHA-512，它比 SHA-256 更安全，尤其是在 64 位系统上性能更佳。
        /// </summary>
        public HashAlgorithmName AlgorithmName = HashAlgorithmName.SHA512;
        /// <summary>使用 PBKDF2 算法哈希密码。</summary>
        /// <param name="data">要哈希的密码明文。</param>
        /// <param name="salt">衍纸</param>
        /// <returns>一个自包含的哈希字符串，格式为 "Pbkdf2$iterations$salt$hash"。</returns>
        public string Hash(string data, string salt)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));

            // 步骤 1: 处理盐。如果未提供，则生成一个新的随机盐；否则，从 Base64 解码。
            var saltBytes = !string.IsNullOrEmpty(salt)
                ? Convert.FromBase64String(salt)
                : RandomNumberGenerator.GetBytes(SaltSize);

            // 步骤 2: 使用 Rfc2898DeriveBytes.Pbkdf2 方法计算哈希。
            // 这个方法封装了 PBKDF2 的核心逻辑，包括多次迭代。
            var hash = Rfc2898DeriveBytes.Pbkdf2(data, saltBytes, Iterations, AlgorithmName, KeySize);

            // 步骤 3: 将所有参数（算法标识、迭代次数、盐、哈希）编码到一个自包含的字符串中。
            // 这样做的好处是，验证时无需额外存储这些参数。
            return $"{(int)HashAlgorithm.Pbkdf2}${Iterations}${Convert.ToBase64String(saltBytes)}${Convert.ToBase64String(hash)}";
        }
        /// <summary>验证密码是否与给定的 PBKDF2 哈希匹配。</summary>
        /// <param name="data">要验证的密码明文。</param>
        /// <param name="hash">自包含的哈希字符串。</param>
        /// <returns>如果匹配则为 true，否则为 false。</returns>
        public bool Verify(string data, string hash)
        {
            if (string.IsNullOrWhiteSpace(data)) { throw new ArgumentNullException(nameof(data)); }
            if (string.IsNullOrWhiteSpace(hash)) { throw new ArgumentNullException(nameof(hash)); }
            try
            {
                // 步骤 1: 解析自包含的哈希字符串，提取出各个部分。
                // 使用 . 作为分隔符。
                var parts = hash.Split('$', 4);
                // 如果格式不匹配，说明这不是一个由本提供程序生成的有效 PBKDF2 哈希。
                if (parts.Length != 4 || parts[0] != $"{(int)HashAlgorithm.Pbkdf2}") { return false; }

                // 步骤 2: 从字符串中提取哈希计算时使用的原始参数。
                if (!int.TryParse(parts[1], out var iterations))
                {
                    return false; // 迭代次数格式不正确
                }
                var salt = Convert.FromBase64String(parts[2]);
                var originalHashBytes = Convert.FromBase64String(parts[3]);

                // 步骤 3: 使用从哈希字符串中提取的完全相同的参数（盐、迭代次数、算法）来重新计算哈希。
                // 这是验证过程的核心：只有使用相同的输入和参数，才能得到相同的输出。
                var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(data, salt, iterations, AlgorithmName, originalHashBytes.Length);

                // 步骤 4: 使用恒定时间比较（CryptographicOperations.FixedTimeEquals）来安全地对比两个哈希。
                // 这种比较方法可以有效防止时序攻击（Timing Attack），即攻击者通过测量比较操作的微小时间差异来推断哈希内容。
                return CryptographicOperations.FixedTimeEquals(originalHashBytes, hashToCompare);
            }
            catch { return false; }// 如果在解析或解码过程中发生任何异常（如 Base64 格式错误），都视为验证失败。
        }
    }
}
