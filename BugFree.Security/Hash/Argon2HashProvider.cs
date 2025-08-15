//using Konscious.Security.Cryptography;

//using System.Security.Cryptography;
//using System.Text;
//using System.Text.RegularExpressions;

//namespace BugFree.Security.Hash
//{
//    /// <summary>
//    /// 使用 Argon2id 算法提供密码哈希功能。Argon2 是密码哈希竞赛的获胜者，
//    /// 被认为是当前用于密码存储的最强大、最安全的哈希算法之一。
//    /// 它具有内存密集、抗 GPU 破解和可调整参数的特点。
//    /// </summary>
//    internal class Argon2idHashProvider : IHashProvider
//    {
//        /// <summary>
//        /// 获取或设置盐（Salt）的字节大小。
//        /// 盐是一个随机值，用于确保即使相同的密码也会产生不同的哈希值。
//        /// 默认值为 16 字节（128位）。
//        /// </summary>
//        public int SaltSize { get; set; } = 16;

//        /// <summary>
//        /// 获取或设置派生密钥（即哈希）的字节大小。
//        /// 默认值为 32 字节（256位）。
//        /// </summary>
//        public int HashSize { get; set; } = 32;

//        /// <summary>
//        /// 获取或设置并行度（Degree of Parallelism）。
//        /// 此参数决定了可以并行计算的线程数，可以利用多核处理器来加快哈希计算。
//        /// 默认值为 8。
//        /// </summary>
//        public int DegreeOfParallelism { get; set; } = 8;

//        /// <summary>
//        /// 获取或设置迭代次数（Time Cost）。
//        /// 此参数定义了哈希算法执行的次数。增加此值会使哈希计算变慢，从而提高安全性。
//        /// 默认值为 4。
//        /// </summary>
//        public int Iterations { get; set; } = 4;

//        /// <summary>
//        /// 获取或设置内存成本（Memory Cost），单位为 KB。
//        /// 此参数定义了计算哈希时需要分配的内存量。高内存需求使得大规模并行攻击（如使用 ASIC 或 FPGA）的成本更高。
//        /// 默认值为 128 MB (131072 KB)。
//        /// </summary>
//        public int MemorySize { get; set; } = 1024 * 128;


//        /// <summary>
//        /// 使用 Argon2id 算法哈希密码。
//        /// </summary>
//        /// <param name="data">要哈希的密码明文。</param>
//        /// <param name="salt">一个 Base64 编码的盐字符串。如果为 null 或空，将自动生成一个随机盐。</param>
//        /// <returns>一个自包含的、遵循模块化加密格式 (MCF) 的哈希字符串。</returns>
//        public string Hash(string data, string salt)
//        {
//            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));

//            // 步骤 1: 处理盐。如果未提供，则生成一个新的随机盐；否则，从 Base64 解码。
//            var saltBytes = !string.IsNullOrEmpty(salt)
//                ? Convert.FromBase64String(salt)
//                : RandomNumberGenerator.GetBytes(SaltSize);
//            // 步骤 2: 配置并计算 Argon2id 哈希。
//            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(data))
//            {
//                Salt = saltBytes,
//                DegreeOfParallelism = DegreeOfParallelism,
//                Iterations = Iterations,
//                MemorySize = MemorySize
//            };

//            var hashBytes = argon2.GetBytes(HashSize);

//            // 步骤 3: 将所有参数编码到一个标准的模块化加密格式 (MCF) 字符串中。
//            // 格式: $argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<hash>
//            // Base64 编码的盐和哈希不需要填充 '=' 字符。
//            var saltBase64 = Convert.ToBase64String(saltBytes).TrimEnd('=');
//            var hashBase64 = Convert.ToBase64String(hashBytes).TrimEnd('=');

//            return $"{HashAlgorithmType.Argon2id}$v=19$m={MemorySize},t={Iterations},p={DegreeOfParallelism}${saltBase64}${hashBase64}";
//        }
//        /// <summary>
//        /// 验证密码是否与给定的 Argon2id 哈希匹配。
//        /// </summary>
//        /// <param name="data">要验证的密码明文。</param>
//        /// <param name="hash">自包含的 Argon2id 哈希字符串 (MCF 格式)。</param>
//        /// <returns>如果匹配则为 true，否则为 false。</returns>
//        public bool Verify(string data, string hash)
//        {
//            if (string.IsNullOrWhiteSpace(data)) { throw new ArgumentNullException(nameof(data)); }
//            if (string.IsNullOrWhiteSpace(hash)) { throw new ArgumentNullException(nameof(hash)); }

//            // 步骤 1: 验证哈希字符串是否为有效的 Argon2id MCF 格式。
//            if (!hash.StartsWith($"{HashAlgorithmType.Argon2id}")) { return false; }

//            try
//            {
//                // 步骤 2: 解析 MCF 字符串以提取参数。
//                var match = Argon2ParametersRegex.Match(hash);
//                if (!match.Success) { return false; }

//                // 使用 TryParse 增强稳健性
//                if (!int.TryParse(match.Groups["m"].Value, out var memorySize) ||
//                    !int.TryParse(match.Groups["t"].Value, out var iterations) ||
//                    !int.TryParse(match.Groups["p"].Value, out var parallelism))
//                {
//                    return false; // 参数格式不正确
//                }

//                var saltBase64 = match.Groups["salt"].Value;
//                var hashBase64 = match.Groups["hash"].Value;

//                // 步骤 3: 解码盐和原始哈希。
//                // 需要为 Base64 字符串添加可能被移除的填充。
//                var salt = Convert.FromBase64String(PadBase64(saltBase64));
//                var originalHashBytes = Convert.FromBase64String(PadBase64(hashBase64));

//                // 步骤 4: 使用从哈希字符串中提取的完全相同的参数重新计算哈希。
//                using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(data))
//                {
//                    Salt = salt,
//                    DegreeOfParallelism = parallelism,
//                    Iterations = iterations,
//                    MemorySize = memorySize
//                };

//                var hashToCompare = argon2.GetBytes(originalHashBytes.Length);

//                // 步骤 5: 使用恒定时间比较来防止时序攻击。
//                return CryptographicOperations.FixedTimeEquals(originalHashBytes, hashToCompare);
//            }
//            catch { return false; }// 如果解析或解码过程中出现任何错误，则视为验证失败。
//        }
//        /// <summary>
//        /// 为 Base64 字符串添加必要的 '=' 填充。
//        /// </summary>
//        static string PadBase64(string b64)
//        {
//            int padding = b64.Length % 4;
//            if (padding > 0)
//            {
//                return b64 + new string('=', 4 - padding);
//            }
//            return b64;
//        }

//        // 使用传统的 Regex 对象来解析标准的 Argon2 MCF 哈希字符串。
//        // RegexOptions.Compiled 提供了性能优化。
//        static readonly Regex Argon2ParametersRegex = new Regex(
//            @"^Argon2id\$v=19\$m=(?<m>\d+),t=(?<t>\d+),p=(?<p>\d+)\$(?<salt>[A-Za-z0-9+/]+)\$(?<hash>[A-Za-z0-9+/]+)$",
//            RegexOptions.Compiled);
//    }
//}
