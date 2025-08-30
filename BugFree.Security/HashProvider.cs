using BugFree.Security.GM;

using System.Security.Cryptography;
using System.Text;

namespace BugFree.Security
{
    /// <summary>哈希算法（Hash Algorithm）提供者</summary>
    public static class HashProvider
    {
        static readonly ThreadLocal<MD5> _MD5 = new(() => MD5.Create());
        static readonly ThreadLocal<SHA1> _SHA1 = new(() => SHA1.Create());
        static readonly ThreadLocal<SHA256> _SHA256 = new(() => SHA256.Create());
        static readonly ThreadLocal<SHA384> _SHA384 = new(() => SHA384.Create());
        static readonly ThreadLocal<SHA512> _SHA512 = new(() => SHA512.Create());
        static readonly ThreadLocal<SHA3_256> _SHA3_256 = new(() => SHA3_256.Create());
        static readonly ThreadLocal<SHA3_384> _SHA3_384 = new(() => SHA3_384.Create());
        static readonly ThreadLocal<SHA3_512> _SHA3_512 = new(() => SHA3_512.Create());
        static readonly ThreadLocal<SM3> _SM3 = new(() => SM3.Create());

        /// <summary>哈希算法</summary>
        /// <param name="data">要哈希的明文字符串。</param>
        /// <param name="algorithms">要应用的哈希算法列表。默认为 SHA256。</param>
        /// <param name="salt">用于哈希的盐。如果为 null，将自动生成。</param>
        /// <param name="saltSize">盐的字节大小。</param>
        /// <returns>格式为 "salt$hash$algorithms" 的自包含哈希字符串。</returns>
        public static string ComputeHash(this string data, IList<HashAlgorithm>? algorithms = null, string? salt = null, int saltSize = 16)
        {
            if (string.IsNullOrWhiteSpace(data)) { throw new ArgumentNullException(nameof(data)); }
            // 如果未提供算法，则默认为 SHA256
            algorithms ??= new List<HashAlgorithm> { HashAlgorithm.SHA256 };
            if (!algorithms.Any()) algorithms.Add(HashAlgorithm.SHA256);
            // 步骤 1: 处理传统的链式快速哈希
            var saltBytes = string.IsNullOrWhiteSpace(salt) ? RandomNumberGenerator.GetBytes(saltSize) : Convert.FromBase64String(salt);
            // 1. 核心逻辑现在操作字节数组
            var dataBytes = Encoding.UTF8.GetBytes(data);
            foreach (var algorithm in algorithms) { dataBytes = Hash(dataBytes, algorithm, saltBytes); }
            var finalHash = Convert.ToBase64String(dataBytes);
            var finalSalt = Convert.ToBase64String(saltBytes);
            var algorithmsString = string.Join("$", algorithms.Select(o => (int)o));
            return $"{finalSalt}${finalHash}${algorithmsString}";
        }
        /// <summary>验证数据是否与给定的哈希匹配</summary>
        /// <param name="data">要验证的明文字符串</param>
        /// <param name="hash">自包含的哈希字符串</param>
        public static bool VerifyHash(this string data, string hash)
        {
            if (string.IsNullOrWhiteSpace(data)) { throw new ArgumentNullException(nameof(data)); }
            if (string.IsNullOrWhiteSpace(hash)) { throw new ArgumentNullException(nameof(hash)); }
            var parts = hash.Split('$');
            // 步骤 2:如果没有慢哈希提供程序支持，则回退到传统的链式快速哈希格式
            if (3 > parts.Length) { throw new FormatException("The provided hash is not in the expected format 'salt$hash$algorithms'."); }
            var salt = parts[0];
            var originalHash = parts[1];
            var algorithms = parts.Skip(2)
                                  .Select(s => (HashAlgorithm)Enum.Parse(typeof(HashAlgorithm), s))
                                  .ToList();
            // 2. 重新计算哈希以进行比较
            var expectedHash = ComputeHash(data, algorithms, salt);
            // 3. 使用恒定时间比较来防止时序攻击
            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(hash),
                Encoding.UTF8.GetBytes(expectedHash));
        }

        #region 辅助函数
        /// <summary>核心哈希方法，对字节数组进行操作</summary>
        /// <exception cref="NotSupportedException"></exception>
        static byte[] Hash(byte[] data, HashAlgorithm algorithm, byte[] salt)
        {
            // 4. 统一所有哈希逻辑
            return algorithm switch
            {
                // 标准哈希: Hash(salt + data)
                HashAlgorithm.MD5 => ComputeHash(_MD5.Value, salt, data),
                HashAlgorithm.SHA1 => ComputeHash(_SHA1.Value, salt, data),
                HashAlgorithm.SHA256 => ComputeHash(_SHA256.Value, salt, data),
                HashAlgorithm.SHA384 => ComputeHash(_SHA384.Value, salt, data),
                HashAlgorithm.SHA512 => ComputeHash(_SHA512.Value, salt, data),
                HashAlgorithm.SHA3_256 => !SHA3_256.IsSupported ? throw new PlatformNotSupportedException($"{nameof(SHA3_256)} is not supported on this platform.") : ComputeHash(_SHA3_256.Value, salt, data),
                HashAlgorithm.SHA3_384 => !SHA3_384.IsSupported ? throw new PlatformNotSupportedException($"{nameof(SHA3_384)} is not supported on this platform.") : ComputeHash(_SHA3_384.Value, salt, data),
                HashAlgorithm.SHA3_512 => !SHA3_512.IsSupported ? throw new PlatformNotSupportedException($"{nameof(SHA3_512)} is not supported on this platform.") : ComputeHash(_SHA3_512.Value, salt, data),
                // 国密3 SM3 哈希
                //使用的 System.Security.Cryptography.GM.SM3 这个类的具体实现在重用时存在状态管理上的缺陷。即使您正确地调用了 Initialize()，它的内部状态也无法保证被完全、可靠地重置
                HashAlgorithm.SM3 => ComputeHash(_SM3.Value, salt, data),

                //消息认证码（MAC / HMAC）算法
                HashAlgorithm.HMACMD5 => HMACMD5.HashData(salt, data),
                HashAlgorithm.HMACSHA1 => HMACSHA1.HashData(salt, data),
                HashAlgorithm.HMACSHA256 => HMACSHA256.HashData(salt, data),
                HashAlgorithm.HMACSHA384 => HMACSHA384.HashData(salt, data),
                HashAlgorithm.HMACSHA512 => HMACSHA512.HashData(salt, data),

                // 密码哈希算法,用于密码哈希、防爆破,效率慢
                HashAlgorithm.Pbkdf2 => throw new NotSupportedException($"Hash algorithm '{algorithm}' is not supported."),
                HashAlgorithm.Argon2i => throw new NotSupportedException($"Hash algorithm '{algorithm}' is not supported."),
                HashAlgorithm.Argon2d => throw new NotSupportedException($"Hash algorithm '{algorithm}' is not supported."),
                HashAlgorithm.Argon2id => throw new NotSupportedException($"Hash algorithm '{algorithm}' is not supported."),
                _ => throw new NotSupportedException($"Hash algorithm '{algorithm}' is not supported.")
            };
        }
        static byte[] ComputeHash(System.Security.Cryptography.HashAlgorithm? hash, byte[] salt, byte[] data)
        {
            if (hash is null) { throw new ArgumentNullException(nameof(hash)); }
            // 关键：重用实例前必须调用 Initialize() 来清除之前的状态
            //hasher.Initialize();
            //hasher.TransformBlock(salt, 0, salt.Length, null, 0);
            //hasher.TransformFinalBlock(data, 0, data.Length);
            //return hasher.Hash;

            // 为确保原子性和避免状态问题，推荐使用 ComputeHash(byte[])
            var combinedBytes = new byte[(salt?.Length ?? 0) + data.Length];
            if (salt is not null && 0 < salt.Length) { Buffer.BlockCopy(salt, 0, combinedBytes, 0, salt.Length); }
            Buffer.BlockCopy(data, 0, combinedBytes, salt?.Length ?? 0, data.Length);
            return hash.ComputeHash(combinedBytes);
        }
        #endregion
    }

    /// <summary>哈希算法</summary>
    public enum HashAlgorithm
    {
        #region 普通哈希（适用于摘要校验、签名、完整性验证等）
        /// <summary>MD5</summary>
        MD5,
        /// <summary>SHA1</summary>
        SHA1,
        /// <summary>SHA256</summary>
        SHA256,
        /// <summary>SHA384</summary>
        SHA384,
        /// <summary>SHA512</summary>
        SHA512,
        /// <summary>SHA3-256, 仅在 Windows 11 build 25324 或更高版本</summary>
        SHA3_256,
        /// <summary>SHA3-384, 仅在 Windows 11 build 25324 或更高版本</summary>
        SHA3_384,
        /// <summary>SHA3-512, 仅在 Windows 11 build 25324 或更高版本</summary>
        SHA3_512,
        /// <summary>SM3(国密3)</summary>
        SM3,
        #endregion

        #region 消息认证码（MAC / HMAC）算法
        /// <summary>HMACMD5</summary>
        HMACMD5,
        /// <summary>HMACSHA1</summary>
        HMACSHA1,
        /// <summary>HMACSHA256</summary>
        HMACSHA256,
        /// <summary>HMACSHA384</summary>
        HMACSHA384,
        /// <summary>HMACSHA512</summary>
        HMACSHA512,

        #endregion

        #region 用于密码哈希、防爆破、效率慢
        /*
        | 算法       | 用途       | 侧信道抗性 | 抗 GPU 攻击 | 推荐用于密码哈希 |
        | -------- | -------- | ----- | -------- | -------- |
        | Argon2d  | 密钥派生     | 低     | 高        | 否        |
        | Argon2i  | 密码哈希     | 高     | 中        | 是        |
        | Argon2id | 密码哈希（推荐） | 高     | 高        | 是        |
         */
        /// <summary>PBKDF2（基于 HMAC 的密码派生函数）效率慢</summary>
        Pbkdf2,
        /// <summary>Argon2i（抗侧信道攻击）</summary>
        /// <remarks>侧重于抵抗 GPU 和 ASIC 硬件的暴力破解攻击
        ///内存访问依赖于输入数据（data-dependent），速度快，但可能受到侧信道攻击
        /// 不推荐用于密码哈希，适合加密密钥派生</remarks>
        Argon2i,

        /// <summary>Argon2d（抗 GPU）</summary>
        /// <remarks>侧重于抵抗 GPU 和 ASIC 硬件的暴力破解攻击
        ///内存访问依赖于输入数据（data-dependent），速度快，但可能受到侧信道攻击
        ///不推荐用于密码哈希，适合加密密钥派生</remarks>
        Argon2d,

        /// <summary>Argon2id（混合模式，推荐用于密码哈希）</summary>
        /// <remarks>结合了 Argon2i 和 Argon2d 的优点
        /// 先做一次数据无关访问，再做数据相关访问既安全又抗 GPU 攻击
        /// 是目前密码哈希的推荐选择（NIST 等机构也推荐）</remarks>
        Argon2id,
        #endregion
    }
}
