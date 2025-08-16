using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1; // DER/ASN.1 编解码（签名 r,s 转换）
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement; // ECDHBasicAgreement（密钥派生，非严格 SM2 KAP）
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests; // SM3Digest（KDF）
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System.Text;

namespace BugFree.Security.GM
{
    /// <summary>
    /// SM2 椭圆曲线公钥密码算法（基于 BouncyCastle）。
    /// 提供密钥对生成、SM2 加密/解密（C1C3C2/C1C2C3 格式）。
    ///
    /// 重要硬编码说明（请在使用时知悉）：
    /// - 曲线名称：固定为 "sm2p256v1"（GM/T 0003-2012 推荐曲线）。若需替换曲线，请修改 <see cref="sm2Params"/> 的 GetByName 参数。
    /// - 公钥编码：默认非压缩格式（前缀 0x04），由 <see cref="ECPublicKeyParameters.Q"/>.GetEncoded(false) 决定；若需要压缩公钥，请改为 true，并在接收侧同步变更。
    /// - 默认分组模式：<see cref="SM2Engine.Mode.C1C3C2"/>，与国密常见实现兼容。仅为字节拼接顺序差异，性能几乎无差。
    /// - 随机数源：复用全局 <see cref="rng"/>，避免频繁创建随机数实例导致的熵源/性能开销；如需自定义熵源，请在构造时替换。
    ///
    /// 性能提示：
    /// - 已对基点 G 做固定点预计算，以提升标量乘法速度（影响密钥生成与加密）。
    /// - 对大数据量（>8KB）建议使用“SM2 包裹对称密钥 + SM4-GCM/CTR 加密数据”的混合加密方案。
    /// </summary>
    public class SM2
    {
        // 硬编码：使用 GM 标准曲线 sm2p256v1。如需自定义曲线，可替换为 GMNamedCurves.GetByOid(...) 或自定义参数。
        static readonly X9ECParameters sm2Params = GMNamedCurves.GetByName("sm2p256v1");

        // 椭圆曲线域参数：包含曲线、基点 G、阶 N、余因子 H。
        static readonly ECDomainParameters domainParams = new(sm2Params.Curve, sm2Params.G, sm2Params.N, sm2Params.H);

        // 共享随机数：避免每次加/解密临时创建 SecureRandom 带来的系统熵源调用成本。
        static readonly SecureRandom rng = new SecureRandom();

        // 硬编码：SM2 默认用户标识（User ID，ZA/ZB 计算用）。与常见实现保持一致，除非对接方有明确要求。
        static readonly byte[] DefaultUserId = Encoding.ASCII.GetBytes("1234567812345678");

        /// <summary>
        /// 工厂方法，便于链式创建。
        /// </summary>
        public static SM2 Create() => new SM2();

        /// <summary>
        /// 构造函数：对基点 G 进行固定点预计算，提升后续标量乘法性能。
        /// 注：FixedPointUtilities 位于 Org.BouncyCastle.Math.EC.Multiplier 命名空间；此处使用全名避免额外 using。
        /// </summary>
        public SM2() => Org.BouncyCastle.Math.EC.Multiplier.FixedPointUtilities.Precompute(sm2Params.G);

        /// <summary>
        /// 生成 SM2 密钥对。
        /// </summary>
        /// <returns>
        /// tuple.Item1 = 公钥字节（非压缩格式，首字节 0x04）
        /// tuple.Item2 = 私钥字节（D 的无符号大端表示）
        /// </returns>
        public (byte[], byte[]) GenerateKeyPair()
        {
            // 初始化密钥对生成器（使用预设域参数与共享随机数）
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(
                domainParams,
                rng // 使用安全的随机数生成器（共享实例，见上）
            );
            generator.Init(keyGenParams);
            // 生成密钥对
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

            // 提取私钥 (BigInteger D)
            ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.Private;
            var priKey = privateKey.D.ToByteArrayUnsigned(); // 转换为无符号字节数组（大端），长度通常为 32 字节

            // 提取公钥 (ECPoint Q)
            ECPublicKeyParameters publicKey = (ECPublicKeyParameters)keyPair.Public;
            var pubKey = publicKey.Q.GetEncoded(false); // 硬编码：非压缩格式（含 0x04 前缀）。需压缩公钥时改为 true。
            return (pubKey, priKey);
        }

        /// <summary>
        /// 使用 SM2 解密。
        /// </summary>
        /// <param name="data">密文，按 <paramref name="mode"/> 指定的 C1C3C2 或 C1C2C3 格式组织。</param>
        /// <param name="privateKey">私钥 D 的无符号大端字节数组。</param>
        /// <param name="mode">字节序格式，默认为 C1C3C2（硬编码默认）。</param>
        /// <returns>解密后的明文字节。</returns>
        public byte[] Decrypt(byte[] data, byte[] privateKey, SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2)
        {
            BigInteger d = new BigInteger(1, privateKey);

            // 创建私钥参数
            ECPrivateKeyParameters keyParameter = new ECPrivateKeyParameters(d, domainParams);

            SM2Engine engine = new SM2Engine(mode);
            engine.Init(false, keyParameter);

            byte[] decryptedData = engine.ProcessBlock(data, 0, data.Length);
            return decryptedData;
        }

        /// <summary>
        /// 使用 SM2 加密。
        /// </summary>
        /// <param name="data">待加密明文。</param>
        /// <param name="publicKey">公钥点 Q 的编码（默认非压缩 0x04 前缀）。</param>
        /// <param name="mode">字节序格式，默认为 C1C3C2（硬编码默认）。</param>
        /// <returns>密文，按所选模式拼接。</returns>
        public byte[] Encrypt(byte[] data, byte[] publicKey, SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2)
        {
            // 解析公钥编码为曲线点 Q；要求与 GenerateKeyPair 输出的编码一致（默认非压缩）。
            Org.BouncyCastle.Math.EC.ECPoint q = sm2Params.Curve.DecodePoint(publicKey);
            AsymmetricKeyParameter keyParameter = new ECPublicKeyParameters(q, domainParams);

            SM2Engine engine = new SM2Engine(mode);

            // 硬编码：使用共享 rng 作为临时密钥 k 的随机源；若需可测或可复现，请外部注入自定义 SecureRandom。
            engine.Init(true, new ParametersWithRandom(keyParameter, rng));

            byte[] encryptedData = engine.ProcessBlock(data, 0, data.Length);
            return encryptedData;
        }

        /// <summary>
        /// 使用 SM2（SM3withSM2）对数据进行数字签名。
        /// </summary>
        /// <param name="data">待签名字节（将直接参与 SM3withSM2 计算）。</param>
        /// <param name="privateKey">私钥 D 的无符号大端字节数组。</param>
        /// <param name="userId">
        /// 用户标识（用于计算 ZA）。若为 null，使用硬编码 <see cref="DefaultUserId"/>（"1234567812345678"）。
        /// 注意：对接双方必须使用相同的 User ID，且大小写/编码一致，否则验签失败。
        /// </param>
        /// <param name="der">
        /// 输出格式：true=DER 编码（ASN.1 SEQUENCE(r,s)），false=纯 64 字节 r||s（每段 32 字节）。
        /// </param>
        /// <returns>签名（DER 或 r||s）。</returns>
        public byte[] Sign(byte[] data, byte[] privateKey, byte[]? userId = null, bool der = true)
        {
            // 1) 构造私钥参数
            BigInteger d = new BigInteger(1, privateKey);
            ICipherParameters keyParam = new ECPrivateKeyParameters(d, domainParams);

            // 2) 绑定 UserID（影响 ZA 值）
            var uid = userId ?? DefaultUserId;
            if (uid.Length == 0) uid = DefaultUserId; // 保护：空数组时回退默认
            keyParam = new ParametersWithID(keyParam, uid);

            // 3) 使用标准名称获取签名器（等价于 new SM2Signer(new SM3Digest())）
            ISigner signer = SignerUtilities.GetSigner("SM3WITHSM2");
            signer.Init(true, keyParam);
            signer.BlockUpdate(data, 0, data.Length);
            byte[] sigDer = signer.GenerateSignature(); // BouncyCastle 默认返回 DER 编码

            if (der) return sigDer;

            // 转换为原始 64 字节 r||s
            return DerToPlainRS(sigDer, 32);
        }

        /// <summary>
        /// 验证 SM2（SM3withSM2）签名。
        /// </summary>
        /// <param name="data">原始数据。</param>
        /// <param name="signature">签名字节（可为 DER 或 64 字节 r||s）。</param>
        /// <param name="publicKey">公钥点 Q 的编码（默认非压缩 0x04 前缀）。</param>
        /// <param name="userId">用户标识（用于计算 ZA）。与签名时一致；null 则使用 <see cref="DefaultUserId"/>。</param>
        /// <returns>true=验签通过；false=验签失败。</returns>
        public bool Verify(byte[] data, byte[] signature, byte[] publicKey, byte[]? userId = null)
        {
            // 1) 解析公钥
            var q = sm2Params.Curve.DecodePoint(publicKey);
            ICipherParameters keyParam = new ECPublicKeyParameters(q, domainParams);

            // 2) 绑定 UserID
            var uid = userId ?? DefaultUserId;
            if (uid.Length == 0) uid = DefaultUserId;
            keyParam = new ParametersWithID(keyParam, uid);

            // 3) 根据输入格式准备 DER 签名
            byte[] sigDer = signature.Length == 64 ? PlainRSToDer(signature) : signature;

            // 4) 验签
            ISigner verifier = SignerUtilities.GetSigner("SM3WITHSM2");
            verifier.Init(false, keyParam);
            verifier.BlockUpdate(data, 0, data.Length);
            return verifier.VerifySignature(sigDer);
        }

        /// <summary>
        /// 基于 SM2 曲线的密钥派生（ECDH + SM3-KDF）。
        /// 注意：这是“替代方案”，并非严格的 GM/T 0003-2012 SM2 密钥交换（KAP/KAE）。
        /// 若需严格 SM2 KEP（涉及双重密钥对与会话确认），请告知以改用 BouncyCastle 的 SM2KeyExchange 适配。
        /// </summary>
        /// <param name="myPrivateKey">本方私钥 D（无符号大端）。</param>
        /// <param name="peerPublicKey">对端公钥 Q 的编码（默认非压缩 0x04 前缀）。</param>
        /// <param name="keySizeBytes">期望导出会话密钥字节数（默认 16=128bit）。</param>
        /// <param name="kdfSalt">可选额外上下文（如双方 ID 拼接），将并入 KDF。</param>
        /// <returns>派生出的对称密钥字节（长度 = keySizeBytes）。</returns>
        public byte[] DeriveSharedKey(byte[] myPrivateKey, byte[] peerPublicKey, int keySizeBytes = 16, byte[]? kdfSalt = null)
        {
            if (keySizeBytes <= 0) throw new ArgumentOutOfRangeException(nameof(keySizeBytes));

            // 1) ECDH 基本协商，使用 SM2 曲线域参数
            BigInteger d = new BigInteger(1, myPrivateKey);
            var priv = new ECPrivateKeyParameters(d, domainParams);
            var q = sm2Params.Curve.DecodePoint(peerPublicKey);
            var pub = new ECPublicKeyParameters(q, domainParams);

            var agree = new ECDHBasicAgreement();
            agree.Init(priv);
            BigInteger zInt = agree.CalculateAgreement(pub);
            byte[] z = zInt.ToByteArrayUnsigned(); // 共享秘密（不包含 ZA/ZB）

            // 2) SM3-KDF（简化版）：K = SM3(z || salt || ct) 迭代拼接，截取所需长度
            return Sm3Kdf(z, keySizeBytes, kdfSalt);
        }

        #region 私有辅助：签名格式转换、KDF
        // DER -> r||s（每段定长 outLen 字节）
        static byte[] DerToPlainRS(byte[] der, int outLen)
        {
            var seq = (Asn1Sequence)Asn1Object.FromByteArray(der);
            var r = ((DerInteger)seq[0]).PositiveValue.ToByteArrayUnsigned();
            var s = ((DerInteger)seq[1]).PositiveValue.ToByteArrayUnsigned();
            return Concat(FixedLen(r, outLen), FixedLen(s, outLen));
        }

        // r||s（64字节）-> DER
        static byte[] PlainRSToDer(byte[] plain)
        {
            if (plain.Length % 2 != 0) throw new ArgumentException("Invalid r||s length", nameof(plain));
            int n = plain.Length / 2;
            byte[] r = new byte[n];
            byte[] s = new byte[n];
            Buffer.BlockCopy(plain, 0, r, 0, n);
            Buffer.BlockCopy(plain, n, s, 0, n);

            var v = new Org.BouncyCastle.Asn1.Asn1EncodableVector();
            v.Add(new DerInteger(new BigInteger(1, r)));
            v.Add(new DerInteger(new BigInteger(1, s)));
            return new DerSequence(v).GetEncoded();
        }

        static byte[] FixedLen(byte[] src, int len)
        {
            if (src.Length == len) return src;
            if (src.Length > len)
            {
                // 去掉前导 0 以适配定长
                var offset = src.Length - len;
                byte[] cut = new byte[len];
                Buffer.BlockCopy(src, offset, cut, 0, len);
                return cut;
            }
            else
            {
                byte[] pad = new byte[len];
                Buffer.BlockCopy(src, 0, pad, len - src.Length, src.Length);
                return pad;
            }
        }

        static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] x = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, x, 0, a.Length);
            Buffer.BlockCopy(b, 0, x, a.Length, b.Length);
            return x;
        }

        // 简化 SM3-KDF：K = SM3(z || salt || ct) || SM3(z || salt || (ct+1)) ... 直到长度满足
        static byte[] Sm3Kdf(byte[] z, int outLen, byte[]? salt)
        {
            var digest = new SM3Digest();
            byte[] outKey = new byte[outLen];
            byte[] ct = new byte[4]; // 计数器（大端）
            int generated = 0;
            uint counter = 1;

            while (generated < outLen)
            {
                digest.Reset();
                digest.BlockUpdate(z, 0, z.Length);
                if (salt != null && salt.Length > 0)
                    digest.BlockUpdate(salt, 0, salt.Length);
                ToBigEndian(counter++, ct);
                digest.BlockUpdate(ct, 0, ct.Length);

                byte[] buf = new byte[digest.GetDigestSize()];
                digest.DoFinal(buf, 0);

                int toCopy = Math.Min(buf.Length, outLen - generated);
                Buffer.BlockCopy(buf, 0, outKey, generated, toCopy);
                generated += toCopy;
            }
            return outKey;
        }

        static void ToBigEndian(uint n, byte[] bs)
        {
            bs[0] = (byte)(n >> 24);
            bs[1] = (byte)(n >> 16);
            bs[2] = (byte)(n >> 8);
            bs[3] = (byte)(n);
        }
        #endregion
    }
}
