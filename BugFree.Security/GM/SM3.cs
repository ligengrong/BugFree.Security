using Org.BouncyCastle.Crypto.Digests;

namespace BugFree.Security.GM
{
    /// <summary>
    /// SM3 哈希算法实现，兼容 HashAlgorithm API，基于 Portable.BouncyCastle。
    /// </summary>
    public class SM3 : System.Security.Cryptography.HashAlgorithm
    {
        /// <summary>内部 BouncyCastle SM3 实现</summary>
        SM3Digest _digest;

        /// <summary>
        /// 初始化 SM3 实例，设置 HashSize=256。
        /// </summary>
        public SM3()
        {
            _digest = new SM3Digest();
            HashSizeValue = 256;
        }

        /// <summary>
        /// 创建 SM3 实例，兼容 HashAlgorithm.Create() 习惯。
        /// </summary>
        public new static SM3 Create()
        {
            return new SM3();
        }
        /// <summary>
        /// 重置内部状态。
        /// </summary>
        public override void Initialize()
        {
            _digest.Reset();
        }

        /// <summary>
        /// 核心散列过程：对输入分块数据做更新。
        /// </summary>
        /// <param name="array">输入数据</param>
        /// <param name="ibStart">起始偏移</param>
        /// <param name="cbSize">长度</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            _digest.BlockUpdate(array, ibStart, cbSize);
        }

        /// <summary>
        /// 结束散列，输出最终结果。
        /// </summary>
        /// <returns>哈希结果字节数组</returns>
        protected override byte[] HashFinal()
        {
            byte[] result = new byte[_digest.GetDigestSize()];
            _digest.DoFinal(result, 0);
            return result;
        }

        /// <summary>
        /// 计算输入数据的 SM3 哈希值（快捷方法）。
        /// </summary>
        /// <param name="data">输入数据</param>
        /// <returns>哈希值</returns>
        public new static byte[] ComputeHash(byte[] data)
        {
            var sm3 = new SM3Digest();
            sm3.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[sm3.GetDigestSize()];
            sm3.DoFinal(result, 0);
            return result;
        }

        /// <summary>
        /// 释放资源。
        /// </summary>
        /// <param name="disposing">是否由托管代码显式调用</param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }
}
