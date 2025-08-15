using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace BugFree.Security
{
    /// <summary>SSL提供者</summary>
    /// <remarks>你的连接不是专用连接 攻击者可能试图从 192.168.31.22 窃取你的信息(例如，密码、消息或信用卡)。
    /// 详细了解此警告net::ERR_CERT_AUTHORITY_INVALID192.168.31.22 使用加密来保护你的信息。
    /// 这次，当 Microsoft Edge 尝试连接到 192.168.31.22 时，网站发回了不正常和不正确的凭据。
    /// 如果攻击者尝试假冒 192.168.31.22，或者 WLAN 登录屏幕已中断连接，则可能会发生这种情况。你的信息仍然安全，因为在交换任何数据之前，Microsoft Edge 停止了连接。
    /// 你现在无法访问 192.168.31.22，因为网站使用的是 HSTS。网络错误和攻击通常是暂时的，因此该页面以后可能会恢复正常
    /// 操作步骤（Windows）：双击 .pfx 文件导入证书。
    /// 选择「本地计算机」而不是当前用户。
    /// 导入路径选择：受信任的根证书颁发机构。
    /// 输入密码，完成导入。
    /// 重启浏览器（彻底退出进程）。
    /// 再次访问 https://192.168.31.22。
    /// </remarks>
    public class SelfSignedCertProvider
    {
        /// <summary>生成自签名证书</summary>
        public void GenerateSelfSignedCert(string pfxPath, string pfxName, string password, IList<string> dnsNames, IList<string> ipAddresses, int year = 1)
        {
            var path = Path.Combine(pfxPath, pfxName);
            if (File.Exists(path))
            {
                try
                {
                    var cert = new X509Certificate2(path, password);
                    // 提前 30 天重新生成 证书还有效，不需要重新生成
                    if (cert.NotAfter > DateTime.UtcNow.AddDays(30)) { return; }
                }
                catch { }// 读取失败说明文件可能损坏，继续重新生成
                // 删除旧证书
                File.Delete(path);
                Directory.Delete(Path.GetDirectoryName(path)!);
            }
            {
                // 创建 RSA 密钥对
                using var ecdsa = RSA.Create(2048);
                // 构建证书请求（CSR），指定主题名称、密钥算法、哈希算法
                var certReq = new CertificateRequest($"CN={dnsNames.FirstOrDefault() ?? "localhost"}", ecdsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                // 添加基本约束：不是 CA，路径长度为 0，不关键扩展
                certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                // 添加密钥用法：仅用于数字签名
                certReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
                // 添加主体密钥标识符（Subject Key Identifier）
                certReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certReq.PublicKey, false));
                certReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                   new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true)); // Server Authentication
                // 构建 SAN（Subject Alternative Name）扩展
                var sanBuilder = new SubjectAlternativeNameBuilder();
                foreach (var dns in dnsNames) { sanBuilder.AddDnsName(dns); }
                foreach (var ip in ipAddresses) { sanBuilder.AddIpAddress(IPAddress.Parse(ip)); }
                // 添加 SAN 扩展
                certReq.CertificateExtensions.Add(sanBuilder.Build());
                // 确保路径存在
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                // 创建自签名证书，有效期 N 年
                var cert = certReq.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(year));
                // 导出为 PFX 格式的字节数组
                var pfxbytes = cert.Export(X509ContentType.Pfx, password);
                // 保存证书到文件
                File.WriteAllBytes(path, pfxbytes);
                // 导出为 cer 格式的字节数组
                var cerbytes = cert.Export(X509ContentType.Cert); // 注意：不带私钥
                // 保存证书到文件
                File.WriteAllBytes(Path.ChangeExtension(path, ".cer"), cerbytes);
            }
        }
    }
}
