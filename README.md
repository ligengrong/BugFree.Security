# BugFree.Security

BugFree.Security 是一个基于 .NET 的安全加密库，覆盖对称加密、非对称加密、哈希/HMAC、国密（SM3/SM4）、数字签名、密钥交换、自签名证书等能力。目标是提供统一、简单、可靠的 API，适用于 .NET 5/6/7/8/9 与 .NET Standard 2.1，兼容常见 Web/服务端场景（含 Razor Pages）。

核心设计要点：
- 统一 Provider 接口与枚举，开箱即用的扩展方法（string 扩展 Encrypt/Decrypt/Sign/Verify 等）。
- 加解密输出自包含（含算法标识/必要元信息），默认安全参数（随机 IV/Nonce、强哈希等）。
- 选用标准库优先；必要时引入 BouncyCastle 以覆盖 AES-CTR/CFB/OFB、SM3/SM4、Blowfish、Twofish、Camellia 等。

## 功能矩阵（按阶段标注）

说明：
- 已实现（稳定）：默认可用，提供完整最小可用集。
- 进行中/待接入：代码草案或接口已预留，尚未在工厂注册或依赖缺失。
- 规划中：路线图阶段，尚未落地实现。

-### 对称加密
- 已实现（稳定）
	- AES（CBC）
	- AES-GCM（认证加密，嵌入 Nonce/Tag/AAD）
	- AES-CTR / AES-CFB / AES-OFB（基于 BouncyCastle）
	- DES、TripleDES、RC2（CBC）
	- Blowfish（CBC）、Twofish（CBC）、Camellia（CBC）
	- SM4（内部实现兼容 ECB/CBC；当前默认 ECB）
- 规划中
	- ChaCha20-Poly1305、AES-CCM、AES-SIV
	- XTS 模式（磁盘加密场景）

注意：对称加密统一走 `SymmetricProvider`，密文格式为 `算法编号$Base64(负载)`。SM4 的 Key 期望 16 字节十六进制（32 个 hex 字符）。

### 非对称加密 / 签名 / 密钥交换
- 已实现（稳定）
	- RSA：密钥对、加解密、签名/验签
	- DSA：签名/验签
	- ECDSA（P-256）：签名/验签
	- ECDH（P-256）：密钥交换
- 进行中/待接入
	- Ed25519：签名/验签（.NET 8+，已有 Provider 草案，尚未在工厂注册）
	- X25519：密钥交换（需第三方库，如 NSec；当前占位，默认不支持）
	- SM2：密钥对/加解密/签名/密钥交换（占位，未实现）
- 规划中
	- Ed448/X448、国密 SM2 全面接入（基于稳定依赖）
	- 更丰富曲线族群选择（P-384/P-521 等）

说明：非对称能力统一走 `AsymmetricProvider`。
- 加解密：当前仅 RSA 可用（SM2 入口已预留但尚未接入实现）。
- 签名/验签：RSA、DSA、ECDSA 可用；Ed25519 处于“待接入”。
- 密钥交换：ECDH 可用；X25519 处于“待接入/第三方”。

### 哈希 / HMAC / 密码哈希
- 已实现（稳定）
	- MD5、SHA1、SHA256/384/512
	- SHA3-256/384/512（BouncyCastle）
	- SM3（BouncyCastle）
	- HMAC：HMACMD5、HMACSHA1、HMACSHA256/384/512
- 进行中/待接入
	- PBKDF2（已有 Provider 草案，暂未启用）
	- Argon2i/Argon2d/Argon2id（已有 Provider 草案，暂未启用）
- 规划中
	- scrypt、bcrypt
	- BLAKE2/BLAKE3、SHAKE 系列

说明：`HashProvider.ComputeHash` 支持链式多算法并内嵌盐，输出格式为 `salt$hash$algorithms`，`Verify` 采用恒定时比较。

### 证书
- 已实现（稳定）
	- 自签名证书生成（RSA，支持 SAN：DNS/IP；导出 .pfx/.cer）

## 安装

通过 NuGet 安装（任选一种）：

```powershell
dotnet add package BugFree.Security
```

## 使用示例

### 1）哈希 / 验证
```csharp
using BugFree.Security;
var data = "This is a test string for hashing and encryption.";
var hash = data.ComputeHash(new[] { HashAlgorithm.SHA256 });
var ok = data.VerifyHash(hash);
```

### 2）对称加密
```csharp
using BugFree.Security;
var key = "0123456789abcdef"; // 任意口令字符串（AES 等），SM4 请使用 32 个 hex 字符
var plain = "This is a test string for hashing and encryption.";
var cipher = plain.EncryptSymmetric(SymmetricAlgorithm.Aes, key);
var back  = cipher.DecryptSymmetric(key); // 解密无需再次传算法，算法编号已包含在密文中
```

### 3）非对称
#### 3.1 RSA 加解密
```csharp
using BugFree.Security;
var plain = "This is a test string for hashing and encryption.";
var keyPair = AsymmetricProvider.GenerateKeyPair(AsymmetricAlgorithm.RSA);
var cipher = plain.EncryptAsymmetric(keyPair.PublicKey, AsymmetricAlgorithm.RSA);
var back   = cipher.DecryptAsymmetric(keyPair.PrivateKey);
```

#### 3.2 签名 / 验签
（算法与密钥需匹配，例如这里用 RSA；也可以换成 ECDSA/DSA 并用对应的密钥对）
```csharp
using BugFree.Security;
var data = "This is a test string for hashing and encryption.";
var kp = AsymmetricProvider.GenerateKeyPair(AsymmetricAlgorithm.RSA);
var sig = data.Sign(kp.PrivateKey, AsymmetricAlgorithm.RSA);
var ok  = data.Verify(sig, kp.PublicKey);
```

#### 3.3 密钥交换（ECDH）
```csharp
using BugFree.Security;
var a = AsymmetricProvider.GenerateKeyPair(AsymmetricAlgorithm.ECDH);
var b = AsymmetricProvider.GenerateKeyPair(AsymmetricAlgorithm.ECDH);
var s1 = a.PrivateKey.GenerateSharedSecret(b.PublicKey, AsymmetricAlgorithm.ECDH);
var s2 = b.PrivateKey.GenerateSharedSecret(a.PublicKey, AsymmetricAlgorithm.ECDH);
```

## 注意事项
- 对称密钥派生：多数实现会对传入 key 做哈希/截断派生（如 AES 使用 SHA256 派生），请避免直接复用弱口令。
- SM4 Key：请使用 16 字节十六进制字符串（32 个 hex 字符）。
- AES-GCM：输出中已包含 Nonce/Tag/AAD，解密无需额外参数。
- 非对称能力：目前仅 RSA 支持加解密；SM2/Ed25519/X25519 为“待接入/规划中”。

## 路线图（Roadmap）
- 阶段 A（当前）：
	- 对称：AES 全家桶、传统分组（DES/3DES/RC2）、现代分组（Blowfish/Twofish/Camellia）、SM4
	- 非对称：RSA/DSA/ECDSA/ECDH；自签名证书
	- 哈希：SHA2/SHA3/SM3 + HMAC
- 阶段 B（短期）：
	- 接入 Ed25519（.NET 8+）与 PBKDF2/Argon2id Provider
	- 完善 SM4 模式切换与文档（ECB/CBC 明示）
	- 增补示例与单元测试矩阵
- 阶段 C（中期）：
	- SM2（加解密/签名/密钥交换）完整接入
	- X25519（第三方依赖可选）
	- 新增 ChaCha20-Poly1305、HKDF、BLAKE2/3
- 阶段 D（长期）：
	- 更多曲线与硬件加速适配（CNG/Apple Crypto/PKCS#11 等）
	- 跨平台互操作测试与 FIPS 场景文档

## 依赖环境

- 运行/开发：.NET 8.0（当前项目采用单目标构建）
- 计划：视需求增加多目标（如 .NET 7/9、.NET Standard 2.1）
- 部分算法依赖 BouncyCastle（已通过 NuGet 引入）

## 近期更新

- 目标框架切换为 net8.0（单目标构建，简化依赖与发布）
- 依赖更新：BouncyCastle.Cryptography 升级至 2.6.2
- 预引入 Konscious.Security.Cryptography.Argon2（为后续密码哈希 Provider 做准备，默认未启用）
- 文档优化：明确对称密文格式（算法编号$Base64(负载)）与 AES-GCM 的 Nonce/Tag/AAD 自包含说明；修正 SM4 条目缩进

## 贡献

欢迎提交 Issue 或 Pull Request，一起完善算法支持、优化 API/性能与文档示例。

## 联系方式

如有问题或建议，请联系邮箱：**ligengrong@hotmail.com**
