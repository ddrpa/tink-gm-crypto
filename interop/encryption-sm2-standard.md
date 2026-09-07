# 互操作：标准 SM2 公钥加密（GB/T 32918.4，C1C3C2）

适用于：**加密方**持有接收者的公钥 `Q` 向其发送密文，**解密方**持有私钥 `d` 解密。

> 这是唯一一种“密文为国标格式、可与其他国密实现（BC/OpenSSL/GmSSL）直接互通”的公钥加密方案；
> 需要携带关联数据时请改用本库的 SM2 混合加密（[encryption-sm2-hybrid.md](encryption-sm2-hybrid.md)，
> 但注意那是自定义格式）。

## 1. 参数（固定）

| 参数 | 值 |
| --- | --- |
| 曲线 | sm2p256v1 |
| KDF/摘要 | SM3（GB/T 32918.4 的 KDF 与 C3 摘要均使用 SM3） |
| 密文布局 | **C1 ‖ C3 ‖ C2**（GB/T 32918.4；OpenSSL/GmSSL 的 SM2 默认亦为此布局） |
| C1 | 65 字节非压缩点 `04 ‖ X ‖ Y` |
| C3 | 32 字节 SM3 摘要 |
| C2 | 与明文等长的密文（SM2 为流式异或 + 摘要） |
| 关联数据 | **不支持**：contextInfo 必须为 `null` 或空，非空直接报错 |
| 明文 | 必须非空（SM2 引擎不支持零长度输入） |

## 2. 密文线格式（RAW，无前缀）

```
密文 = C1(65, 04‖X‖Y) ‖ C3(32) ‖ C2(明文长)         （总长 = 97 + 明文长）
```

## 3. 参考实现

文件：`src/test/java/cc/ddrpa/interop/bc/Sm2StandardEncryption.java`。核心用法：

```java
// 加密方（需要接收者公钥 Q，64 字节 X‖Y）
byte[] ciphertext = Sm2StandardEncryption.encrypt(Q64Bytes, plaintextBytes);

// 解密方（需要私钥 d，32 字节）
byte[] plaintext = Sm2StandardEncryption.decrypt(d32Bytes, ciphertext);
```

实现要点：使用 BC 低层 `SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2)`；加密以随机临时密钥对
初始化（`ParametersWithRandom`）。解密失败统一抛出 `GeneralSecurityException("Decryption failed")`。

## 4. Tink 侧：生成/接收该格式

- 注册：`HybridEncryptWrapper.register(); HybridDecryptWrapper.register();
  Sm2EncryptionKeyManager.registerPair(true);`
- 使用具名参数 `SM2_ENCRYPTION_RAW` 生成密钥集；把公钥密钥集的 `Q` 发给加密方。
- RAW 密文即标准 C1C3C2；TINK 前缀变体（`SM2_ENCRYPTION`）输出为
  `0x01 ‖ keyId(4 字节大端) ‖ C1C3C2`，收到该变体密文时需先剥离前缀再解密。
- contextInfo：调用 `encrypt/decrypt` 时传入 `null` 或空数组；传非空会报错。

## 5. 注意

- 布局/编码三件事不能错：`C1C3C2` 顺序、非压缩点（`04` 开头）、SM3。部分库默认输出 `C1C2C3`
  或压缩点，需显式配置。
- 空明文非法（明文长度 ≥ 1）。
- 明文较长时直接做“分段后逐段加密”即可（每段独立 SM2 加密没有长度上限的额外约束）；若追求效率
  或需要 AAD，考虑用 SM4-GCM 或混合方案加密内容、SM2 只加密会话密钥（混合方案见另一文档）。
- 解密失败统一报错；不要泄露“C3 校验失败”等细节。
- 与 GmSSL/OpenSSL 互通时注意其命令行默认输出格式与本库一致（C1C3C2、非压缩）；不同版本的
  命令行选项可能不同，建议以库调用为主，仓库内自动验证覆盖 BouncyCastle。

## 6. 仓库内自检与固定向量

- 双向自检：`cc.ddrpa.interop.Sm2StandardEncryptionInteropTest`。
- 固定密钥与历史向量（`cc.ddrpa.interop.testing.InteropFixtures`）：
  - `d` / `Q`：见 `SM2_PRIVATE_D_HEX` / `SM2_PUBLIC_Q_HEX`
  - 明文：`SAMPLE_PLAINTEXT`（UTF-8 常量文本）
  - 历史密文：`SM2_STANDARD_ENCRYPTION_VECTOR_CIPHERTEXT_HEX`（199 字节 = 97+102，可用
    `Sm2StandardEncryption.decrypt(d, …)` 独立解出上述明文）
