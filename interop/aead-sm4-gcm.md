# 互操作：SM4-GCM AEAD（对称加密）

适用于：双方共享一个 16 字节 SM4 密钥后，用 SM4-GCM 做带关联数据的对称加密。

## 1. 参数（固定）

| 参数 | 值 |
| --- | --- |
| 算法 | SM4-GCM（GB/T 32907 SM4 分组 + GCM 工作模式） |
| 密钥 | 16 字节（128 位） |
| IV / nonce | 12 字节（96 位），随机生成，每次加密不同 |
| tag | 16 字节（128 位） |
| 关联数据 AAD | 任意字节；由 GCM 认证，`null` 与空数组等价 |

## 2. 密文线格式（RAW，无任何前缀）

```
密文 = IV(12) ‖ SM4-GCM 密文 ‖ tag(16)          （总长 = 28 + 明文长）
```

与 BouncyCastle / OpenSSL / GmSSL 使用 SM4-GCM 时的通用布局一致。

## 3. 参考实现

文件：`src/test/java/cc/ddrpa/interop/bc/Sm4GcmAead.java`（整包拷贝见
[README](README.md)）。核心用法：

```java
byte[] key = HexUtil.decode("000102030405060708090a0b0c0d0e0f"); // 16 字节 SM4 密钥
byte[] aad = "recipient@example.org".getBytes(StandardCharsets.US_ASCII);

byte[] ciphertext = Sm4GcmAead.encrypt(key, plaintext, aad);     // 密文 = IV‖密文‖tag
byte[] plaintext2 = Sm4GcmAead.decrypt(key, ciphertext, aad);    // tag 校验失败抛异常
```

要点：Java 无内置 SM4-GCM，类内部通过
`Cipher.getInstance("SM4/GCM/NoPadding", new BouncyCastleProvider())` 显式指定 BC 提供者，调用方
无需全局注册 BC。实现只依赖 JDK + bcprov。

## 4. Tink 侧：生成/接收该格式

- 生成密钥并注册：`AeadConfig.register(); Sm4GcmKeyManager.register(true);`
- 使用具名参数 `SM4_GCM_RAW`（或 `Sm4GcmParameters.Variant.NO_PREFIX` 手动构建）生成密钥集；
  该变体加密输出即上述格式（无前缀）。
- 若系统收到的是 **TINK 前缀变体**（默认 `SM4_GCM` 模板）产生的数据，需要按
  `0x01 ‖ keyId(4 字节大端)` 剥离前缀后再处理（剥离与校验逻辑在仓库自检 `Sm4GcmInteropTest` 中
  有覆盖，见下文）。跨系统新对接建议直接使用 RAW 变体，避免前缀处理。

## 5. 注意

- GCM 的 IV 必须唯一：随机 12 字节 IV 碰撞概率可忽略；若自行提供 IV（`encryptWithIv`），严禁
  对同一密钥重复使用同一 IV。
- 解密失败请统一报错，不要区分“tag 校验失败”等细节。
- 空明文合法（密文 28 字节）。
- 与 OpenSSL/GmSSL 互通时按标准 SM4-GCM 参数即可；OpenSSL 命令行对 AEAD 的处理与库调用不同，
  建议用库调用（EVP）方式。

## 6. 仓库内自检与固定向量

- 双向自检：`cc.ddrpa.interop.Sm4GcmInteropTest`（Tink 加密→BC 解密、BC 加密→Tink 解密、错误
  AAD/篡改拒绝、TINK 前缀剥离）。
- 固定密钥与历史向量：`cc.ddrpa.interop.testing.InteropFixtures`：
  - SM4 密钥：`000102030405060708090a0b0c0d0e0f`
  - 明文：`SAMPLE_PLAINTEXT`（UTF-8 常量文本）
  - AAD：`recipient@example.org`
  - 历史密文：`SM4_GCM_VECTOR_CIPHERTEXT_HEX`（130 字节 = 12+102+16；由本库生成的一次性快照，
    可用 `Sm4GcmAead.decrypt` 独立解出上述明文）
