# 互操作：SM4-GCM-HKDF 流式 AEAD（本库自定义格式）

适用于：双方共享一个 16 字节初始密钥材料（IKM）后，对大文件/流式数据做“边读边加解密、支持随机
读写位置解密”的对称加密。

> ⚠️ **自定义格式**：该线格式不是国标，而是本库（及其对照实现的 Google Tink AES-GCM-HKDF 流式
> 布局）自定义的分段格式，不能指望通用国密库直接支持。双方都实现本文档格式即可互通；建议直接
> 采用本仓库参考实现（`Sm4GcmHkdfStreamingAead`，它已与本库 Tink 侧做过双向自动验证）。
> 另注意：**HKDF 使用 HMAC-SHA256（不是 SM3）**、段内密文为 SM4-GCM。

## 1. 参数

| 参数 | 值 |
| --- | --- |
| 密钥 | 初始密钥材料 IKM（本库模板为 16 字节，实际实现要求 ≥ 16 字节） |
| 派生 | 每份密文一个随机 salt（16 字节）；数据密钥 = HKDF-SHA256(ikm, salt=该 salt, info=AAD, L=16) |
| 段 GCM | SM4-GCM：16 字节密钥、12 字节 nonce、16 字节 tag、无 AAD（AAD 已通过 HKDF info 绑定） |
| 密文段大小 C | 4KB 模板 C=4096；1MB 模板 C=1048576 |

## 2. 密文线格式

```
密文 = header ‖ segment_0 ‖ segment_1 ‖ … ‖ segment_k

header = headerLength(1 字节, = 24) ‖ salt(16) ‖ noncePrefix(7)
segment_i 的 nonce(12) = noncePrefix ‖ u32be(i) ‖ last      # last=1 仅最后一段
```

- header 长度恒为 24（1+16+7），首字节即 24。
- 分段规则（令 p = C−16 为每段明文容量，首段明文容量为 C−40）：
  - 第 0 段密文长 C−24（含 16 字节 tag），第 1…k 段密文各长 C；
  - 加密时先凑满首段明文容量，再逐段凑满 p；最后一段放剩余明文（可为空），置 last=1；
  - 空明文：密文 = header + 仅含 tag 的最后一段，共 40 字节；
  - 总长 = 24 + Σ各段密文长；等价公式 `ciphertextSize(明文长, C)` 见参考实现。
- 段序号 i 从 0 开始，u32be 为 4 字节大端计数（2^32 段内安全）。
- 解密算法：读 header → 用 salt/AAD 派生密钥 → 第 0 段尝试读 C−24 字节、之后每段尝试读 C 字节；
  读到文件尾的那一段即最后一段（可能更短，last=1）→ 逐段 SM4-GCM 解密并校验 tag。
- 每份密文使用随机 salt 与随机 noncePrefix（各一次），因此同一明文多次加密结果不同。

## 3. 参考实现

文件：`src/test/java/cc/ddrpa/interop/bc/Sm4GcmHkdfStreamingAead.java`。核心用法：

```java
// 字节数组便捷方法
byte[] ciphertext = Sm4GcmHkdfStreamingAead.encryptBytes(
    ikm16Bytes, 4096 /* 或 1024*1024 */, aadBytes, plaintextBytes);
byte[] plaintext = Sm4GcmHkdfStreamingAead.decryptBytes(
    ikm16Bytes, 4096, aadBytes, ciphertext);

// 真·流式接口（InputStream/OutputStream），适合大文件
Sm4GcmHkdfStreamingAead.encrypt(ikm, 4096, aad, plaintextIn, ciphertextOut);
Sm4GcmHkdfStreamingAead.decrypt(ikm, 4096, aad, ciphertextIn, plaintextOut);
```

实现要点：HKDF-SHA256 用 JDK `Mac("HmacSHA256")` 手工实现（RFC 5869）；段 SM4-GCM 用显式 BC
provider；nonce 构造 `prefix(7) ‖ u32be(段号) ‖ last`；段缓冲一次只占用一个密文段大小的内存，
真正支持流式/大文件。

## 4. Tink 侧：生成/接收该格式

- 注册：`StreamingAeadConfig.register(); Sm4GcmHkdfStreamingKeyManager.register(true);`
- 具名参数：`SM4_GCM_HKDF_4KB`、`SM4_GCM_HKDF_1MB`（只有这两档密文段大小；密钥 16 字节）。
- 流式 AEAD 没有前缀概念，密文即 §2 布局。本库（Tink）侧通过 `newEncryptingStream/…Channel` 加密、
  `newDecryptingStream/…Channel` 解密，加密与解密必须使用相同的 AAD 参数。

## 5. 注意

- AAD 通过 HKDF info 绑定整份密文（不是逐段 GCM AAD）：解密端 AAD 不一致会在首段解密即失败。
- 篡改任意一段都会被该段 GCM tag 校验拦下；但随机读优化（seek）场景仍建议整文件认证后再信任。
- 段边界数字（C−40、C−16、C−24）务必与文档一致，否则无法互通；仓库自检覆盖边界长度。
- 与标准 SM4-GCM 或国标流式（如 SM4-CTR + SM3-HMAC）没有对应关系，勿混用。

## 6. 仓库内自检与固定向量

- 双向自检：`cc.ddrpa.interop.Sm4GcmHkdfStreamingInteropTest`（4KB/1MB 模板、段边界长度、空明文/
  空 AAD、错误 AAD、篡改 header/中段拒绝）。
- 固定密钥与历史向量（`cc.ddrpa.interop.testing.InteropFixtures`）：
  - IKM：`000102030405060708090a0b0c0d0e0f`；密文段大小 4096；AAD：`recipient@example.org`
  - 明文：`SM4_GCM_HKDF_STREAMING_VECTOR_PLAINTEXT_HEX`（100 字节，确定性内容）
  - 历史密文：`SM4_GCM_HKDF_STREAMING_VECTOR_CIPHERTEXT_HEX`（140 字节 = 24+100+16，可用
    `Sm4GcmHkdfStreamingAead.decryptBytes(ikm, 4096, aad, …)` 独立解出上述明文）
