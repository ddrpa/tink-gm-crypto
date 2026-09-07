# 互操作：SM2-KEM + SM4-GCM 混合加密（本库自定义格式）

对方系统（不使用 Google Tink）与本库 `SM2_HYBRID_RAW`（NO_PREFIX 变体）互通时的线格式、参数与
对方侧参考实现说明。

> ⚠️ **自定义格式**：本方案是“SM2 密钥封装 + SM4-GCM 数据封装”的混合加密，密文布局**不是**国标
> SM2 密文格式、也非任何通用标准，**不能**与 OpenSSL/GmSSL 等实现对同一段数据直接互解。它解决
> “标准 SM2 不支持关联数据”的问题：`contextInfo` 会作为 SM4-GCM 关联数据被完整认证。跨系统
> 互通时若不要求关联数据，请优先使用标准 SM2（[encryption-sm2-standard.md](encryption-sm2-standard.md)）。
> 双方都实现本文档格式时即可互通（包括与大文件场景下的 SM4-GCM 分段配合使用）。

## 1. 参数（固定）

| 参数 | 值 |
| --- | --- |
| 曲线 | sm2p256v1 |
| 密钥封装 | 加密方每次生成临时 SM2 密钥对；C1 = 临时公钥非压缩点 `04‖X‖Y`（65 字节） |
| 共享点 | S = k·Q（k 为临时私钥标量，Q 为接收方公钥）；解密方重算 S = d·C1 |
| 密钥派生 | SM2-KDF（GB/T 32918.4 §5.4.3，SM3 计数型）以 x2‖y2（64 字节）为输入，输出 16 字节 |
| DEM | SM4-GCM：16 字节密钥、12 字节随机 nonce、16 字节 tag |
| 关联数据 | `contextInfo` 作为 SM4-GCM AAD 被认证；`null` 与空等价；解密必须传相同字节 |

## 2. 密文线格式（RAW，无前缀）

```
密文 = C1(65, 04‖X‖Y) ‖ nonce(12) ‖ SM4-GCM 密文 ‖ tag(16)      （总长 = 93 + 明文长）
```

（对应地：C1 长度 65 + nonce 12 = 77 字节固定头。）

## 3. 对方侧参考实现

文件：`src/test/java/cc/ddrpa/interop/bc/Sm2KemSm4GcmHybrid.java`。核心用法：

```java
// 加密方（需要接收者公钥 Q）
byte[] ciphertext = Sm2KemSm4GcmHybrid.encrypt(Q64Bytes, plaintextBytes, contextInfo);

// 解密方（需要私钥 d；contextInfo 必须与加密时完全一致）
byte[] plaintext = Sm2KemSm4GcmHybrid.decrypt(d32Bytes, ciphertext, contextInfo);
```

实现要点：BC 生成临时密钥对 → 共享点 `recipientQ.multiply(k)` 规范化后取仿射坐标 x2‖y2 → 按
GB/T 32918.4 KDF（4 字节大端计数器 + SM3）派生 16 字节 → JCE `SM4/GCM/NoPadding`（显式 BC
provider）加密，AAD = contextInfo。解密时 C1 点必须做曲线上/非无穷远校验。

## 4. Tink 侧：生成/接收该格式

- 注册：`HybridEncryptWrapper.register(); HybridDecryptWrapper.register();
  Sm2HybridKeyManager.registerPair(true);`
- 使用具名参数 `SM2_HYBRID_RAW` 生成密钥集，分发公钥 `Q`；`encrypt(plaintext, contextInfo)` /
  `decrypt(ciphertext, contextInfo)`。
- 若使用 **TINK 前缀变体**（`SM2_HYBRID`），输出前带 `0x01 ‖ keyId`，对方需先剥离。

## 5. 注意

- 每次加密随机生成临时密钥对与 nonce，因此同一明文多次加密结果不同，属正常。
- contextInfo 两端字节必须完全一致（包括为空时用空数组），否则解密失败。
- 公钥/私钥长度与编码同其他 SM2 方案（Q 64 字节、d 32 字节，定长大端，点用非压缩编码）。
- 若数据量很大，可先随机生成一次性 SM4-GCM 会话密钥加密内容，再对会话密钥使用本方案封装
  （KEM 思路）；直接逐段调用本方案则每段都会有 SM2 运算开销。

## 6. 仓库内自检与固定向量

- 双向自检：`cc.ddrpa.interop.Sm2HybridInteropTest`（含错误 contextInfo 拒绝、null/空等价、
  空明文、篡改拒绝）。
- 固定密钥与历史向量（`cc.ddrpa.interop.testing.InteropFixtures`）：
  - `d` / `Q`：见 `SM2_PRIVATE_D_HEX` / `SM2_PUBLIC_Q_HEX`
  - 明文：`SAMPLE_PLAINTEXT`；contextInfo：`SAMPLE_CONTEXT_INFO`（ASCII `request-2026-0001`）
  - 历史密文：`SM2_HYBRID_VECTOR_CIPHERTEXT_HEX`（195 字节 = 77+102+16，可用
    `Sm2KemSm4GcmHybrid.decrypt(d, …, contextInfo)` 独立解出上述明文）
