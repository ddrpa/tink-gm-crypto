# 面向对方系统（不使用 Google Tink）的互操作资料

加解密需求通常发生在两个独立系统之间。本仓库为 Google Tink 增加了国密 SM2/SM4 支持，但如果
**对方系统不依赖 Google Tink**，对方开发人员无法直接使用本库的 keyset/原语 API。本目录为对方
开发人员提供“基于常见加解密库（Java + BouncyCastle）的替代方案”：

1. 每个算法一张线格式说明（密文/签名布局、参数、密钥材质）；
2. 一套**对方侧参考实现**（纯 BouncyCastle + JDK，见 `src/test/java/cc/ddrpa/interop/bc/`，可整包拷贝，
   零 Tink 依赖）；
3. 仓库内**双向自检**（Tink ⇄ 纯 BC）与固定历史向量，确保文档示例真实可用；
4. 密钥交换指引（如何把本库的 keyset 转成对方可用的裸密钥）。

## 使用路径（快速决策）

| 你的需求 | 本库推荐参数 | 线格式 | 对方文档 | 分级 |
| --- | --- | --- | --- | --- |
| 对称加密（文件/消息，可带关联数据） | `SM4_GCM_RAW` | `IV(12) ‖ SM4-GCM 密文 ‖ tag(16)` | [aead-sm4-gcm.md](aead-sm4-gcm.md) | ✅ 直接互操作（标准 SM4/GCM） |
| 大文件/流式加密 | `SM4_GCM_HKDF_4KB` / `SM4_GCM_HKDF_1MB` | Tink 流式布局（header + 分段 SM4-GCM） | [streaming-aead-sm4-gcm-hkdf.md](streaming-aead-sm4-gcm-hkdf.md) | ⚠️ 自定义格式，按文档实现 |
| 数字签名 | `SM2_SIGN_RAW` | 64 字节 `r ‖ s` | [signature-sm2.md](signature-sm2.md) | ✅ 直接互操作（GB/T 32918.2 默认 ID） |
| 公钥加密（国标密文） | `SM2_ENCRYPTION_RAW` | `C1(65) ‖ C3(32) ‖ C2` | [encryption-sm2-standard.md](encryption-sm2-standard.md) | ✅ 直接互操作（GB/T 32918.4 C1C3C2） |
| 公钥加密（可携带 contextInfo） | `SM2_HYBRID_RAW` | `C1(65) ‖ nonce(12) ‖ SM4-GCM` | [encryption-sm2-hybrid.md](encryption-sm2-hybrid.md) | ⚠️ 自定义格式，按文档实现 |

> 分级说明
> - **✅ 直接互操作**：密文/签名即为国标或通用格式，对方用任何支持国密的库（BC/OpenSSL/GmSSL 等）
>   按文档说明即可互通。
> - **⚠️ 自定义格式**：线格式由本库（及其对照的 Google Tink 流式布局）定义，**不是国标**；若
>   对方必须与这两种算法互通，请按对应文档实现格式；若只是需要“SM2 公钥加密”，优先使用上面的
>   标准 SM2（✅），除非确需携带 contextInfo / 需要混合加密特性。

## 对方侧参考实现（Java + BouncyCastle）

- 目录：`src/test/java/cc/ddrpa/interop/bc/`，全部文件**只依赖 JDK 11+ 与
  `org.bouncycastle:bcprov-jdk18on`（1.78 或更新）**，不依赖 Google Tink / JUnit，可整体拷贝到对方工程
  （重命名包名即可）。
- 每个算法一个类（`Sm4GcmAead`、`Sm4GcmHkdfStreamingAead`、`Sm2Signature`、`Sm2StandardEncryption`、
  `Sm2KemSm4GcmHybrid`），另有 `Sm2BcUtil`（曲线/密钥工具）与 `HexUtil`。
- `BcInteropDemo` 提供一条 main 自演示：拷贝后执行
  `java -cp .:bcprov-jdk18on-<version>.jar cc.ddrpa.interop.bc.BcInteropDemo` 即可看到各算法往返自检
  全部 PASS（内置固定测试密钥）。
- 这些文件在本仓库内被自动测试（见下文“仓库内自检”），请以仓库当前代码为准拷贝，勿复制过时的
  副本。

## 仓库内自检

在仓库根目录执行（需要 JDK 11+；首次会联网拉取 Maven 依赖）：

```shell
./mvnw test -Dtest='cc.ddrpa.interop.*Test'
```

覆盖矩阵见各算法文档，核心保证：
- 方向一：本库（Tink）加密/签名 → 对方参考实现（纯 BC）解密/验签；
- 方向二：对方参考实现加密/签名 → 本库解密/验签；
- 固定历史向量：用**纯 BC** 独立解密/验签本仓库固化的“Tink 侧历史输出”，防止两侧共享同一实现错误
  （向量与固定密钥见 `src/test/java/cc/ddrpa/interop/testing/InteropFixtures.java`）。

## 密钥交换与总则

1. **RAW 变体**：跨系统一律用 RAW（`*_RAW`）密钥/模板。RAW 输出/输入**不带** Tink 前缀，与对方
   格式一一对应；TINK 前缀（`0x01 ‖ keyId(4 字节大端)`）是 Tink 的 keyset 分派机制，其他实现不认识。
2. **对方能做什么、需要什么**：
   - SM4-GCM / 流式：对方拿到 SM4 密钥（16 字节 hex/base64）即可加密与解密；
   - SM2：**加密/验签**只分发公钥 `Q`（64 字节 `X‖Y`）；**解密/签名**必须持有私钥 `d`（32 字节）——
     私钥只能由密钥属主保存，经安全通道分发，切勿明文发送 keyset 文件。
3. **如何从本库 keyset 导出裸密钥**：参考
   `src/test/java/cc/ddrpa/playground/ExportKeysForInterop.java`（读明文 JSON keyset，逐个打印
   keyId、前缀 hex 与密钥材质 hex）。请不要引导对方解析 Tink keyset JSON（`keyValue` 是 Tink 私有
   proto 布局）。
4. **密钥/参数固定编码**：SM2 坐标与私钥均为 32 字节定长大端无符号（不省略前导零）；公钥点使用
   非压缩编码 `04 ‖ X ‖ Y`；SM4 密钥 16 字节；曲线固定 `sm2p256v1`（BC 注册名，等价于 GM/T 0009 /
   GB/T 32918.5 的 SM2 曲线）。
5. **失败处理**：请让对方解密失败时返回统一错误（不要区分“tag 不对”“C1 非法”等），避免把解密
   侧变成 oracle；本库侧也是统一失败语义。
6. **样本数据（固定测试密钥与历史向量）**：见
   `src/test/java/cc/ddrpa/interop/testing/InteropFixtures.java`——固定 SM4 密钥、固定 SM2 密钥对、
   固定消息/明文/关联数据，以及由本库 Tink 实现生成的历史密文/签名 hex。对方可用这些值对照自验。

## 常见陷阱速查

- 部分库默认把 SM2 加密输出为 `C1C2C3` 或压缩点：标准 SM2 互操作必须 `C1C3C2` + 非压缩点。
- 部分库的 SM2 签名默认 DER 包装或使用非默认用户标识：互操作要求 64 字节 `r‖s` + 默认 ID
  `1234567812345678`，且是对**原始消息**签名（无需预先哈希）。
- 本库流式 AEAD 的 HKDF 使用 **HMAC-SHA256**（不是 SM3），与“国密标配 SM3”不同，实现时勿想当然。
- `contextInfo`/关联数据：标准 SM2 **不支持**（非空即报错）；SM4-GCM 作为 GCM AAD；混合加密与流式
  也认证 AAD/contextInfo，两端必须传**完全相同的字节**（null 与空等价）。
- 空明文：标准 SM2 不允许空明文（国标算法限制）；SM4-GCM/混合/流式允许。
- SM2 密钥对须满足 `d ∈ [1, n-1]`、公钥点在曲线上且非无穷远；坐标溢出/坏点应直接拒绝。

## 维护说明

- 修改任一算法实现时，请同步执行仓库内自检并确保全绿（`./mvnw test`）。
- 若算法线格式演进，需要同步更新本目录文档、对方参考实现（`cc.ddrpa.interop.bc`）与
  `InteropFixtures` 中的历史向量。
- 重新生成历史向量的方法：密文/签名是随机输出，无法在测试中自动复现；做法是临时写一个
  main/test，用 `InteropFixtures` 中的固定密钥调用本库 RAW 原语打印 hex，替换
  `InteropFixtures` 对应常量（同时保留断言其可被纯 BC 解密/验签的回归用例），随后删除临时代码。
- 对方参考实现只依赖 JDK + BouncyCastle 的约束由
  `scripts/verify-interop-samples.sh` 自动守护（编译并运行整个 `cc.ddrpa.interop.bc` 包，classpath
  上只有 bcprov）。
