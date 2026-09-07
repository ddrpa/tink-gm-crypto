# 为 Google Tink 添加部分国密支持

保持 Google Tink 框架安全性和易用性的同时，为开发者提供符合国家密码管理局标准的加密实现。

软件包的版本标识了兼容的 Google Tink 版本，例如 1.23.0.x 表示基于 `com.google.crypto.tink:tink:1.23.0` 开发。当前实现使用 Tink 1.22.0 起引入的公开序列化 API（如 `com.google.crypto.tink.ProtoKeySerialization`），因此最低要求 Tink 1.22.0。

**注意：** 目前只有 Java SDK 实现，因此密钥创建管理等动作如果需要识别相关的密钥，也需要依赖 Java SDK。暂未有移植到其他语言 SDK 或 tinkey 的计划。 

# 现已支持

## AEAD

参照 AES-GCM 实现了 SM4-GCM 支持，密钥类型为 `type.googleapis.com/ddrpa.crypto.tink.Sm4GcmKey`。

```java
AeadConfig.register();
Sm4GcmKeyManager.register(true);
```

参考 `src/test/java/cc/ddrpa/playground/CreateClearTextKeyset.java` 方法创建密钥。

参考 `src/test/java/cc/ddrpa/playground/UseAEAD.java` 使用。

## 流式 AEAD

参照 AES-GCM-HKDF 实现了 SM4-GCM-HKDF 支持，密钥类型为 `type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey`。

```java
StreamingAeadConfig.register();
Sm4GcmHkdfStreamingKeyManager.register(true);
```

参考 `src/test/java/cc/ddrpa/playground/CreateClearTextKeyset.java` 方法创建密钥。

参考 `src/test/java/cc/ddrpa/playground/UseStreamingAEAD.java` 使用。

## 数字签名（SM2）

参照 ECDSA 实现了 SM2 数字签名（GB/T 32918.2-2016，SM3，`sm2p256v1` 曲线，用户标识 IDA 固定使用
标准默认值 `1234567812345678`），签名值为定长 64 字节的 r ‖ s。密钥类型为
`type.googleapis.com/ddrpa.crypto.tink.Sm2SignaturePrivateKey` / `Sm2SignaturePublicKey`，
具名参数 `SM2_SIGN`（TINK 前缀）与 `SM2_SIGN_RAW`（无前缀，纯 64 字节签名，可与其他实现互操作）。

```java
// SignatureConfig.register() 注册 Tink 的签名 wrapper（PublicKeySign/PublicKeyVerify）
SignatureConfig.register();
Sm2SignKeyManager.registerPair(true);
```

参考 `src/test/java/cc/ddrpa/playground/CreateSM2Keysets.java` 创建签名密钥集与可分发的公钥密钥集，
参考 `src/test/java/cc/ddrpa/playground/UseSM2Signature.java` 使用。

## 公钥加密：标准 SM2

按 GB/T 32918.4-2016 实现标准 SM2 公钥加密，密文布局为 C1 ‖ C3 ‖ C2（C1 为 65 字节非压缩点），
以 Tink 的 HybridEncrypt / HybridDecrypt 原语提供，密钥类型为
`type.googleapis.com/ddrpa.crypto.tink.Sm2EncryptionPrivateKey` / `Sm2EncryptionPublicKey`，
具名参数 `SM2_ENCRYPTION`（TINK 前缀）与 `SM2_ENCRYPTION_RAW`（无前缀，密文可与 GmSSL、OpenSSL
等其他国密实现互操作）。

标准 SM2 算法没有关联数据槽位，因此 **contextInfo 必须为 null 或空**，传入非空值会直接报错。

```java
HybridEncryptWrapper.register();
HybridDecryptWrapper.register();
Sm2EncryptionKeyManager.registerPair(true);
```

参考 `src/test/java/cc/ddrpa/playground/CreateSM2Keysets.java` 与
`src/test/java/cc/ddrpa/playground/UseSM2Encryption.java`。

## 公钥加密：SM2-KEM + SM4-GCM 混合

在 SM2 曲线上提供 KEM + DEM 混合加密：加密方生成临时密钥对，以 SM2-KDF（SM3）从共享点
(x2 ‖ y2) 派生 SM4-GCM 数据密钥，`contextInfo` 作为 SM4-GCM 的关联数据被**完整认证**
（解密时必须传入相同的 contextInfo）。密钥类型为
`type.googleapis.com/ddrpa.crypto.tink.Sm2HybridPrivateKey` / `Sm2HybridPublicKey`，
具名参数 `SM2_HYBRID`（TINK 前缀）与 `SM2_HYBRID_RAW`（无前缀）。

该实现密文格式（C1 ‖ nonce ‖ SM4-GCM）并非国标 SM2 密文格式，不与外部国密实现互操作；
需要标准格式时请使用上面的“标准 SM2”实现。

```java
HybridEncryptWrapper.register();
HybridDecryptWrapper.register();
Sm2HybridKeyManager.registerPair(true);
```

参考 `src/test/java/cc/ddrpa/playground/CreateSM2Keysets.java` 与
`src/test/java/cc/ddrpa/playground/UseSM2Encryption.java`。

> 说明：以上 SM2 实现基于 Bouncy Castle，注册时若处于 Tink FIPS 模式（无 BoringCrypto）会被拒绝；
> 私钥与公钥分别使用私钥/公钥密钥集管理，可通过 `KeysetHandle#getPublicKeysetHandle()` 导出公钥密钥集
> 分发给验证方/加密方（RAW 互操作请使用 NO_PREFIX 变体并自行剥离前缀规则，见各节说明）。

# 面向不使用 Google Tink 的对方系统（跨系统互操作）

加解密通常发生在两个不同系统之间：本库一侧使用 Tink，对方系统开发人员往往不使用 Tink。为此
仓库提供了独立的互操作资料与一套**对方侧参考实现**（Java + BouncyCastle，纯 BC/JDK、零 Tink
依赖、可整包拷贝），涵盖全部已支持算法，并按互操作友好度分级：

- **可直接互操作**（国标/通用格式）：SM4-GCM（`SM4_GCM_RAW`）、SM2 签名（`SM2_SIGN_RAW`，
  64 字节 r‖s、默认用户标识）、标准 SM2 加密（`SM2_ENCRYPTION_RAW`，C1C3C2）；
- **本库自定义格式**（按线格式文档实现即可互通）：SM4-GCM-HKDF 流式 AEAD、SM2-KEM+SM4-GCM 混合。

仓库内自动测试对“Tink ⇄ 对方侧（纯 BC）”做双向自检并固化历史向量，确保示例真实可用。详见
[interop/](interop/README.md)（密钥交换、各算法线格式与注意事项、对方代码拷贝与自检方法、
导出裸密钥工具 `src/test/java/cc/ddrpa/playground/ExportKeysForInterop.java`）。

# 计划添加

- PEM / SPKI 公钥导入（仅数字签名）：参照 Tink `SignaturePemKeysetReader` 的机制，按 SM2 曲线/算法
  OID（1.2.156.10197.1.301 / 1.2.156.10197.1.501）自研读取 PEM 公钥并转换为 SM2 签名 keyset；
  不做 X.509 证书导出（证书属 PKI/CA 层，超出 Tink 模型）
- SM3 以 Tink 原语形态提供的可行性评估（例如 HMAC-SM3 映射到 Mac 原语；Tink 不提供裸摘要原语）
- 为 SM2 / SM4 模块接入 Tink keyset 监控（MonitoringClient，仓库测试支持类已随 v1.23.0 同步）

# 验证对新版 Tink 的适配

pom.xml 中的 `tink.version` 属性声明了所依赖的 Tink 版本（默认 1.23.0）。Tink 升级后可用下面的方式快速验证本库是否仍然适配：

1. 运行当前默认版本的全部单元测试（331 个用例，覆盖密钥/参数序列化、密钥模板与 KeysetHandle 生成、
   对称与非对称加解密往返、签名与验签、SM2 与 Bouncy Castle 交叉验证、跨系统互操作自检
   （Tink ⇄ 纯 BC，见 [interop/](interop/README.md)）、非法输入拒绝等）：

   ```shell
   ./mvnw test
   ```

2. 不改动 pom，直接对任意 Tink 版本做完整验证：

   ```shell
   ./mvnw test -Dtink.version=<版本号>
   ```

3. 或使用验证脚本（省略版本号时读取 pom 中的默认值）：

   ```shell
   ./scripts/verify-tink-version.sh <版本号>
   ```

当 Tink 新版本的 API 与本库不再兼容时，编译错误或上述用例的失败会立刻指出需要适配的位置。制品与各 Tink 版本的兼容关系及适配边界见 [COMPATIBILITY.md](COMPATIBILITY.md)，每次验证通过后请在该文件中登记结果。

维护说明：`src/test/java/com/google/crypto/tink/` 下随仓库维护的 Tink 测试支持类（如 `Asserts`、`KeyTester`、`FakeMonitoringClient`、`StreamingTestUtil` 等）与所适配的 tink-java 版本保持一致（取自 v1.23.0 源码）；升级 Tink 版本时建议从对应 tag 同步更新这些文件，以免其内部 API 与新版本不兼容。
