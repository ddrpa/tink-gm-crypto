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

# 计划添加

- SM2（椭圆曲线数字签名算法与公钥加密）支持

# 验证对新版 Tink 的适配

pom.xml 中的 `tink.version` 属性声明了所依赖的 Tink 版本（默认 1.23.0）。Tink 升级后可用下面的方式快速验证本库是否仍然适配：

1. 运行当前默认版本的全部单元测试（108 个用例，覆盖密钥/参数序列化、密钥模板与 KeysetHandle 生成、加解密往返、非法输入拒绝等）：

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
