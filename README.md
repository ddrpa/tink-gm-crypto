# 为 Google Tink 添加部分国密支持

保持 Google Tink 框架安全性和易用性的同时，为开发者提供符合国家密码管理局标准的加密实现。

软件包的版本标识了兼容的 Google Tink 版本，例如 1.17.0.x 表示基于 `com.google.crypto.tink:tink:1.17.0` 开发。

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
