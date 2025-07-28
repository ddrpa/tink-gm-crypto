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

## 数字签名

参照 ECDSA 实现了 SM2 数字签名支持，私钥类型为 `type.googleapis.com/ddrpa.crypto.tink.Sm2PrivateKey`，公钥类型为 `type.googleapis.com/ddrpa.crypto.tink.Sm2PublicKey`。

```java
SignatureConfig.register();
Sm2SignatureKeyManager.register(true);
```

支持的功能：
- **哈希算法**：SM3、SHA256
- **签名编码**：DER、IEEE P1363
- **前缀模式**：TINK、NO_PREFIX、LEGACY、CRUNCHY
- **椭圆曲线**：SM2P256V1

可用的密钥模板：
```java
// SM3 哈希 + DER 编码 + TINK 前缀
Sm2SignatureKeyManager.sm2Sm3Template()

// SHA256 哈希 + DER 编码 + TINK 前缀  
Sm2SignatureKeyManager.sm2Sha256Template()

// SM3 哈希 + DER 编码 + 无前缀
Sm2SignatureKeyManager.rawSm2Sm3Template()
```

参考 `src/test/java/cc/ddrpa/playground/UseSM2Signature.java` 使用。

## 混合加密

参照 ECIES 实现了 SM2 混合加密支持，私钥类型为 `type.googleapis.com/ddrpa.crypto.tink.Sm2EncryptionPrivateKey`，公钥类型为 `type.googleapis.com/ddrpa.crypto.tink.Sm2EncryptionPublicKey`。

```java
// 注册 SM2 混合加密支持（未来版本将提供完整注册）
// 目前可直接使用工厂方法
```

支持的功能：
- **哈希算法**：SM3、SHA256（用于密钥派生函数）
- **对称加密**：SM4-GCM、AES-GCM（用于数据加密）
- **混合加密模式**：遵循 ECIES 模式，先用 SM2 加密随机对称密钥，再用对称算法加密数据
- **椭圆曲线**：SM2P256V1

可用的密钥生成：
```java
// SM3 哈希 + SM4-GCM 对称加密
Sm2EncryptionPrivateKey privateKey1 = Sm2EncryptionKeyManager.generateKeySm3Sm4Gcm();

// SHA256 哈希 + AES-GCM 对称加密  
Sm2EncryptionPrivateKey privateKey2 = Sm2EncryptionKeyManager.generateKeySha256AesGcm();
```

使用示例：
```java
// 生成密钥对
Sm2EncryptionPrivateKey privateKey = Sm2EncryptionKeyManager.generateKeySha256AesGcm();
Sm2EncryptionPublicKey publicKey = privateKey.getPublicKey();

// 创建加密解密原语
HybridEncrypt encryptor = Sm2EncryptionKeyManager.createHybridEncrypt(publicKey);
HybridDecrypt decryptor = Sm2EncryptionKeyManager.createHybridDecrypt(privateKey);

// 加密解密
byte[] plaintext = "Hello, SM2 hybrid encryption!".getBytes();
byte[] contextInfo = "additional context".getBytes();

byte[] ciphertext = encryptor.encrypt(plaintext, contextInfo);
byte[] decrypted = decryptor.decrypt(ciphertext, contextInfo);
```

参考 `src/test/java/cc/ddrpa/playground/UseSM2Encryption.java` 使用。

# 计划添加

目前已完成所有主要国密算法的支持：
- ✅ SM4（对称加密）- AEAD 和 Streaming AEAD
- ✅ SM2（数字签名）- 支持 SM3 和 SHA256 哈希
- ✅ SM2（混合加密）- 支持 SM3/SHA256 哈希 + SM4-GCM/AES-GCM 对称加密

未来计划：
- 完善 Tink 框架集成（密钥模板、自动注册等）
- 性能优化和安全审计
