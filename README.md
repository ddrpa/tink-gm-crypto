# 为 Google Tink 添加部分国密支持

保持 Google Tink 框架安全性和易用性的同时，为开发者提供符合国家密码管理局标准的加密实现。

软件包的版本表达了兼容的 Google Tink 版本，例如 1.17.0.x 表示基于 `com.google.crypto.tink:tink:1.17.0` 开发。

# 注意

目前只有 Java SDK 实现，因此密钥创建管理等依赖 Java SDK，暂未有移植到其他语言 SDK 或 tinkey 的计划。 

# 现已支持

## AEAD

参照 AES-GCM 实现了 SM4-GCM

```java
Sm4GcmKeyManager.register(true);
```

## 流式 AEAD

参照 AES-GCM-HKDF 实现了 SM4-GCM-HKDF

```
"type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey";
```

计算方法


## 确定性 AEAD

# 计划添加

SM2（椭圆曲线数字签名算法与公钥加密）支持
