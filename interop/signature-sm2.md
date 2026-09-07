# 互操作：SM2 数字签名（GB/T 32918.2）

适用于：**验签方**持有签名者的公钥（64 字节 `Q`）验证其签名；**签名方**持有私钥
（32 字节 `d`）。

## 1. 参数（固定）

| 参数 | 值 |
| --- | --- |
| 曲线 | sm2p256v1（BC 注册名；域参数见 GB/T 32918.5 / GM/T 0009） |
| 摘要 | SM3（签名算法内部完成，调用方**不要**预先哈希消息） |
| 用户标识 IDA | 固定 ASCII `1234567812345678`（GB/T 32918.2 默认值，无长度前缀差异：SM2 标准按
  ENTLA‖IDA 处理，这里即默认 16 字节 ID） |
| 签名编码 | 定长 64 字节 `r ‖ s`（各 32 字节大端），**非 DER/ASN.1** |
| 消息 | 原始字节（可空）；SM2 内部计算 ZA = SM3(ENTLA‖IDA‖a‖b‖Gx‖Gy‖Qx‖Qy) 后再对 ZA‖M 求摘要 |

## 2. 签名线格式（RAW，无前缀）

```
签名 = r(32) ‖ s(32)                      （64 字节）
```

## 3. 参考实现

文件：`src/test/java/cc/ddrpa/interop/bc/Sm2Signature.java`。核心用法：

```java
// 验签（只需要公钥 Q，64 字节）
boolean ok = Sm2Signature.verify(Q64Bytes, signature64Bytes, messageBytes);

// 签名（需要私钥 d，32 字节）
byte[] signature = Sm2Signature.sign(d32Bytes, messageBytes);
```

实现要点：使用 `new SM2Signer(new PlainDSAEncoding(), new SM3Digest())`，签名/验签时以
`ParametersWithID(..., "1234567812345678".getBytes(US_ASCII))` 传入默认用户标识；`PlainDSAEncoding`
保证输出/接收 64 字节 `r‖s`（BC 默认的 `DERDSAEncoding` 会输出 DER，互操作时不要使用）。

## 4. Tink 侧：生成/接收该格式

- 注册：`SignatureConfig.register(); Sm2SignKeyManager.registerPair(true);`
- 使用具名参数 `SM2_SIGN_RAW` 生成私钥密钥集，把
  `getPublicKeysetHandle()`（公钥密钥集）发给验签方；验签方通过
  `src/test/java/cc/ddrpa/playground/ExportKeysForInterop.java` 或等价代码取出 64 字节 `Q`。
- RAW 签名即 64 字节 `r‖s`；若收到的是 **TINK 前缀变体**（`SM2_SIGN`）产生的签名
  （`0x01 ‖ keyId(4 字节大端) ‖ 64 字节签名`），需要先剥离前缀并把 keyId 与本地公钥对应后再验签。

## 5. 注意

- 消息语义：签名对象是**原始字节**。若双方约定先对内容做摘要/hex/字符串转换，两边必须一致；
  部分实现要求“先 SM3 再签名”与这里的“内部 ZA‖M”不兼容。
- 用户标识：必须使用默认 ID `1234567812345678`；否则验签失败（BC 与多数国产库默认即此 ID）。
- 公钥点需在曲线上且非无穷远；坐标必须是 32 字节定长大端。
- 库内验签对错误签名的行为：`Sm2Signature.verify` 返回 `false`（长度/公钥非法抛异常）；Tink 侧
  `verify` 抛 `GeneralSecurityException`。业务上请把“验签失败”与“数据异常”都当作拒绝处理。

## 6. 仓库内自检与固定向量

- 双向自检：`cc.ddrpa.interop.Sm2SignatureInteropTest`。
- 固定密钥与历史向量（`cc.ddrpa.interop.testing.InteropFixtures`）：
  - `d`：`010203…1e1f20`（32 字节，见 `SM2_PRIVATE_D_HEX`）
  - `Q`：`46d1…43c9`（64 字节，见 `SM2_PUBLIC_Q_HEX`，= d·G，测试会校验）
  - 消息：`SAMPLE_MESSAGE`（UTF-8 常量文本）
  - 历史签名：`SM2_SIGNATURE_VECTOR_HEX`（64 字节，可用 `Sm2Signature.verify(Q, …, SAMPLE_MESSAGE)`
    独立验签）
