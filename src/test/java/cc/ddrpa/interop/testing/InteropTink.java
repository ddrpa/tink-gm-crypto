package cc.ddrpa.interop.testing;

import cc.ddrpa.crypto.tink.aead.Sm4GcmKey;
import cc.ddrpa.crypto.tink.aead.Sm4GcmParameters;
import cc.ddrpa.crypto.tink.hybrid.*;
import cc.ddrpa.crypto.tink.signature.Sm2SignatureParameters;
import cc.ddrpa.crypto.tink.signature.Sm2SignaturePrivateKey;
import cc.ddrpa.crypto.tink.signature.Sm2SignaturePublicKey;
import cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKey;
import cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingParameters;
import cc.ddrpa.interop.bc.HexUtil;
import com.google.crypto.tink.*;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;

import javax.annotation.Nullable;
import java.security.GeneralSecurityException;

/**
 * Tink 侧自检辅助：用 {@link InteropFixtures} 的<strong>固定密钥</strong>构造本库各原语的
 * keyset/primitive，供「Tink ⇄ 对方侧（纯 BC）」双向互操作测试使用。
 *
 * <p>RAW 变体（NO_PREFIX）用于互操作：输出/输入均不带 Tink 前缀；TINK 变体用于验证“收到带
 * 前缀数据时的剥离处理”。
 */
public final class InteropTink {

    private InteropTink() {
    }

    public static byte[] fixtureSm4Key() {
        return HexUtil.decode(InteropFixtures.SM4_KEY_HEX);
    }

    public static byte[] fixtureD() {
        return HexUtil.decode(InteropFixtures.SM2_PRIVATE_D_HEX);
    }

    public static byte[] fixtureQ() {
        return HexUtil.decode(InteropFixtures.SM2_PUBLIC_Q_HEX);
    }

    private static SecretBytes secretBytes(byte[] bytes) {
        return SecretBytes.copyFrom(bytes, InsecureSecretKeyAccess.get());
    }

    // ------------------------------------------------------------------
    // SM4-GCM AEAD
    // ------------------------------------------------------------------

    /**
     * RAW（NO_PREFIX）SM4-GCM AEAD，密钥取自固定向量。
     */
    public static Aead newRawSm4GcmAead() throws GeneralSecurityException {
        return newSm4GcmAead(false, null);
    }

    /**
     * TINK 前缀 SM4-GCM AEAD，密钥取自固定向量，keyId 固定。
     */
    public static Aead newTinkSm4GcmAead(int keyId) throws GeneralSecurityException {
        return newSm4GcmAead(true, keyId);
    }

    private static Aead newSm4GcmAead(boolean tinkPrefix, @Nullable Integer keyId)
            throws GeneralSecurityException {
        Sm4GcmParameters.Builder paramsBuilder = Sm4GcmParameters.builder()
                .setIvSizeBytes(12)
                .setTagSizeBytes(16);
        paramsBuilder.setVariant(
                tinkPrefix ? Sm4GcmParameters.Variant.TINK : Sm4GcmParameters.Variant.NO_PREFIX);
        Sm4GcmParameters params = paramsBuilder.build();
        Sm4GcmKey.Builder keyBuilder = Sm4GcmKey.builder()
                .setParameters(params)
                .setKeyBytes(secretBytes(fixtureSm4Key()));
        if (tinkPrefix) {
            keyBuilder.setIdRequirement(keyId);
        }
        KeysetHandle handle = keysetOf(keyBuilder.build());
        return handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
    }

    // ------------------------------------------------------------------
    // SM4-GCM-HKDF 流式 AEAD
    // ------------------------------------------------------------------

    /**
     * SM4-GCM-HKDF 流式 AEAD（固定 IKM），指定密文段大小（4096 或 1048576）。
     */
    public static StreamingAead newSm4GcmHkdfStreamingAead(int ciphertextSegmentSize)
            throws GeneralSecurityException {
        Sm4GcmHkdfStreamingParameters params = Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(16)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(ciphertextSegmentSize)
                .build();
        Sm4GcmHkdfStreamingKey key =
                Sm4GcmHkdfStreamingKey.create(params, secretBytes(fixtureSm4Key()));
        KeysetHandle handle = keysetOf(key);
        return handle.getPrimitive(RegistryConfiguration.get(), StreamingAead.class);
    }

    // ------------------------------------------------------------------
    // SM2 数字签名
    // ------------------------------------------------------------------

    /**
     * RAW SM2 签名器/验签器（固定 d/Q）。
     */
    public static PublicKeySign newRawSm2Signer() throws GeneralSecurityException {
        return signerFor(false, null);
    }

    public static PublicKeyVerify newRawSm2Verifier() throws GeneralSecurityException {
        return verifierFor(false, null);
    }

    /**
     * TINK 前缀 SM2 签名器/验签器（固定 d/Q，keyId 固定）。
     */
    public static PublicKeySign newTinkSm2Signer(int keyId) throws GeneralSecurityException {
        return signerFor(true, keyId);
    }

    public static PublicKeyVerify newTinkSm2Verifier(int keyId) throws GeneralSecurityException {
        return verifierFor(true, keyId);
    }

    private static PublicKeySign signerFor(boolean tinkPrefix, @Nullable Integer keyId)
            throws GeneralSecurityException {
        Sm2SignaturePublicKey publicKey = signaturePublicKey(tinkPrefix, keyId);
        Sm2SignaturePrivateKey privateKey = Sm2SignaturePrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateValue(secretBytes(fixtureD()))
                .build();
        KeysetHandle handle = keysetOf(privateKey);
        return handle.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
    }

    private static PublicKeyVerify verifierFor(boolean tinkPrefix, @Nullable Integer keyId)
            throws GeneralSecurityException {
        KeysetHandle handle = keysetOf(signaturePublicKey(tinkPrefix, keyId));
        return handle.getPrimitive(RegistryConfiguration.get(), PublicKeyVerify.class);
    }

    private static Sm2SignaturePublicKey signaturePublicKey(
            boolean tinkPrefix, @Nullable Integer keyId) throws GeneralSecurityException {
        Sm2SignatureParameters params = Sm2SignatureParameters.builder()
                .setVariant(tinkPrefix
                        ? Sm2SignatureParameters.Variant.TINK
                        : Sm2SignatureParameters.Variant.NO_PREFIX)
                .build();
        Sm2SignaturePublicKey.Builder builder = Sm2SignaturePublicKey.builder()
                .setParameters(params)
                .setPublicKey(Bytes.copyFrom(fixtureQ()));
        if (tinkPrefix) {
            builder.setIdRequirement(keyId);
        }
        return builder.build();
    }

    // ------------------------------------------------------------------
    // 标准 SM2 加密（C1C3C2）
    // ------------------------------------------------------------------

    public static HybridEncrypt newRawSm2StandardEncryptor() throws GeneralSecurityException {
        return standardEncryptorFor(false, null);
    }

    public static HybridDecrypt newRawSm2StandardDecryptor() throws GeneralSecurityException {
        return standardDecryptorFor(false, null);
    }

    public static HybridEncrypt newTinkSm2StandardEncryptor(int keyId)
            throws GeneralSecurityException {
        return standardEncryptorFor(true, keyId);
    }

    public static HybridDecrypt newTinkSm2StandardDecryptor(int keyId)
            throws GeneralSecurityException {
        return standardDecryptorFor(true, keyId);
    }

    private static HybridEncrypt standardEncryptorFor(boolean tinkPrefix, @Nullable Integer keyId)
            throws GeneralSecurityException {
        KeysetHandle handle = keysetOf(standardPublicKey(tinkPrefix, keyId));
        return handle.getPrimitive(RegistryConfiguration.get(), HybridEncrypt.class);
    }

    private static HybridDecrypt standardDecryptorFor(boolean tinkPrefix, @Nullable Integer keyId)
            throws GeneralSecurityException {
        Sm2EncryptionPublicKey publicKey = standardPublicKey(tinkPrefix, keyId);
        Sm2EncryptionPrivateKey privateKey = Sm2EncryptionPrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateValue(secretBytes(fixtureD()))
                .build();
        KeysetHandle handle = keysetOf(privateKey);
        return handle.getPrimitive(RegistryConfiguration.get(), HybridDecrypt.class);
    }

    private static Sm2EncryptionPublicKey standardPublicKey(
            boolean tinkPrefix, @Nullable Integer keyId) throws GeneralSecurityException {
        Sm2EncryptionParameters params = Sm2EncryptionParameters.builder()
                .setVariant(tinkPrefix
                        ? Sm2EncryptionParameters.Variant.TINK
                        : Sm2EncryptionParameters.Variant.NO_PREFIX)
                .build();
        Sm2EncryptionPublicKey.Builder builder = Sm2EncryptionPublicKey.builder()
                .setParameters(params)
                .setPublicKey(Bytes.copyFrom(fixtureQ()));
        if (tinkPrefix) {
            builder.setIdRequirement(keyId);
        }
        return builder.build();
    }

    // ------------------------------------------------------------------
    // SM2-KEM + SM4-GCM 混合加密
    // ------------------------------------------------------------------

    public static HybridEncrypt newRawSm2HybridEncryptor() throws GeneralSecurityException {
        return hybridEncryptorFor(false, null);
    }

    public static HybridDecrypt newRawSm2HybridDecryptor() throws GeneralSecurityException {
        return hybridDecryptorFor(false, null);
    }

    private static HybridEncrypt hybridEncryptorFor(boolean tinkPrefix, @Nullable Integer keyId)
            throws GeneralSecurityException {
        KeysetHandle handle = keysetOf(hybridPublicKey(tinkPrefix, keyId));
        return handle.getPrimitive(RegistryConfiguration.get(), HybridEncrypt.class);
    }

    private static HybridDecrypt hybridDecryptorFor(boolean tinkPrefix, @Nullable Integer keyId)
            throws GeneralSecurityException {
        Sm2HybridPublicKey publicKey = hybridPublicKey(tinkPrefix, keyId);
        Sm2HybridPrivateKey privateKey = Sm2HybridPrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateValue(secretBytes(fixtureD()))
                .build();
        KeysetHandle handle = keysetOf(privateKey);
        return handle.getPrimitive(RegistryConfiguration.get(), HybridDecrypt.class);
    }

    private static Sm2HybridPublicKey hybridPublicKey(
            boolean tinkPrefix, @Nullable Integer keyId) throws GeneralSecurityException {
        Sm2HybridParameters params = Sm2HybridParameters.builder()
                .setVariant(tinkPrefix
                        ? Sm2HybridParameters.Variant.TINK
                        : Sm2HybridParameters.Variant.NO_PREFIX)
                .build();
        Sm2HybridPublicKey.Builder builder = Sm2HybridPublicKey.builder()
                .setParameters(params)
                .setPublicKey(Bytes.copyFrom(fixtureQ()));
        if (tinkPrefix) {
            builder.setIdRequirement(keyId);
        }
        return builder.build();
    }

    // ------------------------------------------------------------------
    // Keyset 装配
    // ------------------------------------------------------------------

    /**
     * 把单个密钥装配成单主密钥 keyset（无 id 要求的密钥补随机 id）。
     */
    private static KeysetHandle keysetOf(com.google.crypto.tink.Key key)
            throws GeneralSecurityException {
        KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
        if (key.getIdRequirementOrNull() == null) {
            entry.withRandomId();
        } else {
            entry.withFixedId(key.getIdRequirementOrNull());
        }
        return KeysetHandle.newBuilder().addEntry(entry).build();
    }
}
