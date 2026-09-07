package cc.ddrpa.interop;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cc.ddrpa.crypto.tink.aead.Sm4GcmKeyManager;
import cc.ddrpa.crypto.tink.hybrid.Sm2EncryptionKeyManager;
import cc.ddrpa.crypto.tink.hybrid.Sm2HybridKeyManager;
import cc.ddrpa.crypto.tink.signature.Sm2SignKeyManager;
import cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKeyManager;
import cc.ddrpa.interop.bc.HexUtil;
import cc.ddrpa.interop.bc.Sm2KemSm4GcmHybrid;
import cc.ddrpa.interop.bc.Sm2Signature;
import cc.ddrpa.interop.bc.Sm2StandardEncryption;
import cc.ddrpa.interop.bc.Sm4GcmAead;
import cc.ddrpa.interop.bc.Sm4GcmHkdfStreamingAead;
import cc.ddrpa.interop.testing.InteropFixtures;
import cc.ddrpa.interop.testing.InteropTink;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.hybrid.HybridDecryptWrapper;
import com.google.crypto.tink.hybrid.HybridEncryptWrapper;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * 历史向量回归：用<strong>对方角色（纯 BouncyCastle，不依赖 Tink）</strong>独立解密/验签
 * {@link InteropFixtures} 中固化的「Tink 侧历史输出」，防止加密侧与解密侧共享同一处实现错误；
 * 并顺带用 Tink 侧 RAW 原语重解一遍，确认向量与当前实现仍然一致。
 *
 * <p>密文本身是随机输出的一次性快照，因此只做“可被正确解密/验签”的断言。
 */
class HistoricalVectorsTest {

    private static final byte[] KEY = InteropTink.fixtureSm4Key();
    private static final byte[] D = InteropTink.fixtureD();
    private static final byte[] Q = InteropTink.fixtureQ();

    @BeforeAll
    static void setUp() throws Exception {
        AeadConfig.register();
        Sm4GcmKeyManager.register(true);
        StreamingAeadConfig.register();
        Sm4GcmHkdfStreamingKeyManager.register(true);
        SignatureConfig.register();
        Sm2SignKeyManager.registerPair(true);
        HybridEncryptWrapper.register();
        HybridDecryptWrapper.register();
        Sm2EncryptionKeyManager.registerPair(true);
        Sm2HybridKeyManager.registerPair(true);
    }

    @Test
    void sm4GcmHistoricalCiphertextDecryptsWithBcOnly() throws Exception {
        byte[] ciphertext = HexUtil.decode(InteropFixtures.SM4_GCM_VECTOR_CIPHERTEXT_HEX);
        assertEquals(12 + InteropFixtures.SAMPLE_PLAINTEXT.length + 16, ciphertext.length);
        assertArrayEquals(
            InteropFixtures.SAMPLE_PLAINTEXT,
            Sm4GcmAead.decrypt(KEY, ciphertext, InteropFixtures.SAMPLE_AAD));
        // Tink 侧重解（回归）。
        Aead tink = InteropTink.newRawSm4GcmAead();
        assertArrayEquals(
            InteropFixtures.SAMPLE_PLAINTEXT,
            tink.decrypt(ciphertext, InteropFixtures.SAMPLE_AAD));
    }

    @Test
    void sm2SignatureHistoricalValueVerifiesWithBcOnly() throws Exception {
        byte[] signature = HexUtil.decode(InteropFixtures.SM2_SIGNATURE_VECTOR_HEX);
        assertEquals(64, signature.length);
        assertTrue(Sm2Signature.verify(Q, signature, InteropFixtures.SAMPLE_MESSAGE));
        // Tink 侧重验（回归）。
        PublicKeyVerify verifier = InteropTink.newRawSm2Verifier();
        verifier.verify(signature, InteropFixtures.SAMPLE_MESSAGE);
    }

    @Test
    void sm2StandardEncryptionHistoricalCiphertextDecryptsWithBcOnly() throws Exception {
        byte[] ciphertext = HexUtil.decode(
            InteropFixtures.SM2_STANDARD_ENCRYPTION_VECTOR_CIPHERTEXT_HEX);
        assertEquals(65 + 32 + InteropFixtures.SAMPLE_PLAINTEXT.length, ciphertext.length);
        assertArrayEquals(
            InteropFixtures.SAMPLE_PLAINTEXT,
            Sm2StandardEncryption.decrypt(D, ciphertext));
        // Tink 侧重解（回归）。
        HybridDecrypt tink = InteropTink.newRawSm2StandardDecryptor();
        assertArrayEquals(InteropFixtures.SAMPLE_PLAINTEXT, tink.decrypt(ciphertext, null));
    }

    @Test
    void sm2HybridHistoricalCiphertextDecryptsWithBcOnly() throws Exception {
        byte[] ciphertext = HexUtil.decode(InteropFixtures.SM2_HYBRID_VECTOR_CIPHERTEXT_HEX);
        assertEquals(65 + 12 + InteropFixtures.SAMPLE_PLAINTEXT.length + 16, ciphertext.length);
        assertArrayEquals(
            InteropFixtures.SAMPLE_PLAINTEXT,
            Sm2KemSm4GcmHybrid.decrypt(D, ciphertext, InteropFixtures.SAMPLE_CONTEXT_INFO));
        // Tink 侧重解（回归）。
        HybridDecrypt tink = InteropTink.newRawSm2HybridDecryptor();
        assertArrayEquals(
            InteropFixtures.SAMPLE_PLAINTEXT,
            tink.decrypt(ciphertext, InteropFixtures.SAMPLE_CONTEXT_INFO));
    }

    @Test
    void sm4GcmHkdfStreamingHistoricalCiphertextDecryptsWithBcOnly() throws Exception {
        byte[] ciphertext = HexUtil.decode(
            InteropFixtures.SM4_GCM_HKDF_STREAMING_VECTOR_CIPHERTEXT_HEX);
        byte[] plaintext = HexUtil.decode(
            InteropFixtures.SM4_GCM_HKDF_STREAMING_VECTOR_PLAINTEXT_HEX);
        assertEquals(140, ciphertext.length);
        assertArrayEquals(
            plaintext,
            Sm4GcmHkdfStreamingAead.decryptBytes(
                KEY, 4096, InteropFixtures.SAMPLE_AAD, ciphertext));
        // Tink 侧重解（回归）。
        StreamingAead tink = InteropTink.newSm4GcmHkdfStreamingAead(4096);
        assertArrayEquals(
            plaintext,
            Sm4GcmHkdfStreamingInteropTest.tinkDecrypt(tink, ciphertext,
                InteropFixtures.SAMPLE_AAD));
    }
}
