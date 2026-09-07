package cc.ddrpa.interop;

import cc.ddrpa.crypto.tink.hybrid.Sm2HybridKeyManager;
import cc.ddrpa.interop.bc.Sm2KemSm4GcmHybrid;
import cc.ddrpa.interop.testing.InteropFixtures;
import cc.ddrpa.interop.testing.InteropTink;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.hybrid.HybridDecryptWrapper;
import com.google.crypto.tink.hybrid.HybridEncryptWrapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SM2-KEM + SM4-GCM 混合加密（本库自定义格式）的跨系统互操作自检：Tink 侧 ⇄ 对方侧（纯
 * BouncyCastle，{@code cc.ddrpa.interop.bc.Sm2KemSm4GcmHybrid}）。
 *
 * <p>RAW 输出线格式：{@code C1(65, 0x04‖X‖Y) ‖ nonce(12) ‖ SM4-GCM 密文}；数据密钥由共享点
 * x2‖y2 经 SM2-KDF(SM3) 派生；{@code contextInfo} 作为 SM4-GCM 关联数据被认证。
 */
class Sm2HybridInteropTest {

    private static final byte[] D = InteropTink.fixtureD();
    private static final byte[] Q = InteropTink.fixtureQ();
    private static final byte[] PLAINTEXT = InteropFixtures.SAMPLE_PLAINTEXT;
    private static final byte[] CONTEXT = InteropFixtures.SAMPLE_CONTEXT_INFO;

    @BeforeAll
    static void setUp() throws Exception {
        HybridEncryptWrapper.register();
        HybridDecryptWrapper.register();
        Sm2HybridKeyManager.registerPair(true);
    }

    // 方向一：Tink 加密 → 对方 BC 解密。
    @Test
    void tinkEncryptsBcDecrypts() throws Exception {
        HybridEncrypt encryptor = InteropTink.newRawSm2HybridEncryptor();
        byte[] ciphertext = encryptor.encrypt(PLAINTEXT, CONTEXT);
        assertEquals(65 + 12 + PLAINTEXT.length + 16, ciphertext.length);
        assertEquals(0x04, ciphertext[0] & 0xff);
        assertArrayEquals(PLAINTEXT, Sm2KemSm4GcmHybrid.decrypt(D, ciphertext, CONTEXT));
    }

    // 方向二：对方 BC 加密 → Tink 解密。
    @Test
    void bcEncryptsTinkDecrypts() throws Exception {
        HybridDecrypt decryptor = InteropTink.newRawSm2HybridDecryptor();
        byte[] ciphertext = Sm2KemSm4GcmHybrid.encrypt(Q, PLAINTEXT, CONTEXT);
        assertArrayEquals(PLAINTEXT, decryptor.decrypt(ciphertext, CONTEXT));
    }

    @Test
    void nullAndEmptyContextAreEquivalent() throws Exception {
        HybridEncrypt encryptor = InteropTink.newRawSm2HybridEncryptor();
        HybridDecrypt decryptor = InteropTink.newRawSm2HybridDecryptor();

        byte[] ctWithNull = encryptor.encrypt(PLAINTEXT, null);
        byte[] ctWithEmpty = encryptor.encrypt(PLAINTEXT, new byte[0]);
        assertArrayEquals(PLAINTEXT, Sm2KemSm4GcmHybrid.decrypt(D, ctWithNull, new byte[0]));
        assertArrayEquals(PLAINTEXT, Sm2KemSm4GcmHybrid.decrypt(D, ctWithEmpty, null));
        assertArrayEquals(PLAINTEXT, decryptor.decrypt(ctWithNull, null));
        assertArrayEquals(PLAINTEXT, decryptor.decrypt(ctWithEmpty, new byte[0]));
    }

    @Test
    void wrongContextRejectedByBothSides() throws Exception {
        HybridEncrypt encryptor = InteropTink.newRawSm2HybridEncryptor();
        HybridDecrypt decryptor = InteropTink.newRawSm2HybridDecryptor();
        byte[] wrongContext = "wrong-context".getBytes();

        byte[] tinkCiphertext = encryptor.encrypt(PLAINTEXT, CONTEXT);
        assertThrows(GeneralSecurityException.class,
                () -> Sm2KemSm4GcmHybrid.decrypt(D, tinkCiphertext, wrongContext));

        byte[] bcCiphertext = Sm2KemSm4GcmHybrid.encrypt(Q, PLAINTEXT, CONTEXT);
        assertThrows(GeneralSecurityException.class,
                () -> decryptor.decrypt(bcCiphertext, wrongContext));
    }

    @Test
    void emptyPlaintextWorksBothWays() throws Exception {
        HybridEncrypt encryptor = InteropTink.newRawSm2HybridEncryptor();
        HybridDecrypt decryptor = InteropTink.newRawSm2HybridDecryptor();

        byte[] fromTink = encryptor.encrypt(new byte[0], CONTEXT);
        assertArrayEquals(new byte[0], Sm2KemSm4GcmHybrid.decrypt(D, fromTink, CONTEXT));

        byte[] fromBc = Sm2KemSm4GcmHybrid.encrypt(Q, new byte[0], CONTEXT);
        assertArrayEquals(new byte[0], decryptor.decrypt(fromBc, CONTEXT));
    }

    @Test
    void tamperedCiphertextRejected() throws Exception {
        HybridEncrypt encryptor = InteropTink.newRawSm2HybridEncryptor();
        HybridDecrypt decryptor = InteropTink.newRawSm2HybridDecryptor();

        byte[] ciphertext = encryptor.encrypt(PLAINTEXT, CONTEXT);
        // 篡改 SM4-GCM 部分。
        byte[] flipped = Arrays.copyOf(ciphertext, ciphertext.length);
        flipped[flipped.length - 1] ^= 1;
        assertThrows(GeneralSecurityException.class,
                () -> Sm2KemSm4GcmHybrid.decrypt(D, flipped, CONTEXT));
        assertThrows(GeneralSecurityException.class, () -> decryptor.decrypt(flipped, CONTEXT));
        // 篡改 C1（首字节）。
        byte[] badC1 = Arrays.copyOf(ciphertext, ciphertext.length);
        badC1[0] = 0x05;
        assertThrows(GeneralSecurityException.class,
                () -> Sm2KemSm4GcmHybrid.decrypt(D, badC1, CONTEXT));
    }
}
