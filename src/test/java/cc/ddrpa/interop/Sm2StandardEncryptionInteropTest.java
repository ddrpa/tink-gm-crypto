package cc.ddrpa.interop;

import cc.ddrpa.crypto.tink.hybrid.Sm2EncryptionKeyManager;
import cc.ddrpa.interop.bc.Sm2StandardEncryption;
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
 * 标准 SM2 加密（GB/T 32918.4，C1C3C2）的跨系统互操作自检：Tink 侧 ⇄ 对方侧（纯 BouncyCastle，
 * {@code cc.ddrpa.interop.bc.Sm2StandardEncryption}）。
 *
 * <p>RAW 输出线格式：{@code C1(65, 0x04‖X‖Y) ‖ C3(32, SM3) ‖ C2}；无关联数据（contextInfo 必须
 * 为 null/空）；明文必须非空。
 */
class Sm2StandardEncryptionInteropTest {

    private static final byte[] D = InteropTink.fixtureD();
    private static final byte[] Q = InteropTink.fixtureQ();
    private static final byte[] PLAINTEXT = InteropFixtures.SAMPLE_PLAINTEXT;
    private static final int FIXED_KEY_ID = 0x77aabbcc;

    @BeforeAll
    static void setUp() throws Exception {
        HybridEncryptWrapper.register();
        HybridDecryptWrapper.register();
        Sm2EncryptionKeyManager.registerPair(true);
    }

    // 方向一：Tink 加密 → 对方 BC 解密。
    @Test
    void tinkEncryptsBcDecrypts() throws Exception {
        HybridEncrypt encryptor = InteropTink.newRawSm2StandardEncryptor();
        for (byte[] context : new byte[][]{null, new byte[]{}}) {
            byte[] ciphertext = encryptor.encrypt(PLAINTEXT, context);
            // RAW：密文 = 65 + 32 + 明文长，首字节 0x04（非压缩点）。
            assertEquals(65 + 32 + PLAINTEXT.length, ciphertext.length);
            assertEquals(0x04, ciphertext[0] & 0xff);
            assertArrayEquals(PLAINTEXT, Sm2StandardEncryption.decrypt(D, ciphertext));
        }
    }

    // 方向二：对方 BC 加密 → Tink 解密。
    @Test
    void bcEncryptsTinkDecrypts() throws Exception {
        HybridDecrypt decryptor = InteropTink.newRawSm2StandardDecryptor();
        byte[] ciphertext = Sm2StandardEncryption.encrypt(Q, PLAINTEXT);
        assertEquals(65 + 32 + PLAINTEXT.length, ciphertext.length);
        assertArrayEquals(PLAINTEXT, decryptor.decrypt(ciphertext, null));
    }

    @Test
    void nonEmptyContextInfoRejectedByTink() throws Exception {
        HybridEncrypt encryptor = InteropTink.newRawSm2StandardEncryptor();
        byte[] context = "不应支持".getBytes();
        GeneralSecurityException e =
                assertThrows(GeneralSecurityException.class, () -> encryptor.encrypt(PLAINTEXT, context));
        assertTrue(e.getMessage() != null); // 报错即视为通过
    }

    @Test
    void emptyPlaintextRejectedByBothSides() throws Exception {
        HybridEncrypt encryptor = InteropTink.newRawSm2StandardEncryptor();
        assertThrows(GeneralSecurityException.class, () -> encryptor.encrypt(new byte[0], null));
        assertThrows(
                GeneralSecurityException.class,
                () -> Sm2StandardEncryption.encrypt(Q, new byte[0]));
    }

    @Test
    void tamperedCiphertextRejectedByBothSides() throws Exception {
        HybridEncrypt encryptor = InteropTink.newRawSm2StandardEncryptor();
        HybridDecrypt decryptor = InteropTink.newRawSm2StandardDecryptor();

        byte[] ciphertext = encryptor.encrypt(PLAINTEXT, null);
        assertArrayEquals(PLAINTEXT, Sm2StandardEncryption.decrypt(D, ciphertext));

        // 篡改 C2（最后一个字节）与 C1 前缀都必须失败。
        byte[] flippedC2 = Arrays.copyOf(ciphertext, ciphertext.length);
        flippedC2[flippedC2.length - 1] ^= 1;
        assertThrows(GeneralSecurityException.class,
                () -> Sm2StandardEncryption.decrypt(D, flippedC2));
        byte[] badC1 = Arrays.copyOf(ciphertext, ciphertext.length);
        badC1[0] = 0x05;
        assertThrows(GeneralSecurityException.class, () -> Sm2StandardEncryption.decrypt(D, badC1));

        // BC 侧密文被 Tink 拒绝（篡改 C2 后）。
        byte[] bcCiphertext = Sm2StandardEncryption.encrypt(Q, PLAINTEXT);
        byte[] flippedBc = Arrays.copyOf(bcCiphertext, bcCiphertext.length);
        flippedBc[flippedBc.length - 1] ^= 1;
        assertThrows(GeneralSecurityException.class, () -> decryptor.decrypt(flippedBc, null));
    }

    // TINK 前缀的标准 SM2 密文：对方剥离 0x01 ‖ keyId 后按 RAW 解密。
    @Test
    void tinkPrefixedCiphertextStrippedBeforeBcDecrypt() throws Exception {
        HybridEncrypt encryptor = InteropTink.newTinkSm2StandardEncryptor(FIXED_KEY_ID);
        byte[] ciphertext = encryptor.encrypt(PLAINTEXT, null);
        assertEquals(5 + 65 + 32 + PLAINTEXT.length, ciphertext.length);

        assertEquals(0x01, ciphertext[0] & 0xff);
        int keyId = ((ciphertext[1] & 0xff) << 24)
                | ((ciphertext[2] & 0xff) << 16)
                | ((ciphertext[3] & 0xff) << 8)
                | (ciphertext[4] & 0xff);
        assertEquals(FIXED_KEY_ID, keyId);

        byte[] body = Arrays.copyOfRange(ciphertext, 5, ciphertext.length);
        assertArrayEquals(PLAINTEXT, Sm2StandardEncryption.decrypt(D, body));
    }
}
