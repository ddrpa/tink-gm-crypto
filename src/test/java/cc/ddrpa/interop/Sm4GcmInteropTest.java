package cc.ddrpa.interop;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cc.ddrpa.interop.bc.HexUtil;
import cc.ddrpa.interop.bc.Sm4GcmAead;
import cc.ddrpa.interop.testing.InteropFixtures;
import cc.ddrpa.interop.testing.InteropTink;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.aead.AeadConfig;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import cc.ddrpa.crypto.tink.aead.Sm4GcmKeyManager;

/**
 * SM4-GCM AEAD 的跨系统互操作自检：Tink 侧（本库）⇄ 对方侧（纯 BouncyCastle，见
 * {@code cc.ddrpa.interop.bc.Sm4GcmAead}）。
 *
 * <p>RAW 输出线格式（与 BC/OpenSSL 的 SM4-GCM 一致）：{@code IV(12) ‖ 密文 ‖ tag(16)}。
 */
class Sm4GcmInteropTest {

    private static final byte[] KEY = InteropTink.fixtureSm4Key();
    private static final byte[] PLAINTEXT = InteropFixtures.SAMPLE_PLAINTEXT;
    private static final int FIXED_KEY_ID = 0x12345678;

    @BeforeAll
    static void setUp() throws Exception {
        AeadConfig.register();
        Sm4GcmKeyManager.register(true);
    }

    // 方向一：Tink 加密 → 对方 BC 解密。
    @Test
    void tinkEncryptsBcDecrypts() throws Exception {
        Aead tink = InteropTink.newRawSm4GcmAead();
        for (byte[] aad : new byte[][]{InteropFixtures.SAMPLE_AAD, new byte[]{}, null}) {
            byte[] ciphertext = tink.encrypt(PLAINTEXT, aad);
            // RAW：无前缀，密文 = 12 + n + 16。
            assertEquals(12 + PLAINTEXT.length + 16, ciphertext.length);
            byte[] aadForBc = aad == null ? new byte[0] : aad;
            assertArrayEquals(
                PLAINTEXT, Sm4GcmAead.decrypt(KEY, ciphertext, aadForBc));
        }
    }

    // 方向二：对方 BC 加密 → Tink 解密。
    @Test
    void bcEncryptsTinkDecrypts() throws Exception {
        Aead tink = InteropTink.newRawSm4GcmAead();
        byte[] aad = InteropFixtures.SAMPLE_AAD;
        // BC 随机 IV。
        byte[] bcCiphertext = Sm4GcmAead.encrypt(KEY, PLAINTEXT, aad);
        assertArrayEquals(PLAINTEXT, tink.decrypt(bcCiphertext, aad));
        // BC 固定 IV（展示显式 IV 用法；生产请用随机 IV）。
        byte[] fixedIv = HexUtil.decode("000102030405060708090a0b");
        byte[] bcFixed = Sm4GcmAead.encryptWithIv(KEY, fixedIv, PLAINTEXT, aad);
        assertEquals(12, bcFixed.length - PLAINTEXT.length - 16);
        assertArrayEquals(PLAINTEXT, tink.decrypt(bcFixed, aad));
    }

    @Test
    void emptyPlaintextWorksBothWays() throws Exception {
        Aead tink = InteropTink.newRawSm4GcmAead();
        byte[] empty = new byte[0];
        byte[] fromTink = tink.encrypt(empty, InteropFixtures.SAMPLE_AAD);
        assertArrayEquals(empty, Sm4GcmAead.decrypt(KEY, fromTink, InteropFixtures.SAMPLE_AAD));

        byte[] fromBc = Sm4GcmAead.encrypt(KEY, empty, null);
        assertArrayEquals(empty, tink.decrypt(fromBc, null));
    }

    @Test
    void wrongAadRejectedByBothSides() throws Exception {
        Aead tink = InteropTink.newRawSm4GcmAead();
        byte[] wrongAad = "someone-else".getBytes();
        byte[] tinkCiphertext = tink.encrypt(PLAINTEXT, InteropFixtures.SAMPLE_AAD);
        assertThrows(
            GeneralSecurityException.class,
            () -> Sm4GcmAead.decrypt(KEY, tinkCiphertext, wrongAad));

        byte[] bcCiphertext = Sm4GcmAead.encrypt(KEY, PLAINTEXT, InteropFixtures.SAMPLE_AAD);
        assertThrows(GeneralSecurityException.class, () -> tink.decrypt(bcCiphertext, wrongAad));
    }

    /**
     * TINK 前缀变体的数据落到对方系统时，对方需要按 {@code 0x01 ‖ keyId(4 字节大端)} 剥离前缀
     * （并把 keyId 与自己的密钥对应起来）再按 RAW 布局解密——本用例验证该剥离/校验逻辑。
     */
    @Test
    void tinkPrefixStrippedBeforeBcDecrypt() throws Exception {
        Aead tink = InteropTink.newTinkSm4GcmAead(FIXED_KEY_ID);
        byte[] ciphertext = tink.encrypt(PLAINTEXT, InteropFixtures.SAMPLE_AAD);

        // 先校验前缀并取出 keyId，与本地密钥对应后再剥离解密。
        assertEquals(FIXED_KEY_ID, readTinkPrefixKeyId(ciphertext));
        byte[] body = stripTinkPrefix(ciphertext);
        assertArrayEquals(PLAINTEXT, Sm4GcmAead.decrypt(KEY, body, InteropFixtures.SAMPLE_AAD));
    }

    /** 读取 TINK 前缀中的 keyId（4 字节大端）。 */
    static int readTinkPrefixKeyId(byte[] prefixed) {
        assertTrue(prefixed.length > 5, "ciphertext too short for TINK prefix");
        assertEquals(0x01, prefixed[0] & 0xff);
        return ((prefixed[1] & 0xff) << 24)
            | ((prefixed[2] & 0xff) << 16)
            | ((prefixed[3] & 0xff) << 8)
            | (prefixed[4] & 0xff);
    }

    /** 剥离 5 字节 TINK 前缀，返回后续密文体。 */
    static byte[] stripTinkPrefix(byte[] prefixed) {
        readTinkPrefixKeyId(prefixed);
        return Arrays.copyOfRange(prefixed, 5, prefixed.length);
    }
}
