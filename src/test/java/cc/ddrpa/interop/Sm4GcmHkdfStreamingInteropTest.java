package cc.ddrpa.interop;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKeyManager;
import cc.ddrpa.interop.bc.Sm4GcmHkdfStreamingAead;
import cc.ddrpa.interop.testing.InteropFixtures;
import cc.ddrpa.interop.testing.InteropTink;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * SM4-GCM-HKDF 流式 AEAD（本库自定义线格式）的跨系统互操作自检：Tink 侧 ⇄ 对方侧（纯
 * BouncyCastle，{@code cc.ddrpa.interop.bc.Sm4GcmHkdfStreamingAead}）。
 *
 * <p>覆盖 4KB 与 1MB 密文段模板、各段边界长度、空明文/空 AAD、篡改拒绝与错误 AAD 拒绝。
 */
class Sm4GcmHkdfStreamingInteropTest {

    private static final byte[] IKM = InteropTink.fixtureSm4Key();
    private static final int SEGMENT_4KB = 4096;
    private static final int SEGMENT_1MB = 1024 * 1024;

    @BeforeAll
    static void setUp() throws Exception {
        StreamingAeadConfig.register();
        Sm4GcmHkdfStreamingKeyManager.register(true);
    }

    private static byte[] tinkEncrypt(StreamingAead streaming, byte[] plaintext, byte[] aad)
        throws Exception {
        ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
        try (OutputStream encrypting =
            streaming.newEncryptingStream(ciphertext, aad == null ? new byte[0] : aad)) {
            encrypting.write(plaintext);
        }
        return ciphertext.toByteArray();
    }

    static byte[] tinkDecrypt(StreamingAead streaming, byte[] ciphertext, byte[] aad)
        throws Exception {
        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        try (InputStream decrypting = streaming.newDecryptingStream(
            new ByteArrayInputStream(ciphertext), aad == null ? new byte[0] : aad)) {
            byte[] buf = new byte[1 << 16];
            int n;
            while ((n = decrypting.read(buf)) > 0) {
                plaintext.write(buf, 0, n);
            }
        }
        return plaintext.toByteArray();
    }

    /** 生成确定性的伪随机测试数据。 */
    private static byte[] randomData(int length, long seed) {
        byte[] data = new byte[length];
        new Random(seed).nextBytes(data);
        return data;
    }

    // 方向一：对方 BC 加密 → Tink 解密。覆盖 4KB 模板的段边界与多段数据。
    @Test
    void bcEncryptsTinkDecryptsForBoundarySizes() throws Exception {
        StreamingAead tink = InteropTink.newSm4GcmHkdfStreamingAead(SEGMENT_4KB);
        int[] sizes = {0, 1, 4055, 4056, 4057, 4079, 4080, 4081, 8192, 100000};
        for (int i = 0; i < sizes.length; i++) {
            int size = sizes[i];
            byte[] plaintext = randomData(size, 100 + i);
            byte[] aad = (i % 2 == 0) ? InteropFixtures.SAMPLE_AAD : new byte[0];
            byte[] ciphertext =
                Sm4GcmHkdfStreamingAead.encryptBytes(IKM, SEGMENT_4KB, aad, plaintext);
            // 对方产出的密文长度与 Tink 布局公式一致。
            assertEquals(
                Sm4GcmHkdfStreamingAead.ciphertextSize(size, SEGMENT_4KB),
                ciphertext.length,
                "size=" + size);
            assertArrayEquals(plaintext, tinkDecrypt(tink, ciphertext, aad));
        }
    }

    // 方向二：Tink 加密 → 对方 BC 解密。
    @Test
    void tinkEncryptsBcDecrypts() throws Exception {
        StreamingAead tink = InteropTink.newSm4GcmHkdfStreamingAead(SEGMENT_4KB);
        int[] sizes = {0, 1, 4056, 4057, 100000};
        for (int i = 0; i < sizes.length; i++) {
            int size = sizes[i];
            byte[] plaintext = randomData(size, 200 + i);
            byte[] aad = InteropFixtures.SAMPLE_AAD;
            byte[] ciphertext = tinkEncrypt(tink, plaintext, aad);
            assertEquals(
                Sm4GcmHkdfStreamingAead.ciphertextSize(size, SEGMENT_4KB),
                ciphertext.length,
                "size=" + size);
            assertArrayEquals(
                plaintext,
                Sm4GcmHkdfStreamingAead.decryptBytes(IKM, SEGMENT_4KB, aad, ciphertext));
        }
    }

    // 1MB 密文段模板（大文件场景）双向验证。
    @Test
    void oneMegabyteSegmentTemplateBothWays() throws Exception {
        StreamingAead tink = InteropTink.newSm4GcmHkdfStreamingAead(SEGMENT_1MB);
        byte[] plaintext = randomData(250000, 42);
        byte[] aad = InteropFixtures.SAMPLE_AAD;

        byte[] bcCiphertext =
            Sm4GcmHkdfStreamingAead.encryptBytes(IKM, SEGMENT_1MB, aad, plaintext);
        assertArrayEquals(plaintext, tinkDecrypt(tink, bcCiphertext, aad));

        byte[] tinkCiphertext = tinkEncrypt(tink, plaintext, aad);
        assertArrayEquals(
            plaintext,
            Sm4GcmHkdfStreamingAead.decryptBytes(IKM, SEGMENT_1MB, aad, tinkCiphertext));
    }

    @Test
    void emptyAndNullAadAreEquivalent() throws Exception {
        StreamingAead tink = InteropTink.newSm4GcmHkdfStreamingAead(SEGMENT_4KB);
        byte[] plaintext = randomData(5000, 7);
        byte[] ctEmptyAad = tinkEncrypt(tink, plaintext, new byte[0]);
        assertArrayEquals(
            plaintext,
            Sm4GcmHkdfStreamingAead.decryptBytes(IKM, SEGMENT_4KB, new byte[0], ctEmptyAad));
        assertArrayEquals(
            plaintext,
            Sm4GcmHkdfStreamingAead.decryptBytes(IKM, SEGMENT_4KB, null, ctEmptyAad));
    }

    @Test
    void wrongAadRejectedByBothSides() throws Exception {
        StreamingAead tink = InteropTink.newSm4GcmHkdfStreamingAead(SEGMENT_4KB);
        byte[] plaintext = randomData(20000, 11);
        byte[] wrongAad = "wrong-aad".getBytes();

        byte[] tinkCiphertext = tinkEncrypt(tink, plaintext, InteropFixtures.SAMPLE_AAD);
        assertThrows(Exception.class,
            () -> Sm4GcmHkdfStreamingAead.decryptBytes(
                IKM, SEGMENT_4KB, wrongAad, tinkCiphertext));

        byte[] bcCiphertext =
            Sm4GcmHkdfStreamingAead.encryptBytes(IKM, SEGMENT_4KB, InteropFixtures.SAMPLE_AAD,
                plaintext);
        assertThrows(Exception.class, () -> tinkDecrypt(tink, bcCiphertext, wrongAad));
    }

    @Test
    void tamperedCiphertextRejected() throws Exception {
        byte[] plaintext = randomData(20000, 13);
        byte[] ciphertext =
            Sm4GcmHkdfStreamingAead.encryptBytes(IKM, SEGMENT_4KB, InteropFixtures.SAMPLE_AAD,
                plaintext);
        // 篡改中间一段密文。
        byte[] tampered = Arrays.copyOf(ciphertext, ciphertext.length);
        tampered[tampered.length / 2] ^= 1;
        assertThrows(Exception.class,
            () -> Sm4GcmHkdfStreamingAead.decryptBytes(
                IKM, SEGMENT_4KB, InteropFixtures.SAMPLE_AAD, tampered));

        // 篡改 header 中的 salt。
        byte[] tamperedHeader = Arrays.copyOf(ciphertext, ciphertext.length);
        tamperedHeader[1] ^= 1;
        assertThrows(Exception.class,
            () -> Sm4GcmHkdfStreamingAead.decryptBytes(
                IKM, SEGMENT_4KB, InteropFixtures.SAMPLE_AAD, tamperedHeader));
    }
}
