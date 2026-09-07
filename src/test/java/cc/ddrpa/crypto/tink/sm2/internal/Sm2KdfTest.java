package cc.ddrpa.crypto.tink.sm2.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link Sm2Kdf}.
 *
 * <p>KDF 的参考实现：GB/T 32918.4-2016 第 5.4.3 节（SM3 计数型），测试中直接用 SM3Digest 独立
 * 计算 H_1 = SM3(z ‖ 0x00000001)、H_2 = SM3(z ‖ 0x00000002) 等与实现结果比对。
 */
class Sm2KdfTest {

    private static byte[] referenceHash(byte[] z, int counter) {
        SM3Digest digest = new SM3Digest();
        byte[] counterBytes = new byte[] {
            (byte) (counter >>> 24), (byte) (counter >>> 16), (byte) (counter >>> 8), (byte) counter};
        digest.update(z, 0, z.length);
        digest.update(counterBytes, 0, counterBytes.length);
        byte[] hash = new byte[Sm2Kdf.SM3_DIGEST_SIZE];
        digest.doFinal(hash, 0);
        return hash;
    }

    @Test
    void derive_zeroLength_returnsEmpty() throws Exception {
        assertArrayEquals(new byte[0], Sm2Kdf.derive(new byte[64], 0));
    }

    @Test
    void derive_singleBlock_matchesSM3OfZAndCounterOne() throws Exception {
        byte[] z = new byte[64];
        for (int i = 0; i < z.length; i++) {
            z[i] = (byte) (i * 7);
        }
        byte[] reference = referenceHash(z, 1);
        assertArrayEquals(reference, Sm2Kdf.derive(z, Sm2Kdf.SM3_DIGEST_SIZE));
        // 截取：16 字节输出应等于前 16 字节。
        assertArrayEquals(
            Arrays.copyOf(reference, 16), Sm2Kdf.derive(z, 16));
    }

    @Test
    void derive_multiBlock_matchesConcatenatedHashes() throws Exception {
        byte[] z = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        byte[] output = Sm2Kdf.derive(z, 2 * Sm2Kdf.SM3_DIGEST_SIZE + 5);
        assertArrayEquals(referenceHash(z, 1), Arrays.copyOfRange(output, 0, 32));
        assertArrayEquals(referenceHash(z, 2), Arrays.copyOfRange(output, 32, 64));
        assertArrayEquals(
            Arrays.copyOf(referenceHash(z, 3), 5), Arrays.copyOfRange(output, 64, 69));
    }

    @Test
    void derive_isDeterministicAndSensitiveToInput() throws Exception {
        byte[] z1 = new byte[64];
        byte[] z2 = new byte[64];
        z2[63] = 1;
        assertArrayEquals(Sm2Kdf.derive(z1, 40), Sm2Kdf.derive(z1, 40));
        assertTrue(!Arrays.equals(Sm2Kdf.derive(z1, 40), Sm2Kdf.derive(z2, 40)));
    }

    @Test
    void derive_rejectsInvalidArguments() {
        assertThrows(GeneralSecurityException.class, () -> Sm2Kdf.derive(null, 16));
        assertThrows(GeneralSecurityException.class, () -> Sm2Kdf.derive(new byte[16], -1));
    }
}
