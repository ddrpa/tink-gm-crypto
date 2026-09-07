package cc.ddrpa.crypto.tink.sm2.internal;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.bouncycastle.crypto.digests.SM3Digest;

/**
 * SM2 密钥派生函数（KDF），见 GB/T 32918.4-2016 第 5.4.3 节。
 *
 * <p>派生过程：设 Z 为输入（在 SM2 加密中原样为共享点坐标 x2 ‖ y2），以 SM3 为哈希函数按计数
 * 生成足够的比特流后截取前 klen 比特。
 */
public final class Sm2Kdf {

    /** SM3 摘要长度（字节）。 */
    public static final int SM3_DIGEST_SIZE = 32;

    private Sm2Kdf() {
    }

    /**
     * 使用 SM2-KDF 派生密钥材料。
     *
     * @param z 派生输入（通常为 64 字节的 x2 ‖ y2）
     * @param outputSizeBytes 期望的输出长度（字节），可为 0
     * @throws GeneralSecurityException 参数非法时抛出
     */
    public static byte[] derive(byte[] z, int outputSizeBytes) throws GeneralSecurityException {
        if (z == null) {
            throw new GeneralSecurityException("KDF input must not be null");
        }
        if (outputSizeBytes < 0) {
            throw new GeneralSecurityException(
                "KDF output size must be non-negative, got " + outputSizeBytes);
        }
        if (outputSizeBytes == 0) {
            return new byte[0];
        }
        int blockCount = (outputSizeBytes + SM3_DIGEST_SIZE - 1) / SM3_DIGEST_SIZE;
        if (blockCount > 0xFFFFFFFFL) {
            throw new GeneralSecurityException("KDF output size is too large");
        }
        byte[] output = new byte[blockCount * SM3_DIGEST_SIZE];
        byte[] counter = new byte[4];
        SM3Digest digest = new SM3Digest();
        byte[] block = new byte[SM3_DIGEST_SIZE];
        for (int i = 1; i <= blockCount; i++) {
            // 计数器按大端写入 4 字节。
            counter[0] = (byte) (i >>> 24);
            counter[1] = (byte) (i >>> 16);
            counter[2] = (byte) (i >>> 8);
            counter[3] = (byte) i;
            digest.reset();
            digest.update(z, 0, z.length);
            digest.update(counter, 0, counter.length);
            digest.doFinal(block, 0);
            System.arraycopy(block, 0, output, (i - 1) * SM3_DIGEST_SIZE, SM3_DIGEST_SIZE);
        }
        Arrays.fill(block, (byte) 0);
        if (output.length == outputSizeBytes) {
            return output;
        }
        return Arrays.copyOf(output, outputSizeBytes);
    }
}
