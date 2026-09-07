package cc.ddrpa.interop.bc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 对方侧（不使用 Google Tink）的 SM4-GCM-HKDF <strong>流式 AEAD</strong> 参考实现
 * （仅 BouncyCastle + JDK）。
 *
 * <p>该线格式不是任何国标/通用格式，而是本库（以及其对照实现的 Google Tink AES-GCM-HKDF 流式
 * 布局）自定义的流式格式。若要与本库的 {@code SM4_GCM_HKDF_1MB / SM4_GCM_HKDF_4KB} 密钥互操作，
 * 必须按下述布局实现；仅用于本库与对方系统之间，双方都使用本实现即可互通。
 *
 * <p>线格式（header 长度固定为 24）：
 *
 * <pre>
 *   密文 = header ‖ segment_0 ‖ segment_1 ‖ … ‖ segment_k
 *   header = headerLength(1 字节, =24) ‖ salt(16) ‖ noncePrefix(7)
 * </pre>
 *
 * <ul>
 *   <li>每个密文文件使用随机 salt 与随机 noncePrefix（各一次）；</li>
 *   <li>每段数据密钥：<code>key_i = HKDF-SHA256(ikm, salt = header.salt, info = AAD, L = 16)</code>
 *       ——注意 HKDF 使用 HMAC-SHA256（非 SM3），AAD 通过 HKDF 的 info 绑定到整份密文而非逐段 GCM；</li>
 *   <li>每段 nonce（12 字节）= {@code noncePrefix ‖ u32be(段序号) ‖ last}，段序号从 0 递增，
 *       last 为 1 表示最后一段；每段用 SM4-GCM 加密（128 位 key、128 位 tag、无 AAD）；</li>
 *   <li>段大小：令 C = ciphertextSegmentSize（4096 或 1MB），
 *       segment_0 的密文长 C−24（含 16 字节 tag），之后每段密文长 C；
 *       对应地 segment_0 明文容量为 C−40，之后每段明文容量为 C−16；</li>
 *   <li>最后一段始终带 last=1 标记；空明文时密文 = header + 仅含 tag 的最后一段（共 40 字节）。</li>
 * </ul>
 *
 * <p>解密方按段序读取：前 24 字节为 header，随后第 0 段最多读 C−24 字节（若文件在此结束则该段为
 * 最后一段且可能更短），之后每段最多读 C 字节，读到文件末尾的那一段即为最后一段。
 */
public final class Sm4GcmHkdfStreamingAead {

    private Sm4GcmHkdfStreamingAead() {
    }

    /** 派生数据密钥/header salt 长度。 */
    public static final int KEY_SIZE_BYTES = 16;
    /** header 中 nonce 前缀长度。 */
    public static final int NONCE_PREFIX_SIZE_BYTES = 7;
    /** header 总长：headerLength(1) + salt(16) + noncePrefix(7)。 */
    public static final int HEADER_LENGTH = 1 + KEY_SIZE_BYTES + NONCE_PREFIX_SIZE_BYTES;
    /** 每段 GCM tag 长度。 */
    public static final int TAG_SIZE_BYTES = 16;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

    private static void checkParameters(byte[] ikm, int ciphertextSegmentSize)
        throws GeneralSecurityException {
        if (ikm == null || ikm.length < 16 || ikm.length < KEY_SIZE_BYTES) {
            throw new GeneralSecurityException(
                "ikm must be at least " + KEY_SIZE_BYTES + " bytes");
        }
        if (ciphertextSegmentSize <= HEADER_LENGTH + TAG_SIZE_BYTES + 16) {
            throw new GeneralSecurityException(
                "ciphertextSegmentSize must be larger than " + (HEADER_LENGTH + TAG_SIZE_BYTES + 16));
        }
    }

    /**
     * 流式加密：把 {@code plaintext} 的内容加密写入 {@code ciphertext}（header + 分段密文）。
     *
     * @param ikm 初始密钥材料（≥ 16 字节；本库模板为 16 字节 SM4 密钥）
     * @param ciphertextSegmentSize 密文段大小（本库 4KB/1MB 模板分别为 4096 / 1048576）
     * @param associatedData 关联数据（绑定整份密文，解密需相同；null 与空数组等价）
     */
    public static void encrypt(
        byte[] ikm,
        int ciphertextSegmentSize,
        byte[] associatedData,
        InputStream plaintext,
        OutputStream ciphertext)
        throws GeneralSecurityException, IOException {
        checkParameters(ikm, ciphertextSegmentSize);
        byte[] aad = associatedData == null ? new byte[0] : associatedData;

        // 1. 生成 header 并写出。
        byte[] salt = new byte[KEY_SIZE_BYTES];
        byte[] noncePrefix = new byte[NONCE_PREFIX_SIZE_BYTES];
        RANDOM.nextBytes(salt);
        RANDOM.nextBytes(noncePrefix);
        byte[] header = new byte[HEADER_LENGTH];
        header[0] = (byte) HEADER_LENGTH;
        System.arraycopy(salt, 0, header, 1, KEY_SIZE_BYTES);
        System.arraycopy(noncePrefix, 0, header, 1 + KEY_SIZE_BYTES, NONCE_PREFIX_SIZE_BYTES);
        ciphertext.write(header);

        // 2. 派生整份密文的数据密钥。
        byte[] segmentKey = hkdfSha256(ikm, salt, aad, KEY_SIZE_BYTES);

        // 3. 分段加密（与 Tink 通道一致的“惰性”出段：段缓冲区写满且仍有后续明文时才输出非最后段，
        //    EOF 时把剩余内容作为最后一段输出；空明文输出仅含 tag 的最后一段）。
        int firstPlaintextCap = ciphertextSegmentSize - HEADER_LENGTH - TAG_SIZE_BYTES; // C-40
        int plaintextCap = ciphertextSegmentSize - TAG_SIZE_BYTES; // C-16
        int cap = firstPlaintextCap;
        byte[] buf = new byte[plaintextCap]; // 一次性分配最大段容量，首段只使用前 firstPlaintextCap 字节
        int pos = 0;
        long segmentNr = 0;
        byte[] chunk = new byte[1 << 16];
        while (true) {
            int n = plaintext.read(chunk);
            if (n < 0) {
                // 写出最后一段（可能为空 → 仅 16 字节 tag）。
                writeSegment(segmentKey, noncePrefix, segmentNr, true, buf, pos, ciphertext);
                return;
            }
            int off = 0;
            while (off < n) {
                int space = cap - pos;
                if (space == 0) {
                    // 缓冲满且仍有待处理明文：先输出非最后一段，并切换到后续段的明文容量。
                    writeSegment(segmentKey, noncePrefix, segmentNr, false, buf, cap, ciphertext);
                    segmentNr++;
                    pos = 0;
                    cap = plaintextCap;
                    continue;
                }
                int take = Math.min(n - off, space);
                System.arraycopy(chunk, off, buf, pos, take);
                pos += take;
                off += take;
            }
        }
    }

    /**
     * 流式解密：读取 {@code ciphertext}（header + 分段密文），把明文写入 {@code plaintext}。
     *
     * <p>解密失败的段（tag 校验失败、header 非法等）抛出 {@link GeneralSecurityException}。
     */
    public static void decrypt(
        byte[] ikm,
        int ciphertextSegmentSize,
        byte[] associatedData,
        InputStream ciphertext,
        OutputStream plaintext)
        throws GeneralSecurityException, IOException {
        checkParameters(ikm, ciphertextSegmentSize);
        byte[] aad = associatedData == null ? new byte[0] : associatedData;

        // 1. 读 header。
        byte[] header = new byte[HEADER_LENGTH];
        int headerGot = readUpTo(ciphertext, header, HEADER_LENGTH);
        if (headerGot < HEADER_LENGTH) {
            throw new GeneralSecurityException("Ciphertext is too short");
        }
        if ((header[0] & 0xff) != HEADER_LENGTH) {
            throw new GeneralSecurityException("Invalid ciphertext header");
        }
        byte[] salt = Arrays.copyOfRange(header, 1, 1 + KEY_SIZE_BYTES);
        byte[] noncePrefix = Arrays.copyOfRange(
            header, 1 + KEY_SIZE_BYTES, HEADER_LENGTH);
        byte[] segmentKey = hkdfSha256(ikm, salt, aad, KEY_SIZE_BYTES);

        // 2. 逐段解密：segment_0 密文长 C-24，其后每段 C；段内读到 EOF 则该段为最后一段。
        int expected = ciphertextSegmentSize - HEADER_LENGTH;
        long segmentNr = 0;
        int pending = -1; // 预读的一个字节（跨段边界）
        while (true) {
            byte[] segment = new byte[expected];
            int got = 0;
            boolean eof = false;
            while (got < expected) {
                int b = pending >= 0 ? pending : ciphertext.read();
                pending = -1;
                if (b < 0) {
                    eof = true;
                    break;
                }
                segment[got++] = (byte) b;
            }
            boolean isLast;
            if (!eof) {
                int b = ciphertext.read();
                if (b < 0) {
                    isLast = true;
                } else {
                    isLast = false;
                    pending = b;
                }
            } else {
                isLast = true;
            }
            if (got < TAG_SIZE_BYTES) {
                throw new GeneralSecurityException("Ciphertext is truncated");
            }
            byte[] plainSegment = gcmDecryptSegment(
                segmentKey, noncePrefix, segmentNr, isLast, segment, got);
            plaintext.write(plainSegment);
            segmentNr++;
            if (isLast) {
                return;
            }
            expected = ciphertextSegmentSize;
        }
    }

    /** 字节数组便捷方法：加密整段明文。 */
    public static byte[] encryptBytes(
        byte[] ikm, int ciphertextSegmentSize, byte[] associatedData, byte[] plaintext)
        throws GeneralSecurityException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        encrypt(
            ikm,
            ciphertextSegmentSize,
            associatedData,
            new ByteArrayInputStream(plaintext),
            out);
        return out.toByteArray();
    }

    /** 字节数组便捷方法：解密整段密文。 */
    public static byte[] decryptBytes(
        byte[] ikm, int ciphertextSegmentSize, byte[] associatedData, byte[] ciphertext)
        throws GeneralSecurityException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        decrypt(
            ikm,
            ciphertextSegmentSize,
            associatedData,
            new ByteArrayInputStream(ciphertext),
            out);
        return out.toByteArray();
    }

    /** @return 与 Tink 侧 {@code expectedCiphertextSize} 一致的理论密文总长（含 header）。 */
    public static long ciphertextSize(long plaintextSize, int ciphertextSegmentSize) {
        int plaintextSegmentSize = ciphertextSegmentSize - TAG_SIZE_BYTES;
        long offset = HEADER_LENGTH;
        long fullSegments = (plaintextSize + offset) / plaintextSegmentSize;
        long size = fullSegments * ciphertextSegmentSize;
        long lastSegmentSize = (plaintextSize + offset) % plaintextSegmentSize;
        if (lastSegmentSize > 0) {
            size += lastSegmentSize + TAG_SIZE_BYTES;
        }
        return size;
    }

    private static void writeSegment(
        byte[] segmentKey,
        byte[] noncePrefix,
        long segmentNr,
        boolean isLast,
        byte[] plaintext,
        int plaintextLen,
        OutputStream ciphertext)
        throws GeneralSecurityException, IOException {
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", BC_PROVIDER);
        cipher.init(
            Cipher.ENCRYPT_MODE,
            new SecretKeySpec(segmentKey, "SM4"),
            new GCMParameterSpec(8 * TAG_SIZE_BYTES, makeNonce(noncePrefix, segmentNr, isLast)));
        ciphertext.write(cipher.doFinal(plaintext, 0, plaintextLen));
    }

    private static byte[] gcmDecryptSegment(
        byte[] segmentKey,
        byte[] noncePrefix,
        long segmentNr,
        boolean isLast,
        byte[] ciphertextSegment,
        int segmentLen)
        throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", BC_PROVIDER);
        cipher.init(
            Cipher.DECRYPT_MODE,
            new SecretKeySpec(segmentKey, "SM4"),
            new GCMParameterSpec(
                8 * TAG_SIZE_BYTES, makeNonce(noncePrefix, segmentNr, isLast)));
        byte[] plaintext = cipher.doFinal(ciphertextSegment, 0, segmentLen);
        return Arrays.copyOf(plaintext, plaintext.length);
    }

    /** nonce = noncePrefix(7) ‖ u32be(segmentNr) ‖ last。 */
    private static byte[] makeNonce(byte[] noncePrefix, long segmentNr, boolean isLast) {
        if (segmentNr >= (1L << 32)) {
            throw new IllegalStateException("Too many segments: 32 bit segment counter overflow");
        }
        byte[] nonce = new byte[12];
        System.arraycopy(noncePrefix, 0, nonce, 0, NONCE_PREFIX_SIZE_BYTES);
        nonce[7] = (byte) (segmentNr >>> 24);
        nonce[8] = (byte) (segmentNr >>> 16);
        nonce[9] = (byte) (segmentNr >>> 8);
        nonce[10] = (byte) segmentNr;
        nonce[11] = (byte) (isLast ? 1 : 0);
        return nonce;
    }

    /** RFC 5869 HKDF 使用 HMAC-SHA256，输出 {@code length} 字节。 */
    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
        throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        // extract
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        // expand
        Mac expand = Mac.getInstance("HmacSHA256");
        expand.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] output = new byte[length];
        byte[] t = new byte[0];
        int blockSize = 32;
        int blocks = (length + blockSize - 1) / blockSize;
        for (int i = 1; i <= blocks; i++) {
            expand.reset();
            expand.update(t);
            expand.update(info);
            expand.update((byte) i);
            t = expand.doFinal();
            System.arraycopy(t, 0, output, (i - 1) * blockSize,
                Math.min(blockSize, length - (i - 1) * blockSize));
        }
        return output;
    }

    /** 尽力读取 {@code len} 字节，返回实际读取字节数（遇 EOF 提前返回）。 */
    private static int readUpTo(InputStream in, byte[] buf, int len) throws IOException {
        int read = 0;
        while (read < len) {
            int n = in.read(buf, read, len - read);
            if (n < 0) {
                break;
            }
            if (n == 0) {
                continue;
            }
            read += n;
        }
        return read;
    }
}
