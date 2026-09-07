package cc.ddrpa.interop.bc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 对方侧（不使用 Google Tink）的 SM2-KEM + SM4-GCM 混合加密参考实现（仅 BouncyCastle + JDK）。
 *
 * <p>该方案与本库 {@code tink-gm-crypto} 的 {@code SM2_HYBRID_RAW}（NO_PREFIX 变体）输出一致，但
 * <strong>不是国标 SM2 密文格式、也不是任何其他标准格式</strong>，密文布局为本库自定义：
 *
 * <pre>
 *   密文 = C1(65) ‖ nonce(12) ‖ SM4-GCM(plaintext, aad = contextInfo)
 * </pre>
 *
 * <ol>
 *   <li>加密方生成临时 SM2 密钥对，C1 = 临时公钥非压缩点（0x04 ‖ X ‖ Y，65 字节）；</li>
 *   <li>共享点 S = k·Q（k 为临时私钥标量，Q 为接收方公钥），以 x2 ‖ y2（64 字节）为输入，用
 *       SM2-KDF（GB/T 32918.4 第 5.4.3 节，SM3 计数型）派生 16 字节 SM4-GCM 数据密钥；</li>
 *   <li>SM4-GCM 的 nonce 为随机 12 字节，<code>contextInfo</code> 作为 AAD 被完整认证
 *       （{@code null} 与空数组等价），解密时必须传入完全相同的字节。</li>
 * </ol>
 *
 * <p>解密方以 S = d·C1 重算共享点并派生同一数据密钥。若需要与主流国密实现互操作的标准 SM2 密文，
 * 请改用 {@link Sm2StandardEncryption}。
 */
public final class Sm2KemSm4GcmHybrid {

    /**
     * C1 长度：65 字节非压缩点。
     */
    public static final int C1_SIZE = Sm2BcUtil.UNCOMPRESSED_POINT_SIZE;
    /**
     * SM4-GCM nonce 长度。
     */
    public static final int NONCE_SIZE = 12;
    /**
     * 派生数据密钥长度：16 字节。
     */
    public static final int KEY_SIZE_BYTES = 16;
    /**
     * 密文体最小长度：C1 + nonce + tag。
     */
    public static final int MIN_CIPHERTEXT_SIZE = C1_SIZE + NONCE_SIZE + 16;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();
    private Sm2KemSm4GcmHybrid() {
    }

    /**
     * 加密。
     *
     * @param q           64 字节接收方公钥（X ‖ Y）
     * @param plaintext   明文（可为空数组）
     * @param contextInfo 关联数据（可为 null/空，作为 SM4-GCM AAD 认证）
     * @return 本库混合密文 {@code C1 ‖ nonce ‖ SM4-GCM 密文}
     */
    public static byte[] encrypt(byte[] q, byte[] plaintext, byte[] contextInfo)
            throws GeneralSecurityException {
        if (plaintext == null) {
            throw new NullPointerException("plaintext is null");
        }
        ECPublicKeyParameters recipientKey = Sm2BcUtil.publicKeyFromXY(q);

        // 1. 临时密钥对与共享点 S = k * Q。
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(Sm2BcUtil.getDomainParameters(), RANDOM));
        AsymmetricCipherKeyPair ephemeral = generator.generateKeyPair();
        byte[] c1 = Sm2BcUtil.encodePoint(((ECPublicKeyParameters) ephemeral.getPublic()).getQ());
        BigInteger k = ((ECPrivateKeyParameters) ephemeral.getPrivate()).getD();
        ECPoint shared = Sm2BcUtil.validatePoint(recipientKey.getQ().multiply(k));

        // 2. SM2-KDF(SM3) 从 x2 || y2 派生数据密钥。
        byte[] demKey = sm2Kdf(Sm2BcUtil.encodePointWithoutPrefix(shared), KEY_SIZE_BYTES);

        // 3. SM4-GCM 加密，contextInfo 作为 AAD。
        byte[] nonce = new byte[NONCE_SIZE];
        RANDOM.nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", BC_PROVIDER);
        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(demKey, "SM4"),
                new GCMParameterSpec(8 * 16, nonce));
        if (contextInfo != null && contextInfo.length != 0) {
            cipher.updateAAD(contextInfo);
        }
        byte[] body = cipher.doFinal(plaintext);

        byte[] output = new byte[c1.length + NONCE_SIZE + body.length];
        System.arraycopy(c1, 0, output, 0, c1.length);
        System.arraycopy(nonce, 0, output, c1.length, NONCE_SIZE);
        System.arraycopy(body, 0, output, c1.length + NONCE_SIZE, body.length);
        return output;
    }

    /**
     * 解密本库混合密文。
     *
     * @param d           32 字节私钥标量
     * @param ciphertext  {@code C1 ‖ nonce ‖ SM4-GCM 密文}（无前缀）
     * @param contextInfo 加密时使用的同一关联数据
     * @return 明文
     * @throws GeneralSecurityException 长度非法、C1 无效、AAD/tag 校验失败等统一抛此异常
     */
    public static byte[] decrypt(byte[] d, byte[] ciphertext, byte[] contextInfo)
            throws GeneralSecurityException {
        if (ciphertext == null) {
            throw new NullPointerException("ciphertext is null");
        }
        if (ciphertext.length < MIN_CIPHERTEXT_SIZE) {
            throw new GeneralSecurityException("Decryption failed");
        }
        ECPrivateKeyParameters privateKey = Sm2BcUtil.privateKeyFromD(d);
        try {
            // 1. C1 点解码并计算共享点 S = d * C1。
            ECPoint c1Point =
                    Sm2BcUtil.decodePoint(Arrays.copyOfRange(ciphertext, 0, C1_SIZE));
            ECPoint shared = Sm2BcUtil.validatePoint(c1Point.multiply(privateKey.getD()));

            // 2. 重派生数据密钥。
            byte[] demKey = sm2Kdf(Sm2BcUtil.encodePointWithoutPrefix(shared), KEY_SIZE_BYTES);

            // 3. SM4-GCM 解密（AAD = contextInfo）。
            int nonceOffset = C1_SIZE;
            Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", BC_PROVIDER);
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(demKey, "SM4"),
                    new GCMParameterSpec(8 * 16, ciphertext, nonceOffset, NONCE_SIZE));
            if (contextInfo != null && contextInfo.length != 0) {
                cipher.updateAAD(contextInfo);
            }
            byte[] plaintext = cipher.doFinal(
                    ciphertext, nonceOffset + NONCE_SIZE,
                    ciphertext.length - nonceOffset - NONCE_SIZE);
            return Arrays.copyOf(plaintext, plaintext.length);
        } catch (GeneralSecurityException e) {
            throw new GeneralSecurityException("Decryption failed", e);
        } catch (RuntimeException e) {
            // 坏 C1 点、长度错误等运行时异常统一报错。
            throw new GeneralSecurityException("Decryption failed", e);
        }
    }

    /**
     * SM2-KDF（GB/T 32918.4-2016 第 5.4.3 节）：以 SM3 为哈希、4 字节大端计数器循环生成足够比特流后截断。
     *
     * @param z               KDF 输入（本方案中为 64 字节 x2 ‖ y2）
     * @param outputSizeBytes 期望输出长度（字节）
     */
    private static byte[] sm2Kdf(byte[] z, int outputSizeBytes) {
        if (z == null || z.length == 0) {
            throw new IllegalArgumentException("KDF input must not be empty");
        }
        SM3Digest digest = new SM3Digest();
        int blockCount = (outputSizeBytes + 31) / 32;
        byte[] output = new byte[blockCount * 32];
        byte[] block = new byte[32];
        for (int i = 1; i <= blockCount; i++) {
            digest.reset();
            digest.update(z, 0, z.length);
            digest.update((byte) (i >>> 24));
            digest.update((byte) (i >>> 16));
            digest.update((byte) (i >>> 8));
            digest.update((byte) i);
            digest.doFinal(block, 0);
            System.arraycopy(block, 0, output, (i - 1) * 32, 32);
        }
        Arrays.fill(block, (byte) 0);
        return outputSizeBytes == output.length
                ? output
                : Arrays.copyOf(output, outputSizeBytes);
    }
}
