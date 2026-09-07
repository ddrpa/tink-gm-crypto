package cc.ddrpa.interop.bc;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;

/**
 * 对方侧（不使用 Google Tink）的<strong>标准 SM2 公钥加密</strong>参考实现（仅 BouncyCastle + JDK）。
 *
 * <p>与 {@code tink-gm-crypto} 中 {@code SM2_ENCRYPTION_RAW}（NO_PREFIX 变体）输出一致，即
 * GB/T 32918.4-2016 的标准密文布局：
 *
 * <pre>
 *   密文 = C1(65) ‖ C3(32) ‖ C2(len(明文))
 * </pre>
 *
 * 其中 C1 是临时公钥点的 65 字节非压缩编码（0x04 ‖ X ‖ Y），C3 是 32 字节 SM3 摘要，C2 与明文等长。
 * 标准 SM2 没有关联数据槽位，因此调用方不得使用 AAD/contextInfo；明文必须非空（SM2 引擎不支持
 * 零长度输入）。
 *
 * <p>该格式与 BouncyCastle {@code SM2Engine(Mode.C1C3C2)}、OpenSSL/GmSSL 的默认 SM2 加密输出一致，
 * 可与主流国密实现直接互操作（注意部分实现默认输出 C1C2C3 或压缩点，需要显式配置为 C1C3C2 非压缩）。
 */
public final class Sm2StandardEncryption {

    private Sm2StandardEncryption() {
    }

    /** C1 长度：65 字节非压缩点。 */
    public static final int C1_SIZE = Sm2BcUtil.UNCOMPRESSED_POINT_SIZE;
    /** C3 长度：32 字节 SM3 摘要。 */
    public static final int C3_SIZE = 32;
    /** 密文体最小长度：C1 + C3 + 至少 1 字节 C2。 */
    public static final int MIN_CIPHERTEXT_SIZE = C1_SIZE + C3_SIZE + 1;

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * 使用接收方公钥加密。
     *
     * @param q 64 字节公钥（X ‖ Y）
     * @param plaintext 明文，必须非空
     * @return 标准 C1C3C2 密文（无前缀）
     */
    public static byte[] encrypt(byte[] q, byte[] plaintext) throws GeneralSecurityException {
        if (plaintext == null) {
            throw new NullPointerException("plaintext is null");
        }
        if (plaintext.length == 0) {
            throw new GeneralSecurityException("plaintext too short");
        }
        ECPublicKeyParameters publicKey = Sm2BcUtil.publicKeyFromXY(q);
        SM2Engine engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
        try {
            engine.init(true, new ParametersWithRandom(publicKey, RANDOM));
            return engine.processBlock(plaintext, 0, plaintext.length);
        } catch (InvalidCipherTextException | RuntimeException e) {
            throw new GeneralSecurityException("SM2 encryption failed", e);
        }
    }

    /**
     * 使用私钥解密标准 C1C3C2 密文。
     *
     * @param d 32 字节私钥标量
     * @param ciphertext C1C3C2 密文（不得带有任何前缀）
     * @return 明文
     * @throws GeneralSecurityException 长度非法、C1 不在曲线上、C3 校验失败等，统一抛此异常
     */
    public static byte[] decrypt(byte[] d, byte[] ciphertext) throws GeneralSecurityException {
        if (ciphertext == null) {
            throw new NullPointerException("ciphertext is null");
        }
        if (ciphertext.length < MIN_CIPHERTEXT_SIZE) {
            throw new GeneralSecurityException("Decryption failed");
        }
        ECPrivateKeyParameters privateKey = Sm2BcUtil.privateKeyFromD(d);
        SM2Engine engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
        try {
            engine.init(false, privateKey);
            return engine.processBlock(ciphertext, 0, ciphertext.length);
        } catch (InvalidCipherTextException | RuntimeException e) {
            // 所有失败（含错误 C3、坏 C1 点等）统一报错，避免向调用者泄露失败原因。
            throw new GeneralSecurityException("Decryption failed", e);
        }
    }
}
