package cc.ddrpa.interop.bc;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 对方侧（不使用 Google Tink）的 SM4-GCM AEAD 参考实现（仅 BouncyCastle + JDK）。
 *
 * <p>与 {@code tink-gm-crypto} 中 {@code SM4_GCM_RAW}（NO_PREFIX 变体）输出完全一致的线格式：
 *
 * <pre>
 *   密文 = IV(12) ‖ SM4-GCM 密文 ‖ tag(16)
 * </pre>
 *
 * 其中 SM4 密钥为 16 字节（128 位）、IV 为 12 字节（96 位）、tag 为 16 字节（128 位），与 GB/T 32907
 * 定义的 SM4 分组算法配合 GCM 工作模式的标准用法一致；关联数据（AAD）由 GCM 认证，{@code null} 与
 * 空数组等价。这也是 OpenSSL/GmSSL 等实现使用 SM4-GCM 时默认的布局。
 *
 * <p>注意：Java 平台没有内置的 SM4-GCM 提供者，必须显式使用 BouncyCastle 提供者（本类通过
 * {@code Cipher.getInstance("SM4/GCM/NoPadding", provider)} 指定，不要求调用方全局注册）。
 */
public final class Sm4GcmAead {

    private Sm4GcmAead() {
    }

    /** SM4 密钥长度：16 字节（128 位）。 */
    public static final int KEY_SIZE_BYTES = 16;
    /** IV 长度：12 字节（96 位）。 */
    public static final int IV_SIZE_BYTES = 12;
    /** GCM tag 长度：16 字节（128 位）。 */
    public static final int TAG_SIZE_BYTES = 16;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

    private static Cipher newCipher() throws GeneralSecurityException {
        return Cipher.getInstance("SM4/GCM/NoPadding", BC_PROVIDER);
    }

    private static void checkKey(byte[] key) throws GeneralSecurityException {
        if (key == null || key.length != KEY_SIZE_BYTES) {
            throw new GeneralSecurityException(
                "SM4 key must be exactly " + KEY_SIZE_BYTES + " bytes");
        }
    }

    /**
     * 加密：随机生成 12 字节 IV，输出 {@code IV ‖ 密文 ‖ tag}。
     *
     * @param key            16 字节 SM4 密钥
     * @param plaintext      待加密明文（可为空数组，不可为 null）
     * @param associatedData 关联数据（可为 null/空，作为 GCM AAD 认证）
     */
    public static byte[] encrypt(byte[] key, byte[] plaintext, byte[] associatedData)
        throws GeneralSecurityException {
        checkKey(key);
        if (plaintext == null) {
            throw new NullPointerException("plaintext is null");
        }
        byte[] iv = new byte[IV_SIZE_BYTES];
        RANDOM.nextBytes(iv);
        return encryptWithIv(key, iv, plaintext, associatedData);
    }

    /**
     * 加密：使用调用方指定的 IV（便于测试与演示固定 IV 下的线格式，生产请使用随机 IV）。
     *
     * @param iv 必须恰为 12 字节
     */
    public static byte[] encryptWithIv(
        byte[] key, byte[] iv, byte[] plaintext, byte[] associatedData)
        throws GeneralSecurityException {
        checkKey(key);
        if (iv == null || iv.length != IV_SIZE_BYTES) {
            throw new GeneralSecurityException(
                "IV must be exactly " + IV_SIZE_BYTES + " bytes");
        }
        if (plaintext == null) {
            throw new NullPointerException("plaintext is null");
        }
        Cipher cipher = newCipher();
        cipher.init(
            Cipher.ENCRYPT_MODE,
            new SecretKeySpec(key, "SM4"),
            new GCMParameterSpec(8 * TAG_SIZE_BYTES, iv));
        if (associatedData != null && associatedData.length != 0) {
            cipher.updateAAD(associatedData);
        }
        byte[] body = cipher.doFinal(plaintext);
        byte[] output = new byte[IV_SIZE_BYTES + body.length];
        System.arraycopy(iv, 0, output, 0, IV_SIZE_BYTES);
        System.arraycopy(body, 0, output, IV_SIZE_BYTES, body.length);
        return output;
    }

    /**
     * 解密 {@code IV ‖ 密文 ‖ tag} 并校验认证标签。
     *
     * @return 明文；tag 校验失败、长度非法等均抛出 {@link GeneralSecurityException}（建议调用方
     *     对解密失败统一返回错误，避免向调用者区分失败原因）
     */
    public static byte[] decrypt(byte[] key, byte[] ciphertext, byte[] associatedData)
        throws GeneralSecurityException {
        checkKey(key);
        if (ciphertext == null) {
            throw new NullPointerException("ciphertext is null");
        }
        if (ciphertext.length < IV_SIZE_BYTES + TAG_SIZE_BYTES) {
            throw new GeneralSecurityException("ciphertext too short");
        }
        Cipher cipher = newCipher();
        cipher.init(
            Cipher.DECRYPT_MODE,
            new SecretKeySpec(key, "SM4"),
            new GCMParameterSpec(
                8 * TAG_SIZE_BYTES, ciphertext, 0, IV_SIZE_BYTES));
        if (associatedData != null && associatedData.length != 0) {
            cipher.updateAAD(associatedData);
        }
        byte[] plaintext = cipher.doFinal(
            ciphertext, IV_SIZE_BYTES, ciphertext.length - IV_SIZE_BYTES);
        // 防意外共享内部数组：BC 解密结果可能复用输入缓冲，返回副本更稳妥。
        return Arrays.copyOf(plaintext, plaintext.length);
    }
}
