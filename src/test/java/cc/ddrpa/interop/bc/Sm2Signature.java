package cc.ddrpa.interop.bc;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.SM2Signer;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * 对方侧（不使用 Google Tink）的 SM2 数字签名参考实现（仅 BouncyCastle + JDK）。
 *
 * <p>与 {@code tink-gm-crypto} 中 {@code SM2_SIGN_RAW}（NO_PREFIX 变体）输出完全一致：
 *
 * <ul>
 *   <li>曲线 sm2p256v1（GB/T 32918.5），签名算法见 GB/T 32918.2-2016；</li>
 *   <li>用户标识 IDA 固定为默认值 {@code "1234567812345678"}（ASCII）；</li>
 *   <li>对<strong>原始消息字节</strong>签名：SM2 内部先以 SM3 计算 ZA = SM3(ENTLA ‖ IDA ‖ a ‖ b ‖ Gx ‖ Gy ‖ Qx ‖ Qy)，
 *       再对 ZA ‖ M 计算摘要，调用方无需（也不应）预先做任何哈希；</li>
 *   <li>签名值是定长 64 字节的 {@code r ‖ s}（各 32 字节大端），<strong>不是</strong> DER/ASN.1 包装。</li>
 * </ul>
 *
 * <p>如对方实现输出 DER 编码（部分库默认如此），需先转成 {@code r ‖ s} 再校验。
 */
public final class Sm2Signature {

    /**
     * 签名长度：r ‖ s 各 32 字节。
     */
    public static final int SIGNATURE_SIZE_BYTES = 64;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Sm2Signature() {
    }

    /**
     * 对原始消息生成 64 字节 {@code r ‖ s} 签名。
     *
     * @param d       32 字节私钥标量
     * @param message 原始消息（可为空数组）
     */
    public static byte[] sign(byte[] d, byte[] message) throws GeneralSecurityException {
        if (message == null) {
            throw new NullPointerException("message is null");
        }
        ECPrivateKeyParameters privateKey = Sm2BcUtil.privateKeyFromD(d);
        SM2Signer signer = new SM2Signer(new PlainDSAEncoding(), new SM3Digest());
        signer.init(
                true,
                new ParametersWithID(
                        new ParametersWithRandom(privateKey, RANDOM), Sm2BcUtil.DEFAULT_USER_ID));
        signer.update(message, 0, message.length);
        try {
            byte[] signature = signer.generateSignature();
            if (signature.length != SIGNATURE_SIZE_BYTES) {
                throw new GeneralSecurityException(
                        "Unexpected signature length: " + signature.length);
            }
            return signature;
        } catch (CryptoException e) {
            throw new GeneralSecurityException("SM2 signing failed", e);
        }
    }

    /**
     * 校验 64 字节 {@code r ‖ s} 签名。
     *
     * @param q         64 字节公钥（X ‖ Y）
     * @param signature 64 字节签名
     * @param message   被签名的原始消息
     * @return true 表示签名有效
     * @throws IllegalArgumentException 公钥/签名长度非法时抛出
     */
    public static boolean verify(byte[] q, byte[] signature, byte[] message) {
        if (message == null || signature == null) {
            throw new NullPointerException("message/signature is null");
        }
        if (signature.length != SIGNATURE_SIZE_BYTES) {
            throw new IllegalArgumentException(
                    "SM2 signature must be exactly " + SIGNATURE_SIZE_BYTES + " bytes (r || s)");
        }
        ECPublicKeyParameters publicKey = Sm2BcUtil.publicKeyFromXY(q);
        SM2Signer signer = new SM2Signer(new PlainDSAEncoding(), new SM3Digest());
        signer.init(false, new ParametersWithID(publicKey, Sm2BcUtil.DEFAULT_USER_ID));
        signer.update(message, 0, message.length);
        return signer.verifySignature(signature);
    }
}
