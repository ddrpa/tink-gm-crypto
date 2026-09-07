package cc.ddrpa.crypto.tink.sm2.internal;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * SM2 密钥材质的工具类：大整数与定长字节串互转、密钥对生成、SM2 私钥/公钥参数对象的构造与校验。
 *
 * <p>密钥材质在密钥对象与 proto 中一律使用定长大端无符号字节串表示（坐标 32 字节、私钥标量
 * 32 字节），与国标及常见国密实现（GmSSL/OpenSSL/Bouncy Castle）的表示方式一致。
 */
public final class Sm2KeyUtil {

    private Sm2KeyUtil() {
    }

    /**
     * @return 用于随机数生成（密钥生成、签名随机数 k、加密临时密钥）的 {@link SecureRandom}。
     *
     * <p>{@link SecureRandom} 是线程安全的，此处共享单例以降低反复创建的系统开销。
     */
    public static SecureRandom getSecureRandom() {
        return SecureRandomHolder.INSTANCE;
    }

    private static final class SecureRandomHolder {
        private static final SecureRandom INSTANCE = new SecureRandom();
    }

    /**
     * 将非负 {@link BigInteger} 编码为指定长度的定长大端字节串。
     *
     * @throws GeneralSecurityException 值为负或超过 {@code length} 字节
     */
    public static byte[] toFixedLengthBytes(BigInteger value, int length)
        throws GeneralSecurityException {
        if (value == null || value.signum() < 0) {
            throw new GeneralSecurityException("Value must be a non-negative integer");
        }
        byte[] bigEndian = value.toByteArray();
        if (bigEndian.length == length + 1 && bigEndian[0] == 0) {
            // toByteArray 可能带一个前导 0 符号位字节。
            byte[] trimmed = new byte[length];
            System.arraycopy(bigEndian, 1, trimmed, 0, length);
            return trimmed;
        }
        if (bigEndian.length > length) {
            throw new GeneralSecurityException(
                "Integer does not fit into " + length + " bytes");
        }
        byte[] result = new byte[length];
        System.arraycopy(bigEndian, 0, result, length - bigEndian.length, bigEndian.length);
        return result;
    }

    /**
     * 生成一个新的 SM2 密钥对。
     *
     * <p>私钥标量 d 由 {@link SecureRandom} 在 [1, n-1) 内均匀取样（Bouncy Castle 保证），公钥点
     * Q = d·G。密钥对参数已由生成器保证有效。
     */
    public static AsymmetricCipherKeyPair generateKeyPair() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(
            new ECKeyGenerationParameters(Sm2Curve.getDomainParameters(), getSecureRandom()));
        return generator.generateKeyPair();
    }

    /** @return 从密钥对中取出 SM2 公钥参数对象。 */
    public static ECPublicKeyParameters getPublicKey(AsymmetricCipherKeyPair keyPair) {
        return (ECPublicKeyParameters) keyPair.getPublic();
    }

    /** @return 从密钥对中取出 SM2 私钥参数对象。 */
    public static ECPrivateKeyParameters getPrivateKey(AsymmetricCipherKeyPair keyPair) {
        return (ECPrivateKeyParameters) keyPair.getPrivate();
    }

    /**
     * 校验 SM2 私钥标量并返回其 {@link BigInteger} 表示。
     *
     * @param d 32 字节大端无符号私钥标量
     * @throws GeneralSecurityException 字节长度不正确或标量不在 [1, n-1] 内
     */
    public static BigInteger validatePrivateScalar(byte[] d) throws GeneralSecurityException {
        if (d == null || d.length != Sm2Curve.COORDINATE_SIZE_BYTES) {
            throw new GeneralSecurityException(
                "SM2 private key must be exactly " + Sm2Curve.COORDINATE_SIZE_BYTES + " bytes");
        }
        BigInteger value = new BigInteger(1, d);
        if (value.signum() == 0 || value.compareTo(Sm2Curve.getDomainParameters().getN()) >= 0) {
            throw new GeneralSecurityException("SM2 private key scalar is out of range");
        }
        return value;
    }

    /**
     * 从 32 字节私钥标量构造 BC 私钥参数对象（已校验）。
     */
    public static ECPrivateKeyParameters toPrivateKeyParameters(byte[] d)
        throws GeneralSecurityException {
        BigInteger scalar = validatePrivateScalar(d);
        return new ECPrivateKeyParameters(scalar, Sm2Curve.getDomainParameters());
    }

    /**
     * 从 32 字节私钥标量构造 BC 私钥参数对象（已校验）。
     */
    public static ECPrivateKeyParameters toPrivateKeyParameters(BigInteger d)
        throws GeneralSecurityException {
        validatePrivateScalar(toFixedLengthBytes(d, Sm2Curve.COORDINATE_SIZE_BYTES));
        return new ECPrivateKeyParameters(d, Sm2Curve.getDomainParameters());
    }

    /**
     * 从 64 字节公钥（X || Y）构造 BC 公钥参数对象（点有效性已校验）。
     */
    public static ECPublicKeyParameters toPublicKeyParameters(byte[] publicKey)
        throws GeneralSecurityException {
        ECPoint point = decodePublicPoint(publicKey);
        return new ECPublicKeyParameters(point, Sm2Curve.getDomainParameters());
    }

    /** @return 64 字节（X || Y）公钥解码后的校验点。 */
    public static ECPoint decodePublicPoint(byte[] publicKey) throws GeneralSecurityException {
        if (publicKey == null || publicKey.length != 2 * Sm2Curve.COORDINATE_SIZE_BYTES) {
            throw new GeneralSecurityException(
                "SM2 public key must be exactly "
                    + (2 * Sm2Curve.COORDINATE_SIZE_BYTES)
                    + " bytes (X || Y)");
        }
        byte[] x = new byte[Sm2Curve.COORDINATE_SIZE_BYTES];
        byte[] y = new byte[Sm2Curve.COORDINATE_SIZE_BYTES];
        System.arraycopy(
            publicKey, 0, x, 0, Sm2Curve.COORDINATE_SIZE_BYTES);
        System.arraycopy(
            publicKey, Sm2Curve.COORDINATE_SIZE_BYTES, y, 0, Sm2Curve.COORDINATE_SIZE_BYTES);
        return Sm2Curve.decodePoint(x, y);
    }

    /**
     * 计算共享点（用于 SM2 加密/解密与密钥交换）：{@code scalar * point} 并返回规范化结果。
     *
     * @throws GeneralSecurityException 乘算结果为零点（无穷远点）等无效情况
     */
    public static ECPoint multiply(ECPoint point, BigInteger scalar)
        throws GeneralSecurityException {
        Sm2Curve.validatePublicPoint(point);
        BigInteger n = Sm2Curve.getDomainParameters().getN();
        if (scalar == null || scalar.signum() <= 0 || scalar.compareTo(n) >= 0) {
            throw new GeneralSecurityException("Scalar is out of range");
        }
        ECPoint result = point.multiply(scalar).normalize();
        if (result.isInfinity()) {
            throw new GeneralSecurityException("Shared point is the point at infinity");
        }
        return result;
    }
}
