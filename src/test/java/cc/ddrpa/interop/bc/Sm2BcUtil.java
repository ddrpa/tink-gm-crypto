package cc.ddrpa.interop.bc;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * 对方侧参考实现共用的 SM2 曲线（sm2p256v1）与密钥材质工具。
 *
 * <p>与 {@code tink-gm-crypto} 及国标一致：私钥标量 d 与坐标 X/Y 均为 32 字节定长大端无符号整数，
 * 公钥点编码支持 64 字节（X ‖ Y）与 65 字节非压缩（0x04 ‖ X ‖ Y）两种形式。
 */
public final class Sm2BcUtil {

    /**
     * Bouncy Castle 中 SM2 曲线的注册名。
     */
    public static final String CURVE_NAME = "sm2p256v1";
    /**
     * 坐标宽度：32 字节（256 位）。
     */
    public static final int COORDINATE_SIZE_BYTES = 32;
    /**
     * 非压缩点编码长度：0x04 ‖ X ‖ Y。
     */
    public static final int UNCOMPRESSED_POINT_SIZE = 65;

    /**
     * GB/T 32918.2 定义的默认用户标识（ASCII "1234567812345678"）。
     */
    public static final byte[] DEFAULT_USER_ID =
            "1234567812345678".getBytes(StandardCharsets.US_ASCII);

    private static final X9ECParameters X9 = GMNamedCurves.getByName(CURVE_NAME);
    private static final ECDomainParameters DOMAIN =
            new ECDomainParameters(X9.getCurve(), X9.getG(), X9.getN(), X9.getH());

    private Sm2BcUtil() {
    }

    /**
     * @return sm2p256v1 域参数
     */
    public static ECDomainParameters getDomainParameters() {
        return DOMAIN;
    }

    /**
     * @param d 32 字节大端私钥标量
     * @return 校验通过后的 BC 私钥参数对象
     * @throws IllegalArgumentException 长度非 32 或标量不在 [1, n-1] 内
     */
    public static ECPrivateKeyParameters privateKeyFromD(byte[] d) {
        if (d == null || d.length != COORDINATE_SIZE_BYTES) {
            throw new IllegalArgumentException(
                    "SM2 private key must be exactly " + COORDINATE_SIZE_BYTES + " bytes");
        }
        BigInteger scalar = new BigInteger(1, d);
        if (scalar.signum() == 0 || scalar.compareTo(DOMAIN.getN()) >= 0) {
            throw new IllegalArgumentException("SM2 private key scalar is out of range");
        }
        return new ECPrivateKeyParameters(scalar, DOMAIN);
    }

    /**
     * @param q 64 字节公钥（X ‖ Y）
     * @return 校验通过后的 BC 公钥参数对象
     */
    public static ECPublicKeyParameters publicKeyFromXY(byte[] q) {
        if (q == null || q.length != 2 * COORDINATE_SIZE_BYTES) {
            throw new IllegalArgumentException(
                    "SM2 public key must be exactly " + (2 * COORDINATE_SIZE_BYTES) + " bytes (X || Y)");
        }
        byte[] x = new byte[COORDINATE_SIZE_BYTES];
        byte[] y = new byte[COORDINATE_SIZE_BYTES];
        System.arraycopy(q, 0, x, 0, COORDINATE_SIZE_BYTES);
        System.arraycopy(q, COORDINATE_SIZE_BYTES, y, 0, COORDINATE_SIZE_BYTES);
        ECPoint point = validatePoint(decodePoint(x, y));
        return new ECPublicKeyParameters(point, DOMAIN);
    }

    /**
     * @return 将 65 字节非压缩点（0x04 ‖ X ‖ Y）解码为校验过的曲线点
     */
    public static ECPoint decodePoint(byte[] encoded) {
        if (encoded == null || encoded.length != UNCOMPRESSED_POINT_SIZE) {
            throw new IllegalArgumentException(
                    "Encoded SM2 public point must be exactly "
                            + UNCOMPRESSED_POINT_SIZE + " bytes (0x04 || X || Y)");
        }
        if (encoded[0] != 0x04) {
            throw new IllegalArgumentException(
                    "Only uncompressed SM2 public points (0x04 prefix) are supported");
        }
        byte[] x = new byte[COORDINATE_SIZE_BYTES];
        byte[] y = new byte[COORDINATE_SIZE_BYTES];
        System.arraycopy(encoded, 1, x, 0, COORDINATE_SIZE_BYTES);
        System.arraycopy(encoded, 1 + COORDINATE_SIZE_BYTES, y, 0, COORDINATE_SIZE_BYTES);
        return validatePoint(decodePoint(x, y));
    }

    /**
     * @return 将两个 32 字节坐标解码为曲线点（未校验）
     */
    public static ECPoint decodePoint(byte[] x, byte[] y) {
        if (x == null || x.length != COORDINATE_SIZE_BYTES
                || y == null || y.length != COORDINATE_SIZE_BYTES) {
            throw new IllegalArgumentException("SM2 coordinates must be 32 bytes each");
        }
        return DOMAIN.getCurve().createPoint(new BigInteger(1, x), new BigInteger(1, y));
    }

    /**
     * 校验点：非无穷远且位于曲线上，返回规范化后的点。
     */
    public static ECPoint validatePoint(ECPoint point) {
        if (point == null || point.isInfinity()) {
            throw new IllegalArgumentException("SM2 public point must not be the point at infinity");
        }
        if (!point.isValid()) {
            throw new IllegalArgumentException("Public point is not on the SM2 curve");
        }
        return point.normalize();
    }

    /**
     * @return 将校验过的点编码为 65 字节非压缩形式（0x04 ‖ X ‖ Y）
     */
    public static byte[] encodePoint(ECPoint point) {
        ECPoint p = validatePoint(point);
        byte[] out = new byte[UNCOMPRESSED_POINT_SIZE];
        out[0] = 0x04;
        copyFixed(p.getAffineXCoord().toBigInteger(), out, 1);
        copyFixed(p.getAffineYCoord().toBigInteger(), out, 1 + COORDINATE_SIZE_BYTES);
        return out;
    }

    /**
     * @return 将校验过的点编码为 64 字节（X ‖ Y）
     */
    public static byte[] encodePointWithoutPrefix(ECPoint point) {
        ECPoint p = validatePoint(point);
        byte[] out = new byte[2 * COORDINATE_SIZE_BYTES];
        copyFixed(p.getAffineXCoord().toBigInteger(), out, 0);
        copyFixed(p.getAffineYCoord().toBigInteger(), out, COORDINATE_SIZE_BYTES);
        return out;
    }

    private static void copyFixed(BigInteger value, byte[] dest, int offset) {
        byte[] bytes = toFixedLengthBytes(value, COORDINATE_SIZE_BYTES);
        System.arraycopy(bytes, 0, dest, offset, COORDINATE_SIZE_BYTES);
    }

    /**
     * 非负整数编码为 {@code length} 字节定长大端。
     */
    public static byte[] toFixedLengthBytes(BigInteger value, int length) {
        byte[] bigEndian = value.toByteArray();
        if (bigEndian.length == length + 1 && bigEndian[0] == 0) {
            byte[] trimmed = new byte[length];
            System.arraycopy(bigEndian, 1, trimmed, 0, length);
            return trimmed;
        }
        if (bigEndian.length > length) {
            throw new IllegalArgumentException("Integer does not fit into " + length + " bytes");
        }
        byte[] result = new byte[length];
        System.arraycopy(bigEndian, 0, result, length - bigEndian.length, bigEndian.length);
        return result;
    }
}
