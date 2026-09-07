package cc.ddrpa.crypto.tink.sm2.internal;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * SM2 椭圆曲线（sm2p256v1）域参数与点的编解码工具。
 *
 * <p>国密 SM2 固定使用一条 256 位素域曲线，其域参数见 GB/T 32918.5-2017。本类集中提供曲线域参数
 * 与点相关的无状态操作，供签名与加密各子模块复用。所有公开方法均不依赖任何全局可变状态。
 */
public final class Sm2Curve {

    /** Bouncy Castle 中 SM2 曲线的注册名。 */
    public static final String CURVE_NAME = "sm2p256v1";

    /** 坐标宽度：32 字节（256 位）。 */
    public static final int COORDINATE_SIZE_BYTES = 32;

    /** 非压缩点编码长度：0x04 || X || Y，共 65 字节。 */
    public static final int UNCOMPRESSED_POINT_SIZE = 1 + 2 * COORDINATE_SIZE_BYTES;

    private static final X9ECParameters X9_PARAMETERS;
    private static final ECDomainParameters DOMAIN_PARAMETERS;

    static {
        X9ECParameters x9 = GMNamedCurves.getByName(CURVE_NAME);
        if (x9 == null) {
            throw new ExceptionInInitializerError(
                "Bouncy Castle does not provide SM2 curve '" + CURVE_NAME + "'");
        }
        X9_PARAMETERS = x9;
        BigInteger h = x9.getH();
        DOMAIN_PARAMETERS =
            new ECDomainParameters(
                x9.getCurve(),
                x9.getG(),
                x9.getN(),
                h == null ? BigInteger.ONE : h);
    }

    private Sm2Curve() {
    }

    /** @return SM2 曲线的域参数（含曲线、基点 G、阶 n 与余因子 h）。 */
    public static ECDomainParameters getDomainParameters() {
        return DOMAIN_PARAMETERS;
    }

    /** @return SM2 曲线的 {@link ECCurve} 对象。 */
    public static ECCurve getCurve() {
        return DOMAIN_PARAMETERS.getCurve();
    }

    /**
     * 校验一个点是否可作为 SM2 公钥使用：非无穷远点、位于曲线上。
     *
     * <p>SM2 曲线的阶为素数且余因子为 1，因此曲线上任意非无穷远点均落在素数阶子群内，无需再
     * 校验点的阶。
     *
     * @return 规范化后的同一点，便于后续取仿射坐标
     * @throws GeneralSecurityException 若点无效
     */
    public static ECPoint validatePublicPoint(ECPoint point) throws GeneralSecurityException {
        if (point == null) {
            throw new GeneralSecurityException("Public point must not be null");
        }
        if (point.isInfinity()) {
            throw new GeneralSecurityException("Public point must not be the point at infinity");
        }
        try {
            DOMAIN_PARAMETERS.validatePublicPoint(point);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Public point is not on the SM2 curve", e);
        }
        return point.normalize();
    }

    /**
     * 从 32 字节大端坐标构造并校验一个公钥点。
     *
     * @param x 32 字节大端无符号坐标 X
     * @param y 32 字节大端无符号坐标 Y
     */
    public static ECPoint decodePoint(byte[] x, byte[] y) throws GeneralSecurityException {
        if (x == null || x.length != COORDINATE_SIZE_BYTES) {
            throw new GeneralSecurityException(
                "Public key X coordinate must be exactly " + COORDINATE_SIZE_BYTES + " bytes");
        }
        if (y == null || y.length != COORDINATE_SIZE_BYTES) {
            throw new GeneralSecurityException(
                "Public key Y coordinate must be exactly " + COORDINATE_SIZE_BYTES + " bytes");
        }
        BigInteger xValue = new BigInteger(1, x);
        BigInteger yValue = new BigInteger(1, y);
        ECPoint point;
        try {
            // validatePoint 在点不在曲线上时抛出 IllegalArgumentException。
            point = getCurve().validatePoint(xValue, yValue);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Public key point is not on the SM2 curve", e);
        }
        return validatePublicPoint(point);
    }

    /**
     * 从非压缩点编码（{@code 0x04 || X || Y}，65 字节）构造并校验一个公钥点。
     */
    public static ECPoint decodePoint(byte[] encoded) throws GeneralSecurityException {
        if (encoded == null || encoded.length != UNCOMPRESSED_POINT_SIZE) {
            throw new GeneralSecurityException(
                "Encoded SM2 public point must be exactly "
                    + UNCOMPRESSED_POINT_SIZE
                    + " bytes (0x04 || X || Y)");
        }
        if (encoded[0] != 0x04) {
            throw new GeneralSecurityException(
                "Only uncompressed SM2 public points (0x04 prefix) are supported");
        }
        byte[] x = new byte[COORDINATE_SIZE_BYTES];
        byte[] y = new byte[COORDINATE_SIZE_BYTES];
        System.arraycopy(encoded, 1, x, 0, COORDINATE_SIZE_BYTES);
        System.arraycopy(encoded, 1 + COORDINATE_SIZE_BYTES, y, 0, COORDINATE_SIZE_BYTES);
        return decodePoint(x, y);
    }

    /** @return 将校验过的点编码为 65 字节非压缩形式（{@code 0x04 || X || Y}）。 */
    public static byte[] encodePoint(ECPoint point) throws GeneralSecurityException {
        ECPoint normalized = validatePublicPoint(point);
        byte[] encoded = new byte[UNCOMPRESSED_POINT_SIZE];
        encoded[0] = 0x04;
        copyToFixedLength(
            normalized.getAffineXCoord().toBigInteger(), encoded, 1, COORDINATE_SIZE_BYTES);
        copyToFixedLength(
            normalized.getAffineYCoord().toBigInteger(), encoded, 1 + COORDINATE_SIZE_BYTES,
            COORDINATE_SIZE_BYTES);
        return encoded;
    }

    /** @return 将校验过的点编码为 64 字节（X || Y，不带 0x04 前缀）。 */
    public static byte[] encodePointWithoutPrefix(ECPoint point) throws GeneralSecurityException {
        ECPoint normalized = validatePublicPoint(point);
        byte[] encoded = new byte[2 * COORDINATE_SIZE_BYTES];
        copyToFixedLength(
            normalized.getAffineXCoord().toBigInteger(), encoded, 0, COORDINATE_SIZE_BYTES);
        copyToFixedLength(
            normalized.getAffineYCoord().toBigInteger(), encoded, COORDINATE_SIZE_BYTES,
            COORDINATE_SIZE_BYTES);
        return encoded;
    }

    private static void copyToFixedLength(BigInteger value, byte[] dest, int offset, int length)
        throws GeneralSecurityException {
        byte[] bytes = Sm2KeyUtil.toFixedLengthBytes(value, length);
        System.arraycopy(bytes, 0, dest, offset, length);
    }
}
