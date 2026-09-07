package cc.ddrpa.crypto.tink.sm2.internal;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link Sm2Curve} and {@link Sm2KeyUtil}.
 */
class Sm2KeyUtilTest {

    @Test
    void sm2DomainParameters_areSane() throws Exception {
        ECDomainParameters domain = Sm2Curve.getDomainParameters();
        assertEquals(256, domain.getCurve().getFieldSize());
        assertEquals(BigInteger.ONE, domain.getH());
        assertEquals(256, domain.getN().bitLength());
        assertTrue(domain.getN().isProbablePrime(128), "order n should be prime");
        // 基点 G 有效且阶为 n。
        ECPoint g = domain.getG();
        Sm2Curve.validatePublicPoint(g);
        assertTrue(g.multiply(domain.getN()).isInfinity(), "n * G should be the point at infinity");
        assertTrue(Sm2Curve.validatePublicPoint(g).normalize().isNormalized());
    }

    @Test
    void generateKeyPair_publicPointEqualsScalarTimesBasePoint() throws Exception {
        AsymmetricCipherKeyPair keyPair = Sm2KeyUtil.generateKeyPair();
        BigInteger d = Sm2KeyUtil.getPrivateKey(keyPair).getD();
        ECPoint publicPoint = Sm2KeyUtil.getPublicKey(keyPair).getQ();

        Sm2Curve.validatePublicPoint(publicPoint);
        assertTrue(d.signum() > 0 && d.compareTo(Sm2Curve.getDomainParameters().getN()) < 0);

        ECPoint expected = Sm2Curve.getDomainParameters().getG().multiply(d).normalize();
        assertEquals(
                expected.getAffineXCoord().toBigInteger(),
                publicPoint.normalize().getAffineXCoord().toBigInteger());
        assertEquals(
                expected.getAffineYCoord().toBigInteger(),
                publicPoint.normalize().getAffineYCoord().toBigInteger());
    }

    @Test
    void generateKeyPair_producesDistinctKeys() {
        ECPoint first = Sm2KeyUtil.getPublicKey(Sm2KeyUtil.generateKeyPair()).getQ().normalize();
        ECPoint second = Sm2KeyUtil.getPublicKey(Sm2KeyUtil.generateKeyPair()).getQ().normalize();
        // 连续两次生成的密钥对几乎不可能相同。
        assertFalse(first.equals(second));
    }

    @Test
    void encodeDecodePublicKey_roundTrips() throws Exception {
        AsymmetricCipherKeyPair keyPair = Sm2KeyUtil.generateKeyPair();
        ECPoint publicPoint = Sm2KeyUtil.getPublicKey(keyPair).getQ();

        byte[] encoded = Sm2Curve.encodePointWithoutPrefix(publicPoint);
        assertEquals(2 * Sm2Curve.COORDINATE_SIZE_BYTES, encoded.length);
        ECPoint decoded = Sm2KeyUtil.decodePublicPoint(encoded);
        assertEquals(
                publicPoint.normalize().getAffineXCoord().toBigInteger(),
                decoded.getAffineXCoord().toBigInteger());
        assertEquals(
                publicPoint.normalize().getAffineYCoord().toBigInteger(),
                decoded.getAffineYCoord().toBigInteger());

        byte[] uncompressed = Sm2Curve.encodePoint(publicPoint);
        assertEquals(Sm2Curve.UNCOMPRESSED_POINT_SIZE, uncompressed.length);
        assertEquals(0x04, uncompressed[0] & 0xFF);
        ECPoint decodedUncompressed = Sm2Curve.decodePoint(uncompressed);
        assertEquals(
                decoded.getAffineXCoord().toBigInteger(),
                decodedUncompressed.getAffineXCoord().toBigInteger());
    }

    @Test
    void decodePublicPoint_rejectsWrongLengthAndOffCurvePoints() throws Exception {
        byte[] valid = Sm2Curve.encodePointWithoutPrefix(
                Sm2KeyUtil.getPublicKey(Sm2KeyUtil.generateKeyPair()).getQ());
        assertThrows(GeneralSecurityException.class, () -> Sm2KeyUtil.decodePublicPoint(new byte[63]));
        assertThrows(
                GeneralSecurityException.class, () -> Sm2KeyUtil.decodePublicPoint(new byte[65]));

        // 将 Y 坐标加 1（超出曲线）应被拒绝；若加 1 后恰好仍在曲线上（概率极低），换为异或 1。
        byte[] offCurve = valid.clone();
        offCurve[Sm2Curve.COORDINATE_SIZE_BYTES] ^= 1;
        assertThrows(
                GeneralSecurityException.class, () -> Sm2KeyUtil.decodePublicPoint(offCurve));
    }

    @Test
    void validatePrivateScalar_rejectsInvalidValues() throws Exception {
        byte[] d = new byte[Sm2Curve.COORDINATE_SIZE_BYTES];
        // 全 0 -> 0。
        assertThrows(GeneralSecurityException.class, () -> Sm2KeyUtil.validatePrivateScalar(d));

        // d = n 越界。
        byte[] n = Sm2KeyUtil.toFixedLengthBytes(Sm2Curve.getDomainParameters().getN(),
                Sm2Curve.COORDINATE_SIZE_BYTES);
        assertThrows(GeneralSecurityException.class, () -> Sm2KeyUtil.validatePrivateScalar(n));

        // d = n - 1 合法。
        byte[] nMinusOne = Sm2KeyUtil.toFixedLengthBytes(
                Sm2Curve.getDomainParameters().getN().subtract(BigInteger.ONE),
                Sm2Curve.COORDINATE_SIZE_BYTES);
        assertEquals(
                Sm2Curve.getDomainParameters().getN().subtract(BigInteger.ONE),
                Sm2KeyUtil.validatePrivateScalar(nMinusOne));

        // d = 1 合法。
        byte[] one = new byte[Sm2Curve.COORDINATE_SIZE_BYTES];
        one[Sm2Curve.COORDINATE_SIZE_BYTES - 1] = 1;
        assertEquals(BigInteger.ONE, Sm2KeyUtil.validatePrivateScalar(one));

        // 长度错误。
        assertThrows(
                GeneralSecurityException.class,
                () -> Sm2KeyUtil.validatePrivateScalar(new byte[31]));
        assertThrows(
                GeneralSecurityException.class,
                () -> Sm2KeyUtil.validatePrivateScalar(new byte[33]));
    }

    @Test
    void toFixedLengthBytes_validates() throws Exception {
        byte[] one = Sm2KeyUtil.toFixedLengthBytes(BigInteger.ONE, 32);
        assertEquals(32, one.length);
        assertEquals(0, one[31 - 1]);
        assertEquals(1, one[31]);

        byte[] max = Sm2KeyUtil.toFixedLengthBytes(BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE), 32);
        assertEquals(32, max.length);
        assertArrayEquals(new byte[]{(byte) 0xFF}, new byte[]{max[0]});

        assertThrows(
                GeneralSecurityException.class,
                () -> Sm2KeyUtil.toFixedLengthBytes(BigInteger.ONE.shiftLeft(256), 32));
        assertThrows(
                GeneralSecurityException.class,
                () -> Sm2KeyUtil.toFixedLengthBytes(BigInteger.valueOf(-1), 32));
    }

    @Test
    void privateKeyParameters_roundTrip() throws Exception {
        byte[] d = new byte[Sm2Curve.COORDINATE_SIZE_BYTES];
        d[Sm2Curve.COORDINATE_SIZE_BYTES - 1] = 42;
        ECPrivateKeyParameters params = Sm2KeyUtil.toPrivateKeyParameters(d);
        assertEquals(BigInteger.valueOf(42), params.getD());

        ECPublicKeyParameters pubParams = Sm2KeyUtil.toPublicKeyParameters(
                Sm2Curve.encodePointWithoutPrefix(
                        Sm2KeyUtil.getPublicKey(Sm2KeyUtil.generateKeyPair()).getQ()));
        Sm2Curve.validatePublicPoint(pubParams.getQ());
    }

    @Test
    void toPrivateKeyParameters_rejectsScalarOutOfRange() {
        byte[] zero = new byte[Sm2Curve.COORDINATE_SIZE_BYTES];
        assertThrows(GeneralSecurityException.class, () -> Sm2KeyUtil.toPrivateKeyParameters(zero));
    }
}
