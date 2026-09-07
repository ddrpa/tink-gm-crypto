package cc.ddrpa.crypto.tink.hybrid.internal;

import cc.ddrpa.crypto.tink.aead.internal.Sm4GcmJceUtil;
import cc.ddrpa.crypto.tink.hybrid.Sm2HybridPrivateKey;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2Curve;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2Kdf;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.errorprone.annotations.Immutable;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import static com.google.crypto.tink.internal.Util.isPrefix;

/**
 * SM2 hybrid decryption (F2, "SM2-KEM + SM4-GCM DEM") with Bouncy Castle and the JCE SM4-GCM
 * cipher.
 *
 * <p>Expects a ciphertext body of the form {@code C1 || nonce(12) || SM4-GCM ciphertext} (see
 * {@link Sm2HybridEncrypt}) that may be prefixed with the Tink output prefix, which is validated
 * and stripped here. The shared point {@code S = d * C1} is fed as {@code x2 || y2} into the
 * SM2-KDF to re-derive the SM4-GCM data key, and {@code contextInfo} must be exactly the same
 * bytes which were used for encryption, since it is authenticated as SM4-GCM associated data.
 *
 * <p>All decryption failures (bad prefix, wrong length, malformed or off-curve C1, SM4-GCM
 * authentication failure, wrong {@code contextInfo}, ...) are reported as a
 * {@link GeneralSecurityException} with the single uniform message "Decryption failed", so that
 * callers cannot distinguish error kinds.
 */
@Immutable
public final class Sm2HybridDecrypt implements HybridDecrypt {

    /**
     * Length of the C1 part: {@code 0x04 || X || Y}, see {@link Sm2Curve#UNCOMPRESSED_POINT_SIZE}.
     */
    private static final int C1_SIZE = Sm2Curve.UNCOMPRESSED_POINT_SIZE;

    /**
     * Length of the SM4-GCM nonce, see {@link Sm4GcmJceUtil#IV_SIZE_IN_BYTES}.
     */
    private static final int NONCE_SIZE = Sm4GcmJceUtil.IV_SIZE_IN_BYTES;

    /**
     * Size of the derived SM4 data key in bytes (128 bit).
     */
    private static final int KEY_SIZE_BYTES = 16;

    /**
     * Minimal ciphertext body length: C1 + nonce + SM4-GCM tag (empty plaintext).
     */
    private static final int MIN_BODY_SIZE =
            C1_SIZE + NONCE_SIZE + Sm4GcmJceUtil.TAG_SIZE_IN_BYTES;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @SuppressWarnings("Immutable")
    private final ECPrivateKeyParameters privateKeyParams;
    @SuppressWarnings("Immutable")
    private final byte[] outputPrefix;

    private Sm2HybridDecrypt(
            ECPrivateKeyParameters privateKeyParams, byte[] outputPrefix) {
        this.privateKeyParams = privateKeyParams;
        this.outputPrefix = outputPrefix;
    }

    /**
     * Creates a new {@link HybridDecrypt} from the given key.
     */
    @AccessesPartialKey
    public static HybridDecrypt create(Sm2HybridPrivateKey key)
            throws GeneralSecurityException {
        byte[] outputPrefix = key.getOutputPrefix().toByteArray();
        // Validates the private scalar (length and range) and converts it to Bouncy Castle
        // parameters.
        ECPrivateKeyParameters privateKeyParams =
                Sm2KeyUtil.toPrivateKeyParameters(
                        key.getPrivateValue().toByteArray(InsecureSecretKeyAccess.get()));
        // Validate the public key point early so that malformed keys fail fast when the primitive
        // is created instead of producing failures which are hard to attribute.
        Sm2KeyUtil.decodePublicPoint(key.getPublicKey().getPublicKey().toByteArray());
        return new Sm2HybridDecrypt(privateKeyParams, outputPrefix);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] contextInfo)
            throws GeneralSecurityException {
        if (ciphertext == null) {
            throw new NullPointerException("ciphertext is null");
        }
        if (ciphertext.length < outputPrefix.length + MIN_BODY_SIZE) {
            throw new GeneralSecurityException("Decryption failed");
        }
        if (!isPrefix(outputPrefix, ciphertext)) {
            throw new GeneralSecurityException("Decryption failed");
        }
        int bodyOffset = outputPrefix.length;
        try {
            // C1 is the first 65 bytes of the body; decodePoint validates that it is a valid
            // non-infinity point on the SM2 curve (any invalid C1 fails here uniformly).
            ECPoint c1Point =
                    Sm2Curve.decodePoint(
                            Arrays.copyOfRange(ciphertext, bodyOffset, bodyOffset + C1_SIZE));
            // Shared point S = d * C1; the DEM key is derived from the 64 byte x2 || y2 encoding
            // of S exactly as in SM2 key agreement.
            ECPoint sharedPoint = Sm2KeyUtil.multiply(c1Point, privateKeyParams.getD());
            byte[] sharedZ = Sm2Curve.encodePointWithoutPrefix(sharedPoint);
            byte[] demKey = Sm2Kdf.derive(sharedZ, KEY_SIZE_BYTES);

            SecretKey keySpec = Sm4GcmJceUtil.getSecretKey(demKey);
            int nonceOffset = bodyOffset + C1_SIZE;
            AlgorithmParameterSpec params =
                    Sm4GcmJceUtil.getParams(ciphertext, nonceOffset, NONCE_SIZE);
            Cipher cipher = Sm4GcmJceUtil.getThreadLocalCipher();
            cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
            if (contextInfo != null && contextInfo.length != 0) {
                cipher.updateAAD(contextInfo);
            }
            int offset = nonceOffset + NONCE_SIZE;
            int len = ciphertext.length - offset;
            return cipher.doFinal(ciphertext, offset, len);
        } catch (GeneralSecurityException e) {
            throw new GeneralSecurityException("Decryption failed", e);
        } catch (RuntimeException e) {
            // DataLengthException, IllegalArgumentException (e.g. malformed C1 point) and any
            // other runtime failure are all reported identically.
            throw new GeneralSecurityException("Decryption failed", e);
        }
    }
}
