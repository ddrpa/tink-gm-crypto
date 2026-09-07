package cc.ddrpa.crypto.tink.hybrid.internal;

import cc.ddrpa.crypto.tink.hybrid.Sm2EncryptionPrivateKey;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2Curve;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.errorprone.annotations.Immutable;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

import java.security.GeneralSecurityException;

import static com.google.crypto.tink.internal.Util.isPrefix;

/**
 * SM2 (F1) decryption with Bouncy Castle.
 *
 * <p>Expects a standard SM2 ciphertext body ({@code C1 || C3 || C2}, see
 * {@link Sm2EncryptionHybridEncrypt}) that may be prefixed with the Tink output prefix, which is
 * validated and stripped here. Standard SM2 ciphertexts do not support associated data; hence
 * {@code contextInfo} must be null or empty.
 *
 * <p>All decryption failures (bad prefix, wrong length, malformed C1, C3 mismatch, ...) are
 * reported as a {@link GeneralSecurityException} with the single uniform message "Decryption
 * failed", so that callers cannot distinguish error kinds.
 */
@Immutable
public final class Sm2EncryptionHybridDecrypt implements HybridDecrypt {

    /**
     * Length of the C1 part: {@code 0x04 || X || Y}, see {@link Sm2Curve#UNCOMPRESSED_POINT_SIZE}.
     */
    private static final int C1_SIZE = Sm2Curve.UNCOMPRESSED_POINT_SIZE;

    /**
     * Length of the C3 part: the 32 byte SM3 digest.
     */
    private static final int C3_SIZE = 32;

    /**
     * Minimal ciphertext body length: C1 + C3 + at least one byte of C2.
     */
    private static final int MIN_BODY_SIZE = C1_SIZE + C3_SIZE + 1;

    @SuppressWarnings("Immutable")
    private final ECPrivateKeyParameters privateKeyParams;
    @SuppressWarnings("Immutable")
    private final byte[] outputPrefix;

    private Sm2EncryptionHybridDecrypt(
            ECPrivateKeyParameters privateKeyParams, byte[] outputPrefix) {
        this.privateKeyParams = privateKeyParams;
        this.outputPrefix = outputPrefix;
    }

    /**
     * Creates a new {@link HybridDecrypt} from the given key.
     */
    @AccessesPartialKey
    public static HybridDecrypt create(Sm2EncryptionPrivateKey key)
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
        return new Sm2EncryptionHybridDecrypt(privateKeyParams, outputPrefix);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] contextInfo)
            throws GeneralSecurityException {
        if (ciphertext == null) {
            throw new NullPointerException("ciphertext is null");
        }
        if (contextInfo != null && contextInfo.length != 0) {
            throw new GeneralSecurityException(
                    "Standard SM2 ciphertext does not support associated data "
                            + "(contextInfo must be empty)");
        }
        if (ciphertext.length < outputPrefix.length + MIN_BODY_SIZE) {
            throw new GeneralSecurityException("Decryption failed");
        }
        if (!isPrefix(outputPrefix, ciphertext)) {
            throw new GeneralSecurityException("Decryption failed");
        }
        SM2Engine engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
        try {
            engine.init(false, privateKeyParams);
            return engine.processBlock(
                    ciphertext, outputPrefix.length, ciphertext.length - outputPrefix.length);
        } catch (InvalidCipherTextException e) {
            throw new GeneralSecurityException("Decryption failed", e);
        } catch (RuntimeException e) {
            // DataLengthException, IllegalArgumentException (e.g. malformed C1 point) and any
            // other runtime failure are all reported identically.
            throw new GeneralSecurityException("Decryption failed", e);
        }
    }
}
