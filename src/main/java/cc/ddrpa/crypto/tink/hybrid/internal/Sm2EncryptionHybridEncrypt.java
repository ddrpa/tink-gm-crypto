package cc.ddrpa.crypto.tink.hybrid.internal;

import cc.ddrpa.crypto.tink.hybrid.Sm2EncryptionPublicKey;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2Curve;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridEncrypt;
import com.google.errorprone.annotations.Immutable;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;

import java.security.GeneralSecurityException;

/**
 * SM2 (F1) encryption with Bouncy Castle.
 *
 * <p>The standard SM2 encryption algorithm (GB/T 32918.4) is applied to the whole plaintext. The
 * ciphertext layout is fixed to {@code C1 || C3 || C2}, where {@code C1} is the 65 byte
 * uncompressed encoding of the ephemeral public point ({@code 0x04 || X || Y}), {@code C3} the 32
 * byte SM3 digest and {@code C2} the ciphertext of the same length as the plaintext. Standard SM2
 * ciphertexts do not support associated data; hence {@code contextInfo} must be null or empty.
 *
 * <p>The Tink output prefix (if any) is prepended by this primitive, exactly like other AEAD-style
 * primitives in this repository.
 */
@Immutable
public final class Sm2EncryptionHybridEncrypt implements HybridEncrypt {

    /**
     * Length of the C1 part: {@code 0x04 || X || Y}, see {@link Sm2Curve#UNCOMPRESSED_POINT_SIZE}.
     */
    private static final int C1_SIZE = Sm2Curve.UNCOMPRESSED_POINT_SIZE;

    /**
     * Length of the C3 part: the 32 byte SM3 digest.
     */
    private static final int C3_SIZE = 32;

    @SuppressWarnings("Immutable")
    private final ECPublicKeyParameters publicKeyParams;
    @SuppressWarnings("Immutable")
    private final byte[] outputPrefix;

    private Sm2EncryptionHybridEncrypt(
            ECPublicKeyParameters publicKeyParams, byte[] outputPrefix) {
        this.publicKeyParams = publicKeyParams;
        this.outputPrefix = outputPrefix;
    }

    /**
     * Creates a new {@link HybridEncrypt} from the given key.
     */
    @AccessesPartialKey
    public static HybridEncrypt create(Sm2EncryptionPublicKey key)
            throws GeneralSecurityException {
        byte[] outputPrefix = key.getOutputPrefix().toByteArray();
        // Validates the point (length and on-curve) and converts it to Bouncy Castle parameters.
        ECPublicKeyParameters publicKeyParams =
                Sm2KeyUtil.toPublicKeyParameters(key.getPublicKey().toByteArray());
        return new Sm2EncryptionHybridEncrypt(publicKeyParams, outputPrefix);
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] contextInfo)
            throws GeneralSecurityException {
        if (plaintext == null) {
            throw new NullPointerException("plaintext is null");
        }
        if (contextInfo != null && contextInfo.length != 0) {
            throw new GeneralSecurityException(
                    "Standard SM2 ciphertext does not support associated data "
                            + "(contextInfo must be empty)");
        }
        if (plaintext.length == 0) {
            // The SM2Engine rejects zero-length inputs; reject here with a uniform error.
            throw new GeneralSecurityException("plaintext too short");
        }
        // The ciphertext body is 65 + 32 + plaintext.length bytes; guard against overflow before
        // allocating (compare with Sm4GcmJce.encrypt).
        if (plaintext.length > Integer.MAX_VALUE - outputPrefix.length - C1_SIZE - C3_SIZE) {
            throw new GeneralSecurityException("plaintext too long");
        }
        SM2Engine engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
        byte[] ciphertextBody;
        try {
            engine.init(
                    true,
                    new ParametersWithRandom(publicKeyParams, Sm2KeyUtil.getSecureRandom()));
            ciphertextBody = engine.processBlock(plaintext, 0, plaintext.length);
        } catch (InvalidCipherTextException e) {
            throw new GeneralSecurityException("Encryption failed", e);
        } catch (RuntimeException e) {
            throw new GeneralSecurityException("Encryption failed", e);
        }
        byte[] output = new byte[outputPrefix.length + ciphertextBody.length];
        System.arraycopy(outputPrefix, 0, output, 0, outputPrefix.length);
        System.arraycopy(
                ciphertextBody, 0, output, outputPrefix.length, ciphertextBody.length);
        return output;
    }
}
