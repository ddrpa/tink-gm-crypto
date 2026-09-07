package cc.ddrpa.crypto.tink.hybrid.internal;

import cc.ddrpa.crypto.tink.aead.internal.Sm4GcmJceUtil;
import cc.ddrpa.crypto.tink.hybrid.Sm2HybridPublicKey;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2Curve;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2Kdf;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridEncrypt;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

/**
 * SM2 hybrid encryption (F2, "SM2-KEM + SM4-GCM DEM") with Bouncy Castle and the JCE SM4-GCM
 * cipher.
 *
 * <p>Encryption runs a fresh ephemeral SM2 key agreement per call: {@code C1} is the 65 byte
 * uncompressed encoding ({@code 0x04 || X || Y}) of the ephemeral public point, and the shared
 * point {@code S = k * Q} (with {@code k} the ephemeral private scalar and {@code Q} the
 * recipient's public point) is fed as {@code x2 || y2} into the SM2-KDF (GB/T 32918.4) to derive
 * the 128 bit SM4-GCM data key. The body is {@code C1 || nonce(12) || SM4-GCM ciphertext}, where
 * the SM4-GCM tag authenticates {@code contextInfo} as associated data (any byte[] is accepted;
 * {@code null} is treated like the empty array).
 *
 * <p>The Tink output prefix (if any) is prepended by this primitive, exactly like other
 * prefix-capable primitives in this repository.
 */
@Immutable
public final class Sm2HybridEncrypt implements HybridEncrypt {

    /** Length of the C1 part: {@code 0x04 || X || Y}, see {@link Sm2Curve#UNCOMPRESSED_POINT_SIZE}. */
    private static final int C1_SIZE = Sm2Curve.UNCOMPRESSED_POINT_SIZE;

    /** Length of the SM4-GCM nonce, see {@link Sm4GcmJceUtil#IV_SIZE_IN_BYTES}. */
    private static final int NONCE_SIZE = Sm4GcmJceUtil.IV_SIZE_IN_BYTES;

    /** Size of the derived SM4 data key in bytes (128 bit). */
    private static final int KEY_SIZE_BYTES = 16;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @SuppressWarnings("Immutable")
    private final ECPublicKeyParameters publicKeyParams;
    @SuppressWarnings("Immutable")
    private final byte[] outputPrefix;

    private Sm2HybridEncrypt(
        ECPublicKeyParameters publicKeyParams, byte[] outputPrefix) {
        this.publicKeyParams = publicKeyParams;
        this.outputPrefix = outputPrefix;
    }

    /**
     * Creates a new {@link HybridEncrypt} from the given key.
     */
    @AccessesPartialKey
    public static HybridEncrypt create(Sm2HybridPublicKey key)
        throws GeneralSecurityException {
        byte[] outputPrefix = key.getOutputPrefix().toByteArray();
        // Validates the point (length and on-curve) and converts it to Bouncy Castle parameters.
        ECPublicKeyParameters publicKeyParams =
            Sm2KeyUtil.toPublicKeyParameters(key.getPublicKey().toByteArray());
        return new Sm2HybridEncrypt(publicKeyParams, outputPrefix);
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] contextInfo)
        throws GeneralSecurityException {
        if (plaintext == null) {
            throw new NullPointerException("plaintext is null");
        }
        // The ciphertext body is 65 + 12 + (plaintext.length + 16) bytes; guard against overflow
        // before allocating (compare with Sm4GcmJce.encrypt).
        if (plaintext.length > Integer.MAX_VALUE - outputPrefix.length - C1_SIZE - NONCE_SIZE
            - Sm4GcmJceUtil.TAG_SIZE_IN_BYTES) {
            throw new GeneralSecurityException("plaintext too long");
        }
        AsymmetricCipherKeyPair ephemeralKeyPair = Sm2KeyUtil.generateKeyPair();
        try {
            // C1 = ephemeral public point encoded as 0x04 || X || Y (65 bytes).
            byte[] c1 =
                Sm2Curve.encodePoint(Sm2KeyUtil.getPublicKey(ephemeralKeyPair).getQ());
            // Shared point S = k * Q, where k is the ephemeral private scalar; the DEM key is
            // derived from the 64 byte x2 || y2 encoding of S exactly as in SM2 key agreement.
            ECPoint recipientPoint = publicKeyParams.getQ();
            ECPoint sharedPoint =
                Sm2KeyUtil.multiply(recipientPoint, Sm2KeyUtil.getPrivateKey(ephemeralKeyPair).getD());
            byte[] sharedZ = Sm2Curve.encodePointWithoutPrefix(sharedPoint);
            byte[] demKey = Sm2Kdf.derive(sharedZ, KEY_SIZE_BYTES);

            byte[] nonce = new byte[NONCE_SIZE];
            Sm2KeyUtil.getSecureRandom().nextBytes(nonce);
            SecretKey keySpec = Sm4GcmJceUtil.getSecretKey(demKey);
            AlgorithmParameterSpec params = Sm4GcmJceUtil.getParams(nonce);
            Cipher cipher = Sm4GcmJceUtil.getThreadLocalCipher();
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);
            if (contextInfo != null && contextInfo.length != 0) {
                cipher.updateAAD(contextInfo);
            }
            int outputSize = cipher.getOutputSize(plaintext.length);
            if (outputSize > Integer.MAX_VALUE - outputPrefix.length - C1_SIZE - NONCE_SIZE) {
                throw new GeneralSecurityException("plaintext too long");
            }
            int len = outputPrefix.length + C1_SIZE + NONCE_SIZE + outputSize;
            byte[] output = new byte[len];
            System.arraycopy(outputPrefix, 0, output, 0, outputPrefix.length);
            System.arraycopy(c1, 0, output, outputPrefix.length, C1_SIZE);
            System.arraycopy(
                nonce, 0, output, outputPrefix.length + C1_SIZE, NONCE_SIZE);
            int written =
                cipher.doFinal(
                    plaintext,
                    0,
                    plaintext.length,
                    output,
                    outputPrefix.length + C1_SIZE + NONCE_SIZE);
            if (written != outputSize) {
                throw new GeneralSecurityException("not enough data written");
            }
            return output;
        } catch (GeneralSecurityException e) {
            throw new GeneralSecurityException("Encryption failed", e);
        } catch (RuntimeException e) {
            throw new GeneralSecurityException("Encryption failed", e);
        }
    }
}
