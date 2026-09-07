package cc.ddrpa.crypto.tink.signature.internal;

import cc.ddrpa.crypto.tink.signature.Sm2SignaturePrivateKey;
import cc.ddrpa.crypto.tink.signature.Sm2SignaturePublicKey;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.errorprone.annotations.Immutable;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.SM2Signer;

/**
 * SM2 signing with Bouncy Castle.
 *
 * <p>Signatures are computed over the raw 64-byte {@code r || s} encoding (each component 32 bytes
 * big-endian) using {@link PlainDSAEncoding}; Tink's {@code sm2p256v1} signatures are not DER
 * wrapped. This is the encoding mandated by GB/T 32918.2 and used by other SM2 implementations
 * (GmSSL/OpenSSL/Bouncy Castle).
 */
@Immutable
public final class Sm2PublicKeySign implements PublicKeySign {

    /** The default SM2 user ID ("1234567812345678" in ASCII) as defined in GB/T 32918.2. */
    static final byte[] DEFAULT_USER_ID =
        "1234567812345678".getBytes(StandardCharsets.US_ASCII);

    @SuppressWarnings("Immutable")
    private final ECPrivateKeyParameters privateKeyParams;
    @SuppressWarnings("Immutable")
    private final byte[] outputPrefix;

    private Sm2PublicKeySign(ECPrivateKeyParameters privateKeyParams, byte[] outputPrefix) {
        this.privateKeyParams = privateKeyParams;
        this.outputPrefix = outputPrefix;
    }

    /**
     * Creates a new {@link PublicKeySign} from the given key.
     */
    @AccessesPartialKey
    public static PublicKeySign create(Sm2SignaturePrivateKey key)
        throws GeneralSecurityException {
        byte[] outputPrefix = key.getOutputPrefix().toByteArray();
        ECPrivateKeyParameters privateKeyParams =
            Sm2KeyUtil.toPrivateKeyParameters(
                key.getPrivateValue().toByteArray(InsecureSecretKeyAccess.get()));
        // Validate the public key point early so that malformed keys fail fast when the primitive
        // is created instead of producing signatures which can never verify.
        Sm2SignaturePublicKey publicKey = key.getPublicKey();
        Sm2KeyUtil.decodePublicPoint(publicKey.getPublicKey().toByteArray());
        return new Sm2PublicKeySign(privateKeyParams, outputPrefix);
    }

    @Override
    public byte[] sign(byte[] data) throws GeneralSecurityException {
        if (data == null) {
            throw new GeneralSecurityException("data must not be null");
        }
        SM2Signer signer = new SM2Signer(new PlainDSAEncoding(), new SM3Digest());
        signer.init(
            true,
            new ParametersWithID(
                new ParametersWithRandom(privateKeyParams, Sm2KeyUtil.getSecureRandom()),
                DEFAULT_USER_ID));
        signer.update(data, 0, data.length);
        byte[] signature;
        try {
            signature = signer.generateSignature();
        } catch (CryptoException e) {
            throw new GeneralSecurityException("Signing failed", e);
        }
        if (outputPrefix.length == 0) {
            return signature;
        }
        return com.google.crypto.tink.subtle.Bytes.concat(outputPrefix, signature);
    }
}
