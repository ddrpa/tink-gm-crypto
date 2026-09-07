package cc.ddrpa.crypto.tink.signature.internal;

import cc.ddrpa.crypto.tink.signature.Sm2SignaturePublicKey;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.errorprone.annotations.Immutable;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.SM2Signer;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static com.google.crypto.tink.internal.Util.isPrefix;

/**
 * SM2 signature verifying with Bouncy Castle.
 *
 * <p>Verification expects signatures in the raw 64-byte {@code r || s} encoding (see {@link
 * Sm2PublicKeySign}); any malformed signature results in a {@link GeneralSecurityException}, never
 * in a crash.
 */
@Immutable
public final class Sm2PublicKeyVerify implements PublicKeyVerify {

    /**
     * The default SM2 user ID ("1234567812345678" in ASCII) as defined in GB/T 32918.2.
     */
    private static final byte[] DEFAULT_USER_ID =
            "1234567812345678".getBytes(StandardCharsets.US_ASCII);

    @SuppressWarnings("Immutable")
    private final ECPublicKeyParameters publicKeyParams;
    @SuppressWarnings("Immutable")
    private final byte[] outputPrefix;

    private Sm2PublicKeyVerify(ECPublicKeyParameters publicKeyParams, byte[] outputPrefix) {
        this.publicKeyParams = publicKeyParams;
        this.outputPrefix = outputPrefix;
    }

    /**
     * Creates a new {@link PublicKeyVerify} from the given key.
     */
    @AccessesPartialKey
    public static PublicKeyVerify create(Sm2SignaturePublicKey key)
            throws GeneralSecurityException {
        byte[] outputPrefix = key.getOutputPrefix().toByteArray();
        ECPublicKeyParameters publicKeyParams =
                Sm2KeyUtil.toPublicKeyParameters(key.getPublicKey().toByteArray());
        return new Sm2PublicKeyVerify(publicKeyParams, outputPrefix);
    }

    private void noPrefixVerify(final byte[] signature, final byte[] data)
            throws GeneralSecurityException {
        SM2Signer signer = new SM2Signer(new PlainDSAEncoding(), new SM3Digest());
        signer.init(false, new ParametersWithID(publicKeyParams, DEFAULT_USER_ID));
        signer.update(data, 0, data.length);
        boolean verified = signer.verifySignature(signature);
        if (!verified) {
            throw new GeneralSecurityException("Invalid signature");
        }
    }

    @Override
    public void verify(final byte[] signature, final byte[] data)
            throws GeneralSecurityException {
        if (outputPrefix.length == 0) {
            noPrefixVerify(signature, data);
            return;
        }
        if (!isPrefix(outputPrefix, signature)) {
            throw new GeneralSecurityException("Invalid signature (output prefix mismatch)");
        }
        byte[] signatureNoPrefix =
                Arrays.copyOfRange(signature, outputPrefix.length, signature.length);
        noPrefixVerify(signatureNoPrefix, data);
    }
}
