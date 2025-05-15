package cc.ddrpa.crypto.tink.streamingaead;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.streamingaead.StreamingAeadKey;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;

/**
 * Represents a StreamingAead functions.
 *
 * <p>See https://developers.google.com/tink/streaming-aead/sm4_gcm_hkdf_streaming.
 */
public final class Sm4GcmHkdfStreamingKey extends StreamingAeadKey {

    private final Sm4GcmHkdfStreamingParameters parameters;
    private final SecretBytes initialKeymaterial;

    private Sm4GcmHkdfStreamingKey(
        Sm4GcmHkdfStreamingParameters parameters, SecretBytes initialKeymaterial) {
        this.parameters = parameters;
        this.initialKeymaterial = initialKeymaterial;
    }

    @RestrictedApi(
        explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
        link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
        allowedOnPath = ".*Test\\.java",
        allowlistAnnotations = {AccessesPartialKey.class})
    public static Sm4GcmHkdfStreamingKey create(
        Sm4GcmHkdfStreamingParameters parameters, SecretBytes initialKeymaterial)
        throws GeneralSecurityException {

        if (parameters.getKeySizeBytes() != initialKeymaterial.size()) {
            throw new GeneralSecurityException("Key size mismatch");
        }
        return new Sm4GcmHkdfStreamingKey(parameters, initialKeymaterial);
    }

    @RestrictedApi(
        explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
        link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
        allowedOnPath = ".*Test\\.java",
        allowlistAnnotations = {AccessesPartialKey.class})
    public SecretBytes getInitialKeyMaterial() {
        return initialKeymaterial;
    }

    @Override
    public Sm4GcmHkdfStreamingParameters getParameters() {
        return parameters;
    }

    @Override
    public boolean equalsKey(Key o) {
        if (!(o instanceof Sm4GcmHkdfStreamingKey)) {
            return false;
        }
        Sm4GcmHkdfStreamingKey that = (Sm4GcmHkdfStreamingKey) o;
        return that.parameters.equals(parameters)
            && that.initialKeymaterial.equalsSecretBytes(initialKeymaterial);
    }
}
