package cc.ddrpa.crypto.tink.aead;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.aead.AeadKey;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Represents an SM4-GCM key used for computing AEAD.
 */
@Immutable
public final class Sm4GcmKey extends AeadKey {

    private final Sm4GcmParameters parameters;
    private final SecretBytes keyBytes;
    private final Bytes outputPrefix;
    @Nullable
    private final Integer idRequirement;

    private Sm4GcmKey(
        Sm4GcmParameters parameters,
        SecretBytes keyBytes,
        Bytes outputPrefix,
        @Nullable Integer idRequirement) {
        this.parameters = parameters;
        this.keyBytes = keyBytes;
        this.outputPrefix = outputPrefix;
        this.idRequirement = idRequirement;
    }

    @RestrictedApi(
        explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
        link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
        allowedOnPath = ".*Test\\.java",
        allowlistAnnotations = {AccessesPartialKey.class})
    public static Sm4GcmKey.Builder builder() {
        return new Sm4GcmKey.Builder();
    }

    /**
     * Returns the underlying key bytes.
     */
    @RestrictedApi(
        explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
        link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
        allowedOnPath = ".*Test\\.java",
        allowlistAnnotations = {AccessesPartialKey.class})
    public SecretBytes getKeyBytes() {
        return keyBytes;
    }

    @Override
    public Bytes getOutputPrefix() {
        return outputPrefix;
    }

    @Override
    public Sm4GcmParameters getParameters() {
        return parameters;
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
        return idRequirement;
    }

    @Override
    public boolean equalsKey(Key o) {
        if (!(o instanceof Sm4GcmKey)) {
            return false;
        }
        Sm4GcmKey that = (Sm4GcmKey) o;
        // Since outputPrefix is a function of parameters, we can ignore it here.
        return that.parameters.equals(parameters)
            && that.keyBytes.equalsSecretBytes(keyBytes)
            && Objects.equals(that.idRequirement, idRequirement);
    }

    /**
     * Builder for Sm4GcmKey.
     */
    public static class Builder {

        @Nullable
        private Sm4GcmParameters parameters = null;
        @Nullable
        private SecretBytes keyBytes = null;
        @Nullable
        private Integer idRequirement = null;

        private Builder() {
        }

        @CanIgnoreReturnValue
        public Sm4GcmKey.Builder setParameters(Sm4GcmParameters parameters) {
            this.parameters = parameters;
            return this;
        }

        @CanIgnoreReturnValue
        public Sm4GcmKey.Builder setKeyBytes(SecretBytes keyBytes) {
            this.keyBytes = keyBytes;
            return this;
        }

        @CanIgnoreReturnValue
        public Sm4GcmKey.Builder setIdRequirement(@Nullable Integer idRequirement) {
            this.idRequirement = idRequirement;
            return this;
        }

        private Bytes getOutputPrefix() {
            if (parameters.getVariant() == Sm4GcmParameters.Variant.NO_PREFIX) {
                return Bytes.copyFrom(new byte[]{});
            }
            if (parameters.getVariant() == Sm4GcmParameters.Variant.TINK) {
                return Bytes.copyFrom(
                    ByteBuffer.allocate(5).put((byte) 1).putInt(idRequirement).array());
            }
            throw new IllegalStateException(
                "Unknown Sm4GcmParameters.Variant: " + parameters.getVariant());
        }

        public Sm4GcmKey build() throws GeneralSecurityException {
            if (parameters == null || keyBytes == null) {
                throw new GeneralSecurityException(
                    "Cannot build without parameters and/or key material");
            }

            if (parameters.getKeySizeBytes() != keyBytes.size()) {
                throw new GeneralSecurityException("Key size mismatch");
            }

            if (parameters.hasIdRequirement() && idRequirement == null) {
                throw new GeneralSecurityException(
                    "Cannot create key without ID requirement with parameters with ID requirement");
            }

            if (!parameters.hasIdRequirement() && idRequirement != null) {
                throw new GeneralSecurityException(
                    "Cannot create key with ID requirement with parameters without ID requirement");
            }
            Bytes outputPrefix = getOutputPrefix();
            return new Sm4GcmKey(parameters, keyBytes, outputPrefix, idRequirement);
        }
    }
}
