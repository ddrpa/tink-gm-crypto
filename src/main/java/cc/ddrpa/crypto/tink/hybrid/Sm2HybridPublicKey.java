package cc.ddrpa.crypto.tink.hybrid;

import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.hybrid.HybridPublicKey;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Represents the public portion of an SM2 hybrid encryption (F2) key.
 *
 * <p>The public key is an {@code sm2p256v1} curve point stored as 64 bytes (X || Y), each
 * coordinate 32 bytes big-endian, without the 0x04 prefix. It is used as the recipient key of the
 * SM2 key agreement that encapsulates the SM4-GCM data key.
 */
@Immutable
public final class Sm2HybridPublicKey extends HybridPublicKey {

    private final Sm2HybridParameters parameters;
    private final Bytes publicKey;
    private final Bytes outputPrefix;
    @Nullable
    private final Integer idRequirement;

    private Sm2HybridPublicKey(
        Sm2HybridParameters parameters,
        Bytes publicKey,
        Bytes outputPrefix,
        @Nullable Integer idRequirement) {
        this.parameters = parameters;
        this.publicKey = publicKey;
        this.outputPrefix = outputPrefix;
        this.idRequirement = idRequirement;
    }

    @RestrictedApi(
        explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
        link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
        allowedOnPath = ".*Test\\.java",
        allowlistAnnotations = {AccessesPartialKey.class})
    public static Sm2HybridPublicKey.Builder builder() {
        return new Sm2HybridPublicKey.Builder();
    }

    /**
     * Returns the underlying public key material: 64 bytes (X || Y) encoding the {@code
     * sm2p256v1} curve point.
     */
    @RestrictedApi(
        explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
        link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
        allowedOnPath = ".*Test\\.java",
        allowlistAnnotations = {AccessesPartialKey.class})
    public Bytes getPublicKey() {
        return publicKey;
    }

    @Override
    public Bytes getOutputPrefix() {
        return outputPrefix;
    }

    @Override
    public Sm2HybridParameters getParameters() {
        return parameters;
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
        return idRequirement;
    }

    @Override
    public boolean equalsKey(Key o) {
        if (!(o instanceof Sm2HybridPublicKey)) {
            return false;
        }
        Sm2HybridPublicKey that = (Sm2HybridPublicKey) o;
        // Since outputPrefix is a function of parameters, we can ignore it here.
        return that.parameters.equals(parameters)
            && that.publicKey.equals(publicKey)
            && Objects.equals(that.idRequirement, idRequirement);
    }

    /**
     * Builder for Sm2HybridPublicKey.
     */
    public static class Builder {

        @Nullable
        private Sm2HybridParameters parameters = null;
        @Nullable
        private Bytes publicKey = null;
        @Nullable
        private Integer idRequirement = null;

        private Builder() {
        }

        @CanIgnoreReturnValue
        public Sm2HybridPublicKey.Builder setParameters(
            Sm2HybridParameters parameters) {
            this.parameters = parameters;
            return this;
        }

        /**
         * Sets the raw public key material: 64 bytes (X || Y) encoding a point on the {@code
         * sm2p256v1} curve.
         */
        @CanIgnoreReturnValue
        public Sm2HybridPublicKey.Builder setPublicKey(Bytes publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        @CanIgnoreReturnValue
        public Sm2HybridPublicKey.Builder setIdRequirement(@Nullable Integer idRequirement) {
            this.idRequirement = idRequirement;
            return this;
        }

        private Bytes getOutputPrefix() {
            if (parameters.getVariant() == Sm2HybridParameters.Variant.NO_PREFIX) {
                return Bytes.copyFrom(new byte[]{});
            }
            if (parameters.getVariant() == Sm2HybridParameters.Variant.TINK) {
                return Bytes.copyFrom(
                    ByteBuffer.allocate(5).put((byte) 1).putInt(idRequirement).array());
            }
            throw new IllegalStateException(
                "Unknown Sm2HybridParameters.Variant: " + parameters.getVariant());
        }

        public Sm2HybridPublicKey build() throws GeneralSecurityException {
            if (parameters == null) {
                throw new GeneralSecurityException("Cannot build without parameters");
            }
            if (publicKey == null) {
                throw new GeneralSecurityException("Cannot build without public key material");
            }
            // Validates that the public key material is exactly 64 bytes and that the encoded
            // point lies on the sm2p256v1 curve.
            Sm2KeyUtil.decodePublicPoint(publicKey.toByteArray());
            if (parameters.hasIdRequirement() && idRequirement == null) {
                throw new GeneralSecurityException(
                    "Cannot create key without ID requirement with parameters with ID requirement");
            }
            if (!parameters.hasIdRequirement() && idRequirement != null) {
                throw new GeneralSecurityException(
                    "Cannot create key with ID requirement with parameters without ID requirement");
            }
            Bytes outputPrefix = getOutputPrefix();
            return new Sm2HybridPublicKey(
                parameters, publicKey, outputPrefix, idRequirement);
        }
    }
}
