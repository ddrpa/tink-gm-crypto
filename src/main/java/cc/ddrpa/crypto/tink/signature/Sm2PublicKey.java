package cc.ddrpa.crypto.tink.signature;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.signature.SignaturePublicKey;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Represents an SM2 public key used for verifying signatures.
 */
@Immutable
public final class Sm2PublicKey extends SignaturePublicKey {

    private final Sm2SignatureParameters parameters;
    private final Bytes publicKeyX;
    private final Bytes publicKeyY;
    private final Bytes outputPrefix;
    @Nullable
    private final Integer idRequirement;

    private Sm2PublicKey(
            Sm2SignatureParameters parameters,
            Bytes publicKeyX,
            Bytes publicKeyY,
            Bytes outputPrefix,
            @Nullable Integer idRequirement) {
        this.parameters = parameters;
        this.publicKeyX = publicKeyX;
        this.publicKeyY = publicKeyY;
        this.outputPrefix = outputPrefix;
        this.idRequirement = idRequirement;
    }

    @RestrictedApi(
            explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
            link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
            allowedOnPath = ".*Test\\.java",
            allowlistAnnotations = {AccessesPartialKey.class})
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns the x coordinate of the public key point.
     */
    @RestrictedApi(
            explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
            link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
            allowedOnPath = ".*Test\\.java",
            allowlistAnnotations = {AccessesPartialKey.class})
    public Bytes getPublicKeyX() {
        return publicKeyX;
    }

    /**
     * Returns the y coordinate of the public key point.
     */
    @RestrictedApi(
            explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
            link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
            allowedOnPath = ".*Test\\.java",
            allowlistAnnotations = {AccessesPartialKey.class})
    public Bytes getPublicKeyY() {
        return publicKeyY;
    }

    @Override
    public Bytes getOutputPrefix() {
        return outputPrefix;
    }

    @Override
    public Sm2SignatureParameters getParameters() {
        return parameters;
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
        return idRequirement;
    }

    @Override
    public boolean equalsKey(Key o) {
        if (!(o instanceof Sm2PublicKey)) {
            return false;
        }
        Sm2PublicKey that = (Sm2PublicKey) o;
        return Objects.equals(parameters, that.parameters)
                && publicKeyX.equals(that.publicKeyX)
                && publicKeyY.equals(that.publicKeyY)
                && Objects.equals(idRequirement, that.idRequirement);
    }

    /**
     * Builder for Sm2PublicKey.
     */
    public static class Builder {
        @Nullable private Sm2SignatureParameters parameters = null;
        @Nullable private Bytes publicKeyX = null;
        @Nullable private Bytes publicKeyY = null;
        @Nullable private Integer idRequirement = null;

        private Builder() {}

        @CanIgnoreReturnValue
        public Builder setParameters(Sm2SignatureParameters parameters) {
            this.parameters = parameters;
            return this;
        }

        @CanIgnoreReturnValue
        public Builder setPublicKeyX(Bytes publicKeyX) {
            this.publicKeyX = publicKeyX;
            return this;
        }

        @CanIgnoreReturnValue
        public Builder setPublicKeyY(Bytes publicKeyY) {
            this.publicKeyY = publicKeyY;
            return this;
        }

        @CanIgnoreReturnValue
        public Builder setIdRequirement(@Nullable Integer idRequirement) {
            this.idRequirement = idRequirement;
            return this;
        }

        private Bytes getOutputPrefix() {
            if (parameters.getVariant() == Sm2SignatureParameters.Variant.NO_PREFIX) {
                return Bytes.copyFrom(new byte[]{});
            }
            if (parameters.getVariant() == Sm2SignatureParameters.Variant.TINK) {
                return Bytes.copyFrom(
                        ByteBuffer.allocate(5).put((byte) 1).putInt(idRequirement).array());
            }
            if (parameters.getVariant() == Sm2SignatureParameters.Variant.LEGACY) {
                return Bytes.copyFrom(
                        ByteBuffer.allocate(5).put((byte) 0).putInt(idRequirement).array());
            }
            if (parameters.getVariant() == Sm2SignatureParameters.Variant.CRUNCHY) {
                return Bytes.copyFrom(
                        ByteBuffer.allocate(5).put((byte) 0).putInt(idRequirement).array());
            }
            throw new IllegalStateException(
                    "Unknown Sm2SignatureParameters.Variant: " + parameters.getVariant());
        }

        public Sm2PublicKey build() throws GeneralSecurityException {
            if (parameters == null || publicKeyX == null || publicKeyY == null) {
                throw new GeneralSecurityException(
                        "Cannot build without parameters and/or key material");
            }

            if (publicKeyX.size() != 32) {
                throw new GeneralSecurityException("SM2 public key X coordinate must be 32 bytes");
            }

            if (publicKeyY.size() != 32) {
                throw new GeneralSecurityException("SM2 public key Y coordinate must be 32 bytes");
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
            return new Sm2PublicKey(parameters, publicKeyX, publicKeyY, outputPrefix, idRequirement);
        }
    }
}