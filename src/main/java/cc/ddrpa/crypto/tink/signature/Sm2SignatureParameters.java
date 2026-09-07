package cc.ddrpa.crypto.tink.signature;

import com.google.crypto.tink.signature.SignatureParameters;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;

import javax.annotation.Nullable;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * Describes the parameters of an {@link Sm2SignaturePrivateKey} / {@link Sm2SignaturePublicKey}.
 *
 * <p>SM2 signature always uses the SM3 hash, the {@code sm2p256v1} curve and the default SM2 user
 * ID defined in GB/T 32918.2, so the only free parameter is the {@link Variant}.
 */
public final class Sm2SignatureParameters extends SignatureParameters {

    private final Sm2SignatureParameters.Variant variant;

    private Sm2SignatureParameters(Sm2SignatureParameters.Variant variant) {
        this.variant = variant;
    }

    public static Sm2SignatureParameters.Builder builder() {
        return new Sm2SignatureParameters.Builder();
    }

    /**
     * Returns a variant object.
     */
    public Sm2SignatureParameters.Variant getVariant() {
        return variant;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Sm2SignatureParameters)) {
            return false;
        }
        Sm2SignatureParameters that = (Sm2SignatureParameters) o;
        return that.getVariant() == getVariant();
    }

    @Override
    public int hashCode() {
        return Objects.hash(Sm2SignatureParameters.class, variant);
    }

    @Override
    public boolean hasIdRequirement() {
        return variant != Sm2SignatureParameters.Variant.NO_PREFIX;
    }

    @Override
    public String toString() {
        return "Sm2Signature Parameters (variant: " + variant + ")";
    }

    /**
     * Describes how the prefix is computed. For signatures there are two main possibilities:
     * NO_PREFIX (empty prefix) or TINK (prefix the signature with 0x01 followed by a 4-byte key id
     * in big endian format).
     */
    @Immutable
    public static final class Variant {

        public static final Sm2SignatureParameters.Variant TINK = new Sm2SignatureParameters.Variant(
                "TINK");
        public static final Sm2SignatureParameters.Variant NO_PREFIX =
                new Sm2SignatureParameters.Variant("NO_PREFIX");

        private final String name;

        private Variant(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    /**
     * Builds a new Sm2SignatureParameters instance.
     */
    public static final class Builder {

        @Nullable
        private Sm2SignatureParameters.Variant variant = Sm2SignatureParameters.Variant.NO_PREFIX;

        private Builder() {
        }

        @CanIgnoreReturnValue
        public Sm2SignatureParameters.Builder setVariant(Sm2SignatureParameters.Variant variant) {
            this.variant = variant;
            return this;
        }

        public Sm2SignatureParameters build() throws GeneralSecurityException {
            if (variant == null) {
                throw new GeneralSecurityException("Variant is not set");
            }
            return new Sm2SignatureParameters(variant);
        }
    }
}
