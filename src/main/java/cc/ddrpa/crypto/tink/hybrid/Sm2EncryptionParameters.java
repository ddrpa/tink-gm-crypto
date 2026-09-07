package cc.ddrpa.crypto.tink.hybrid;

import com.google.crypto.tink.hybrid.HybridParameters;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Describes the parameters of an {@link Sm2EncryptionPrivateKey} / {@link Sm2EncryptionPublicKey}.
 *
 * <p>SM2 encryption (F1) always uses the SM3 hash, the {@code sm2p256v1} curve and the standard
 * C1C3C2 ciphertext layout defined in GB/T 32918.4, and does not support associated data, so the
 * only free parameter is the {@link Variant}.
 */
public final class Sm2EncryptionParameters extends HybridParameters {

    private final Sm2EncryptionParameters.Variant variant;

    private Sm2EncryptionParameters(Sm2EncryptionParameters.Variant variant) {
        this.variant = variant;
    }

    public static Sm2EncryptionParameters.Builder builder() {
        return new Sm2EncryptionParameters.Builder();
    }

    /**
     * Returns a variant object.
     */
    public Sm2EncryptionParameters.Variant getVariant() {
        return variant;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Sm2EncryptionParameters)) {
            return false;
        }
        Sm2EncryptionParameters that = (Sm2EncryptionParameters) o;
        return that.getVariant() == getVariant();
    }

    @Override
    public int hashCode() {
        return Objects.hash(Sm2EncryptionParameters.class, variant);
    }

    @Override
    public boolean hasIdRequirement() {
        return variant != Sm2EncryptionParameters.Variant.NO_PREFIX;
    }

    @Override
    public String toString() {
        return "Sm2Encryption Parameters (variant: " + variant + ")";
    }

    /**
     * Describes how the output prefix is computed. For hybrid encryption there are two main
     * possibilities: NO_PREFIX (empty prefix) or TINK (prefix the ciphertext with 0x01 followed by
     * a 4-byte key id in big endian format).
     */
    @Immutable
    public static final class Variant {

        public static final Sm2EncryptionParameters.Variant TINK =
            new Sm2EncryptionParameters.Variant("TINK");
        public static final Sm2EncryptionParameters.Variant NO_PREFIX =
            new Sm2EncryptionParameters.Variant("NO_PREFIX");

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
     * Builds a new Sm2EncryptionParameters instance.
     */
    public static final class Builder {

        @Nullable
        private Sm2EncryptionParameters.Variant variant =
            Sm2EncryptionParameters.Variant.NO_PREFIX;

        private Builder() {
        }

        @CanIgnoreReturnValue
        public Sm2EncryptionParameters.Builder setVariant(
            Sm2EncryptionParameters.Variant variant) {
            this.variant = variant;
            return this;
        }

        public Sm2EncryptionParameters build() throws GeneralSecurityException {
            if (variant == null) {
                throw new GeneralSecurityException("Variant is not set");
            }
            return new Sm2EncryptionParameters(variant);
        }
    }
}
