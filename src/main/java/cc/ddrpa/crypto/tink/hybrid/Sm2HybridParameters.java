package cc.ddrpa.crypto.tink.hybrid;

import com.google.crypto.tink.hybrid.HybridParameters;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Describes the parameters of an {@link Sm2HybridPrivateKey} / {@link Sm2HybridPublicKey}.
 *
 * <p>SM2 hybrid encryption (F2) is the "SM2-KEM + SM4-GCM DEM" scheme: an SM2 ephemeral key
 * agreement (over the {@code sm2p256v1} curve, using SM3 through {@code Sm2Kdf}) encapsulates a
 * 128 bit SM4-GCM data key which encrypts the plaintext. Unlike the standard SM2 (F1) encryption,
 * arbitrary {@code contextInfo} bytes are authenticated as SM4-GCM associated data. The only free
 * parameter is the {@link Variant}.
 */
public final class Sm2HybridParameters extends HybridParameters {

    private final Sm2HybridParameters.Variant variant;

    private Sm2HybridParameters(Sm2HybridParameters.Variant variant) {
        this.variant = variant;
    }

    public static Sm2HybridParameters.Builder builder() {
        return new Sm2HybridParameters.Builder();
    }

    /**
     * Returns a variant object.
     */
    public Sm2HybridParameters.Variant getVariant() {
        return variant;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Sm2HybridParameters)) {
            return false;
        }
        Sm2HybridParameters that = (Sm2HybridParameters) o;
        return that.getVariant() == getVariant();
    }

    @Override
    public int hashCode() {
        return Objects.hash(Sm2HybridParameters.class, variant);
    }

    @Override
    public boolean hasIdRequirement() {
        return variant != Sm2HybridParameters.Variant.NO_PREFIX;
    }

    @Override
    public String toString() {
        return "Sm2Hybrid Parameters (variant: " + variant + ")";
    }

    /**
     * Describes how the output prefix is computed. For hybrid encryption there are two main
     * possibilities: NO_PREFIX (empty prefix) or TINK (prefix the ciphertext with 0x01 followed by
     * a 4-byte key id in big endian format).
     */
    @Immutable
    public static final class Variant {

        public static final Sm2HybridParameters.Variant TINK =
            new Sm2HybridParameters.Variant("TINK");
        public static final Sm2HybridParameters.Variant NO_PREFIX =
            new Sm2HybridParameters.Variant("NO_PREFIX");

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
     * Builds a new Sm2HybridParameters instance.
     */
    public static final class Builder {

        @Nullable
        private Sm2HybridParameters.Variant variant =
            Sm2HybridParameters.Variant.NO_PREFIX;

        private Builder() {
        }

        @CanIgnoreReturnValue
        public Sm2HybridParameters.Builder setVariant(
            Sm2HybridParameters.Variant variant) {
            this.variant = variant;
            return this;
        }

        public Sm2HybridParameters build() throws GeneralSecurityException {
            if (variant == null) {
                throw new GeneralSecurityException("Variant is not set");
            }
            return new Sm2HybridParameters(variant);
        }
    }
}
