package cc.ddrpa.crypto.tink.aead;

import com.google.crypto.tink.aead.AeadParameters;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;


/**
 * Describes the parameters of an {@link Sm4GcmKey}
 */
public final class Sm4GcmParameters extends AeadParameters {

    private final int keySizeBytes = 16;
    private final int ivSizeBytes;
    private final int tagSizeBytes;
    private final Sm4GcmParameters.Variant variant;

    private Sm4GcmParameters(int ivSizeBytes, int tagSizeBytes, Sm4GcmParameters.Variant variant) {
        this.ivSizeBytes = ivSizeBytes;
        this.tagSizeBytes = tagSizeBytes;
        this.variant = variant;
    }

    public static Sm4GcmParameters.Builder builder() {
        return new Sm4GcmParameters.Builder();
    }

    public int getKeySizeBytes() {
        return keySizeBytes;
    }

    public int getIvSizeBytes() {
        return ivSizeBytes;
    }

    public int getTagSizeBytes() {
        return tagSizeBytes;
    }

    /**
     * Returns a variant object.
     */
    public Sm4GcmParameters.Variant getVariant() {
        return variant;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Sm4GcmParameters)) {
            return false;
        }
        Sm4GcmParameters that = (Sm4GcmParameters) o;
        return that.getIvSizeBytes() == getIvSizeBytes()
            && that.getTagSizeBytes() == getTagSizeBytes()
            && that.getVariant() == getVariant();
    }

    @Override
    public int hashCode() {
        return Objects.hash(Sm4GcmParameters.class, keySizeBytes, ivSizeBytes, tagSizeBytes,
            variant);
    }

    @Override
    public boolean hasIdRequirement() {
        return variant != Sm4GcmParameters.Variant.NO_PREFIX;
    }

    @Override
    public String toString() {
        return "Sm4Gcm Parameters (variant: "
            + variant
            + ", "
            + ivSizeBytes
            + "-byte IV, "
            + tagSizeBytes
            + "-byte tag, and "
            + keySizeBytes
            + "-byte key)";
    }

    /**
     * Describes how the prefix is computed. For AEAD there are two main possibilities: NO_PREFIX
     * (empty prefix) or TINK (prefix the ciphertext with 0x01 followed by a 4-byte key id in big
     * endian format)
     */
    @Immutable
    public static final class Variant {

        public static final Sm4GcmParameters.Variant TINK = new Sm4GcmParameters.Variant("TINK");
        public static final Sm4GcmParameters.Variant NO_PREFIX = new Sm4GcmParameters.Variant(
            "NO_PREFIX");

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
     * Builds a new Sm4GcmParameters instance. The class Sm4GcmParameters is not responsible for
     * checking if all allowed values for the parameters are implemented and satisfy any potential
     * security policies. Some implementation may not support the full set of parameters at the
     * moment and may restrict them to certain lengths (i.e. key size may be restricted to 16 or 32
     * bytes).
     */
    public static final class Builder {

        @Nullable
        private Integer ivSizeBytes = null;
        @Nullable
        private Integer tagSizeBytes = null;
        private Sm4GcmParameters.Variant variant = Sm4GcmParameters.Variant.NO_PREFIX;

        private Builder() {
        }

        /**
         * IV size must greater than 0.
         */
        @CanIgnoreReturnValue
        public Sm4GcmParameters.Builder setIvSizeBytes(int ivSizeBytes)
            throws GeneralSecurityException {
            if (ivSizeBytes <= 0) {
                throw new GeneralSecurityException(
                    String.format("Invalid IV size in bytes %d; IV size must be positive",
                        ivSizeBytes));
            }
            this.ivSizeBytes = ivSizeBytes;
            return this;
        }

        /**
         * Tag size must be between 12 and 16 bytes.
         */
        @CanIgnoreReturnValue
        public Sm4GcmParameters.Builder setTagSizeBytes(int tagSizeBytes)
            throws GeneralSecurityException {
            if (tagSizeBytes < 12 || tagSizeBytes > 16) {
                throw new GeneralSecurityException(
                    String.format(
                        "Invalid tag size in bytes %d; value must be between 12 and 16 bytes",
                        tagSizeBytes));
            }
            this.tagSizeBytes = tagSizeBytes;
            return this;
        }

        @CanIgnoreReturnValue
        public Sm4GcmParameters.Builder setVariant(Sm4GcmParameters.Variant variant) {
            this.variant = variant;
            return this;
        }

        public Sm4GcmParameters build() throws GeneralSecurityException {
            if (variant == null) {
                throw new GeneralSecurityException("Variant is not set");
            }
            if (ivSizeBytes == null) {
                throw new GeneralSecurityException("IV size is not set");
            }

            if (tagSizeBytes == null) {
                throw new GeneralSecurityException("Tag size is not set");
            }

            return new Sm4GcmParameters(ivSizeBytes, tagSizeBytes, variant);
        }
    }
}
