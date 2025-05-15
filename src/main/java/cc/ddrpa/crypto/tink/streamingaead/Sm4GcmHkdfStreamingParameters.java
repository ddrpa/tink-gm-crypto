package cc.ddrpa.crypto.tink.streamingaead;

import com.google.crypto.tink.streamingaead.StreamingAeadParameters;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Represents the parameters of a {@link Sm4GcmHkdfStreamingKey}.
 *
 * <p>We refer to https://developers.google.com/tink/streaming-aead/sm4_gcm_hkdf_streaming for a
 * complete description of the values.
 */
public class Sm4GcmHkdfStreamingParameters extends StreamingAeadParameters {

    private final Integer keySizeBytes;
    private final Integer derivedSm4GcmKeySizeBytes;
    private final HashType hkdfHashType;
    private final Integer ciphertextSegmentSizeBytes;

    private Sm4GcmHkdfStreamingParameters(
        Integer keySizeBytes,
        Integer derivedSm4GcmKeySizeBytes,
        HashType hkdfHashType,
        Integer ciphertextSegmentSizeBytes) {
        this.keySizeBytes = keySizeBytes;
        this.derivedSm4GcmKeySizeBytes = derivedSm4GcmKeySizeBytes;
        this.hkdfHashType = hkdfHashType;
        this.ciphertextSegmentSizeBytes = ciphertextSegmentSizeBytes;
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns the size of the initial key material.
     */
    public int getKeySizeBytes() {
        return keySizeBytes;
    }

    /**
     * Returns the size of the SM4 GCM key which will internally be derived.
     */
    public int getDerivedSm4GcmKeySizeBytes() {
        return derivedSm4GcmKeySizeBytes;
    }

    /**
     * Returns the type of the hash function used in HKDF.
     */
    public HashType getHkdfHashType() {
        return hkdfHashType;
    }

    /**
     * Returns the size a ciphertext segment has.
     */
    public int getCiphertextSegmentSizeBytes() {
        return ciphertextSegmentSizeBytes;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Sm4GcmHkdfStreamingParameters)) {
            return false;
        }
        Sm4GcmHkdfStreamingParameters that = (Sm4GcmHkdfStreamingParameters) o;
        return that.getKeySizeBytes() == getKeySizeBytes()
            && that.getDerivedSm4GcmKeySizeBytes() == getDerivedSm4GcmKeySizeBytes()
            && that.getHkdfHashType() == getHkdfHashType()
            && that.getCiphertextSegmentSizeBytes() == getCiphertextSegmentSizeBytes();
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            Sm4GcmHkdfStreamingParameters.class,
            keySizeBytes,
            derivedSm4GcmKeySizeBytes,
            hkdfHashType,
            ciphertextSegmentSizeBytes);
    }

    @Override
    public String toString() {
        return "Sm4GcmHkdfStreaming Parameters (IKM size: "
            + keySizeBytes
            + ", "
            + derivedSm4GcmKeySizeBytes
            + "-byte SM4 GCM key, "
            + hkdfHashType
            + " for HKDF "
            + ciphertextSegmentSizeBytes
            + "-byte ciphertexts)";
    }

    /**
     * Represents the hash type used.
     */
    @Immutable
    public static final class HashType {

        public static final HashType SHA1 = new HashType("SHA1");
        public static final HashType SHA256 = new HashType("SHA256");
        public static final HashType SHA512 = new HashType("SHA512");

        private final String name;

        private HashType(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    /**
     * Helps creating new {@link Sm4GcmHkdfStreamingParameters} objects.
     */
    public static final class Builder {

        @Nullable
        private Integer keySizeBytes = null;

        @Nullable
        private Integer derivedSm4GcmKeySizeBytes = null;

        @Nullable
        private HashType hkdfHashType = null;

        @Nullable
        private Integer ciphertextSegmentSizeBytes = null;

        /**
         * Sets the size of the initial key material (used as input to HKDF).
         *
         * <p>Must be at least 16, and at least equal to the value set in {@link
         * #setDerivedSm4GcmKeySizeBytes}
         */
        @CanIgnoreReturnValue
        public Builder setKeySizeBytes(int keySizeBytes) {
            this.keySizeBytes = keySizeBytes;
            return this;
        }

        /**
         * Sets the size of the SM4 GCM key which will internally be derived.
         *
         * <p>Must be 16
         */
        @CanIgnoreReturnValue
        public Builder setDerivedSm4GcmKeySizeBytes(int derivedSm4GcmKeySizeBytes) {
            this.derivedSm4GcmKeySizeBytes = derivedSm4GcmKeySizeBytes;
            return this;
        }

        /**
         * Sets the type of the hash function used in HKDF.
         */
        @CanIgnoreReturnValue
        public Builder setHkdfHashType(HashType hkdfHashType) {
            this.hkdfHashType = hkdfHashType;
            return this;
        }

        /**
         * Sets the size of a segment.
         *
         * <p>Must be at least equal 24 plus the value set in
         * {@link #setDerivedSm4GcmKeySizeBytes}, and less than 2^31.
         */
        @CanIgnoreReturnValue
        public Builder setCiphertextSegmentSizeBytes(int ciphertextSegmentSizeBytes) {
            this.ciphertextSegmentSizeBytes = ciphertextSegmentSizeBytes;
            return this;
        }

        /**
         * Checks restrictions as on the devsite
         */
        public Sm4GcmHkdfStreamingParameters build() throws GeneralSecurityException {
            if (keySizeBytes == null) {
                throw new GeneralSecurityException("keySizeBytes needs to be set");
            }
            if (derivedSm4GcmKeySizeBytes == null) {
                throw new GeneralSecurityException("derivedSm4GcmKeySizeBytes needs to be set");
            }
            if (hkdfHashType == null) {
                throw new GeneralSecurityException("hkdfHashType needs to be set");
            }
            if (ciphertextSegmentSizeBytes == null) {
                throw new GeneralSecurityException("ciphertextSegmentSizeBytes needs to be set");
            }

            if (derivedSm4GcmKeySizeBytes != 16) {
                throw new GeneralSecurityException(
                    "derivedSm4GcmKeySizeBytes needs to be 16, not "
                        + derivedSm4GcmKeySizeBytes);
            }
            if (keySizeBytes < derivedSm4GcmKeySizeBytes) {
                throw new GeneralSecurityException(
                    "keySizeBytes needs to be at least derivedSm4GcmKeySizeBytes, i.e., "
                        + derivedSm4GcmKeySizeBytes);
            }
            if (ciphertextSegmentSizeBytes <= derivedSm4GcmKeySizeBytes + 24) {
                throw new GeneralSecurityException(
                    "ciphertextSegmentSizeBytes needs to be at least derivedSm4GcmKeySizeBytes + 25, i.e., "
                        + (derivedSm4GcmKeySizeBytes + 25));
            }
            return new Sm4GcmHkdfStreamingParameters(
                keySizeBytes, derivedSm4GcmKeySizeBytes, hkdfHashType, ciphertextSegmentSizeBytes);
        }
    }
}
