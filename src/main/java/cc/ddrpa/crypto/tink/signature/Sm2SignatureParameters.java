package cc.ddrpa.crypto.tink.signature;

import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.signature.SignatureParameters;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Describes the parameters of an {@link Sm2PrivateKey} and {@link Sm2PublicKey}.
 */
@Immutable
public final class Sm2SignatureParameters extends SignatureParameters {

    /**
     * Supported hash types for SM2 signature.
     */
    @Immutable
    public static final class HashAlgorithm {
        public static final HashAlgorithm SM3 = new HashAlgorithm("SM3");
        public static final HashAlgorithm SHA256 = new HashAlgorithm("SHA256");

        private final String name;

        private HashAlgorithm(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    /**
     * Supported signature encodings for SM2.
     */
    @Immutable
    public static final class SignatureEncoding {
        public static final SignatureEncoding DER = new SignatureEncoding("DER");
        public static final SignatureEncoding IEEE_P1363 = new SignatureEncoding("IEEE_P1363");

        private final String name;

        private SignatureEncoding(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    /**
     * Describes how the prefix is computed.
     */
    @Immutable
    public static final class Variant {
        public static final Variant TINK = new Variant("TINK");
        public static final Variant NO_PREFIX = new Variant("NO_PREFIX");
        public static final Variant LEGACY = new Variant("LEGACY");
        public static final Variant CRUNCHY = new Variant("CRUNCHY");

        private final String name;

        private Variant(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    private final HashAlgorithm hashAlgorithm;
    private final SignatureEncoding signatureEncoding;
    private final Variant variant;

    private Sm2SignatureParameters(
            HashAlgorithm hashAlgorithm,
            SignatureEncoding signatureEncoding,
            Variant variant) {
        this.hashAlgorithm = hashAlgorithm;
        this.signatureEncoding = signatureEncoding;
        this.variant = variant;
    }

    public static Builder builder() {
        return new Builder();
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public SignatureEncoding getSignatureEncoding() {
        return signatureEncoding;
    }

    public Variant getVariant() {
        return variant;
    }

    /** Returns the hash type corresponding to the hash algorithm. */
    public HashType getHashType() {
        if (hashAlgorithm == HashAlgorithm.SM3) {
            // Note: SM3 is not defined in the standard Tink HashType enum
            // For now, we'll use SHA256 as a placeholder and handle SM3 specifically in the implementation
            return HashType.SHA256;
        }
        if (hashAlgorithm == HashAlgorithm.SHA256) {
            return HashType.SHA256;
        }
        throw new IllegalStateException("Unknown hash algorithm: " + hashAlgorithm);
    }

    @Override
    public boolean hasIdRequirement() {
        return variant != Variant.NO_PREFIX;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Sm2SignatureParameters)) {
            return false;
        }
        Sm2SignatureParameters that = (Sm2SignatureParameters) o;
        return Objects.equals(hashAlgorithm, that.hashAlgorithm)
                && Objects.equals(signatureEncoding, that.signatureEncoding)
                && Objects.equals(variant, that.variant);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Sm2SignatureParameters.class, hashAlgorithm, signatureEncoding, variant);
    }

    @Override
    public String toString() {
        return "SM2 Signature Parameters (hash: "
                + hashAlgorithm
                + ", encoding: "
                + signatureEncoding
                + ", variant: "
                + variant
                + ")";
    }

    /**
     * Builder for Sm2SignatureParameters.
     */
    public static final class Builder {
        @Nullable private HashAlgorithm hashAlgorithm = null;
        @Nullable private SignatureEncoding signatureEncoding = null;
        private Variant variant = Variant.NO_PREFIX;

        private Builder() {}

        @CanIgnoreReturnValue
        public Builder setHashAlgorithm(HashAlgorithm hashAlgorithm) {
            this.hashAlgorithm = hashAlgorithm;
            return this;
        }

        @CanIgnoreReturnValue
        public Builder setSignatureEncoding(SignatureEncoding signatureEncoding) {
            this.signatureEncoding = signatureEncoding;
            return this;
        }

        @CanIgnoreReturnValue
        public Builder setVariant(Variant variant) {
            this.variant = variant;
            return this;
        }

        public Sm2SignatureParameters build() throws GeneralSecurityException {
            if (hashAlgorithm == null) {
                throw new GeneralSecurityException("Hash algorithm is not set");
            }
            if (signatureEncoding == null) {
                throw new GeneralSecurityException("Signature encoding is not set");
            }
            if (variant == null) {
                throw new GeneralSecurityException("Variant is not set");
            }
            return new Sm2SignatureParameters(hashAlgorithm, signatureEncoding, variant);
        }
    }
}