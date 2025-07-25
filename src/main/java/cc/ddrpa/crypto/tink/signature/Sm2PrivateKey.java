package cc.ddrpa.crypto.tink.signature;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.signature.SignaturePrivateKey;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Represents an SM2 private key used for signing.
 */
@Immutable
public final class Sm2PrivateKey extends SignaturePrivateKey {

    private final Sm2SignatureParameters parameters;
    private final SecretBytes privateKeyValue;
    private final Sm2PublicKey publicKey;

    private Sm2PrivateKey(
            Sm2SignatureParameters parameters,
            SecretBytes privateKeyValue,
            Sm2PublicKey publicKey) {
        this.parameters = parameters;
        this.privateKeyValue = privateKeyValue;
        this.publicKey = publicKey;
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
     * Returns the underlying private key bytes.
     */
    @RestrictedApi(
            explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
            link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
            allowedOnPath = ".*Test\\.java",
            allowlistAnnotations = {AccessesPartialKey.class})
    public SecretBytes getPrivateKeyValue() {
        return privateKeyValue;
    }

    /** Returns the public key. */
    @Override
    public Sm2PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public Sm2SignatureParameters getParameters() {
        return parameters;
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
        return publicKey.getIdRequirementOrNull();
    }

    @Override
    public boolean equalsKey(Key o) {
        if (!(o instanceof Sm2PrivateKey)) {
            return false;
        }
        Sm2PrivateKey that = (Sm2PrivateKey) o;
        return Objects.equals(parameters, that.parameters)
                && privateKeyValue.equalsSecretBytes(that.privateKeyValue)
                && publicKey.equalsKey(that.publicKey);
    }

    /**
     * Builder for Sm2PrivateKey.
     */
    public static class Builder {
        @Nullable private Sm2SignatureParameters parameters = null;
        @Nullable private SecretBytes privateKeyValue = null;
        @Nullable private Sm2PublicKey publicKey = null;

        private Builder() {}

        @CanIgnoreReturnValue
        public Builder setParameters(Sm2SignatureParameters parameters) {
            this.parameters = parameters;
            return this;
        }

        @CanIgnoreReturnValue
        public Builder setPrivateKeyValue(SecretBytes privateKeyValue) {
            this.privateKeyValue = privateKeyValue;
            return this;
        }

        @CanIgnoreReturnValue
        public Builder setPublicKey(Sm2PublicKey publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public Sm2PrivateKey build() throws GeneralSecurityException {
            if (parameters == null || privateKeyValue == null || publicKey == null) {
                throw new GeneralSecurityException(
                        "Cannot build without parameters and/or key material");
            }

            if (privateKeyValue.size() != 32) {
                throw new GeneralSecurityException("SM2 private key must be 32 bytes");
            }

            if (!Objects.equals(parameters, publicKey.getParameters())) {
                throw new GeneralSecurityException(
                        "Parameters of private key and public key do not match");
            }

            return new Sm2PrivateKey(parameters, privateKeyValue, publicKey);
        }
    }
}