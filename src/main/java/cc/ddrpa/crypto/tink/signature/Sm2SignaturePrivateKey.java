package cc.ddrpa.crypto.tink.signature;

import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.signature.SignaturePrivateKey;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Represents a key for computing SM2 signatures.
 *
 * <p>The private key material is the 32-byte big-endian scalar {@code d} with {@code 1 <= d < n},
 * where {@code n} is the order of the {@code sm2p256v1} curve base point.
 */
@Immutable
public final class Sm2SignaturePrivateKey extends SignaturePrivateKey {

    private final Sm2SignaturePublicKey publicKey;
    private final SecretBytes privateValue;

    private Sm2SignaturePrivateKey(Sm2SignaturePublicKey publicKey, SecretBytes privateValue) {
        this.publicKey = publicKey;
        this.privateValue = privateValue;
    }

    @RestrictedApi(
        explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
        link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
        allowedOnPath = ".*Test\\.java",
        allowlistAnnotations = {AccessesPartialKey.class})
    public static Sm2SignaturePrivateKey.Builder builder() {
        return new Sm2SignaturePrivateKey.Builder();
    }

    @Override
    public Sm2SignatureParameters getParameters() {
        return publicKey.getParameters();
    }

    @Override
    public Sm2SignaturePublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Returns the underlying private key material: the 32-byte big-endian scalar {@code d}.
     */
    @RestrictedApi(
        explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
        link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
        allowedOnPath = ".*Test\\.java",
        allowlistAnnotations = {AccessesPartialKey.class})
    public SecretBytes getPrivateValue() {
        return privateValue;
    }

    @Override
    public boolean equalsKey(Key o) {
        if (!(o instanceof Sm2SignaturePrivateKey)) {
            return false;
        }
        Sm2SignaturePrivateKey that = (Sm2SignaturePrivateKey) o;
        return that.publicKey.equalsKey(publicKey)
            && privateValue.equalsSecretBytes(that.privateValue);
    }

    /**
     * Builder for Sm2SignaturePrivateKey.
     */
    public static class Builder {

        @Nullable
        private Sm2SignaturePublicKey publicKey = null;
        @Nullable
        private SecretBytes privateValue = null;

        private Builder() {
        }

        @CanIgnoreReturnValue
        public Sm2SignaturePrivateKey.Builder setPublicKey(Sm2SignaturePublicKey publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        /**
         * Sets the private key material: the 32-byte big-endian scalar {@code d} with {@code 1 <=
         * d < n}.
         */
        @CanIgnoreReturnValue
        public Sm2SignaturePrivateKey.Builder setPrivateValue(SecretBytes privateValue) {
            this.privateValue = privateValue;
            return this;
        }

        @AccessesPartialKey
        public Sm2SignaturePrivateKey build() throws GeneralSecurityException {
            if (publicKey == null) {
                throw new GeneralSecurityException(
                    "Cannot build without an SM2 signature public key");
            }
            if (privateValue == null) {
                throw new GeneralSecurityException("Cannot build without a private value");
            }
            // Validates that the private value is exactly 32 bytes and that the scalar lies in
            // [1, n-1], where n is the order of the sm2p256v1 base point.
            Sm2KeyUtil.validatePrivateScalar(
                privateValue.toByteArray(InsecureSecretKeyAccess.get()));
            return new Sm2SignaturePrivateKey(publicKey, privateValue);
        }
    }
}
