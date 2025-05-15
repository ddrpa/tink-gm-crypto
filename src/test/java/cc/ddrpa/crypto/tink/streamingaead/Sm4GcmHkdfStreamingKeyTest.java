package cc.ddrpa.crypto.tink.streamingaead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;

public final class Sm4GcmHkdfStreamingKeyTest {

    @Test
    public void basicBuild_compareParameters_works() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(19)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();
        SecretBytes bytes = SecretBytes.randomBytes(19);
        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters, bytes);

        assertThat(key.getParameters()).isEqualTo(parameters);
        assertThat(key.getInitialKeyMaterial()).isEqualTo(bytes);
    }

    @Test
    public void build_wrongKeySize_throws() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(19)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();
        SecretBytes bytes = SecretBytes.randomBytes(18);
        assertThrows(
            GeneralSecurityException.class, () -> Sm4GcmHkdfStreamingKey.create(parameters, bytes));
    }

    @Test
    public void testEqualities() throws Exception {
        SecretBytes keyBytes33 = SecretBytes.randomBytes(33);
        SecretBytes keyBytes33Copy =
            SecretBytes.copyFrom(
                keyBytes33.toByteArray(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
        SecretBytes keyBytes33Diff = SecretBytes.randomBytes(33);

        Sm4GcmHkdfStreamingParameters parameters33 =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(33)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();
        Sm4GcmHkdfStreamingParameters parameters33Copy =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(33)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();
        Sm4GcmHkdfStreamingParameters parametersDifferentHashType =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(33)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA1)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();

        new KeyTester()
            .addEqualityGroup(
                "33 byte key",
                Sm4GcmHkdfStreamingKey.create(parameters33, keyBytes33),
                Sm4GcmHkdfStreamingKey.create(parameters33, keyBytes33Copy),
                Sm4GcmHkdfStreamingKey.create(parameters33Copy, keyBytes33))
            .addEqualityGroup(
                "different key",
                Sm4GcmHkdfStreamingKey.create(parameters33, keyBytes33Diff),
                Sm4GcmHkdfStreamingKey.create(parameters33Copy, keyBytes33Diff))
            .addEqualityGroup(
                "different parameters",
                Sm4GcmHkdfStreamingKey.create(parametersDifferentHashType, keyBytes33))
            .doTests();
    }

    @Test
    public void testDifferentKeyTypesEquality_fails() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(32)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();
        Sm4GcmHkdfStreamingKey key =
            Sm4GcmHkdfStreamingKey.create(parameters, SecretBytes.randomBytes(32));

        XChaCha20Poly1305Key xChaCha20Poly1305Key =
            XChaCha20Poly1305Key.create(SecretBytes.randomBytes(32));

        assertThat(key.equalsKey(xChaCha20Poly1305Key)).isFalse();
    }
}
