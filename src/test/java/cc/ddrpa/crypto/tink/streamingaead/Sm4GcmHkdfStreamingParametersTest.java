package cc.ddrpa.crypto.tink.streamingaead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;

final class Sm4GcmHkdfStreamingParametersTest {

    @Test
    void buildParametersAndGetProperties() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(19)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();
        assertThat(parameters.getKeySizeBytes()).isEqualTo(19);
        assertThat(parameters.getDerivedSm4GcmKeySizeBytes()).isEqualTo(16);
        assertThat(parameters.getCiphertextSegmentSizeBytes()).isEqualTo(1024 * 1024);
        assertThat(parameters.getHkdfHashType())
            .isEqualTo(Sm4GcmHkdfStreamingParameters.HashType.SHA256);
        assertThat(parameters.hasIdRequirement()).isFalse();
    }

    @Test
    void buildParametersWithoutSettingKeySize_fails() {
        Sm4GcmHkdfStreamingParameters.Builder builder =
            Sm4GcmHkdfStreamingParameters.builder()
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024);
        assertThrows(GeneralSecurityException.class, builder::build);
    }

    @Test
    void buildParametersWithoutSettingDerivedKeySize_fails() {
        Sm4GcmHkdfStreamingParameters.Builder builder =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024);
        assertThrows(GeneralSecurityException.class, builder::build);
    }

    @Test
    void buildParametersWithoutSettingHashType_fails() {
        Sm4GcmHkdfStreamingParameters.Builder builder =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(16)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setCiphertextSegmentSizeBytes(1024 * 1024);
        assertThrows(GeneralSecurityException.class, builder::build);
    }

    @Test
    void buildParametersWithoutSettingCiphertextSegmentSize_fails() {
        Sm4GcmHkdfStreamingParameters.Builder builder =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(16)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256);
        assertThrows(GeneralSecurityException.class, builder::build);
    }

    @Test
    void testEqualities() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(16)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();

        Sm4GcmHkdfStreamingParameters parametersCopy =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(16)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();

        Sm4GcmHkdfStreamingParameters parametersDifferentKeySize =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(32)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();

        Sm4GcmHkdfStreamingParameters parametersDifferentHashType =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(16)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA1)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();

        Sm4GcmHkdfStreamingParameters parametersDifferentCiphertextSegmentSize =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(16)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(2 * 1024 * 1024)
                .build();

        assertThat(parameters).isEqualTo(parametersCopy);
        assertThat(parameters).isNotEqualTo(parametersDifferentKeySize);
        assertThat(parameters).isNotEqualTo(parametersDifferentHashType);
        assertThat(parameters).isNotEqualTo(parametersDifferentCiphertextSegmentSize);
    }
}
