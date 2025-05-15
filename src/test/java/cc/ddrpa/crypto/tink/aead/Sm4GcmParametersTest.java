package cc.ddrpa.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.security.GeneralSecurityException;
import org.junit.Test;

public final class Sm4GcmParametersTest {

    private static final Sm4GcmParameters.Variant NO_PREFIX = Sm4GcmParameters.Variant.NO_PREFIX;
    private static final Sm4GcmParameters.Variant TINK = Sm4GcmParameters.Variant.TINK;

    @Test
    public void buildParametersAndGetProperties() throws Exception {
        Sm4GcmParameters parameters = Sm4GcmParameters.builder().setIvSizeBytes(16)
            .setTagSizeBytes(16).setVariant(NO_PREFIX).build();
        assertThat(parameters.getKeySizeBytes()).isEqualTo(16);
        assertThat(parameters.getIvSizeBytes()).isEqualTo(16);
        assertThat(parameters.getTagSizeBytes()).isEqualTo(16);
        assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
        assertThat(parameters.hasIdRequirement()).isFalse();
    }

    @Test
    public void buildParametersWithoutSettingVariant_hasNoPrefix() throws Exception {
        Sm4GcmParameters parameters = Sm4GcmParameters.builder().setIvSizeBytes(16)
            .setTagSizeBytes(16).build();
        assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
        assertThat(parameters.hasIdRequirement()).isFalse();
    }

    @Test
    public void buildParametersWithoutSettingIvSize_fails() {
        assertThrows(GeneralSecurityException.class,
            () -> Sm4GcmParameters.builder().setTagSizeBytes(16).setVariant(NO_PREFIX).build());
    }

    @Test
    public void buildParametersWithoutSettingTagSize_fails() {
        assertThrows(GeneralSecurityException.class,
            () -> Sm4GcmParameters.builder().setIvSizeBytes(16).setVariant(NO_PREFIX).build());
    }

    @Test
    public void buildWithVariantSetToNull_fails() {
        assertThrows(GeneralSecurityException.class,
            () -> Sm4GcmParameters.builder().setIvSizeBytes(16).setTagSizeBytes(16).setVariant(null)
                .build());
    }

    @Test
    public void buildParametersWithTinkPrefix() throws Exception {
        Sm4GcmParameters parameters = Sm4GcmParameters.builder().setIvSizeBytes(16)
            .setTagSizeBytes(16).setVariant(TINK).build();
        assertThat(parameters.getKeySizeBytes()).isEqualTo(16);
        assertThat(parameters.getVariant()).isEqualTo(TINK);
        assertThat(parameters.hasIdRequirement()).isTrue();
    }

    @Test
    public void testEqualsAndEqualHashCode() throws Exception {
        Sm4GcmParameters parameters1 = Sm4GcmParameters.builder().setIvSizeBytes(16)
            .setTagSizeBytes(16).setVariant(NO_PREFIX).build();
        Sm4GcmParameters parameters2 = Sm4GcmParameters.builder().setIvSizeBytes(16)
            .setTagSizeBytes(16).setVariant(NO_PREFIX).build();
        assertThat(parameters1).isEqualTo(parameters2);
        assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
    }

    @Test
    public void buildParametersWithBadTagSizeFails() {
        assertThrows(GeneralSecurityException.class,
            () -> Sm4GcmParameters.builder().setIvSizeBytes(16).setTagSizeBytes(17)
                .setVariant(NO_PREFIX).build());
    }

    @Test
    public void buildParametersWithBadIvSizeFails() {
        assertThrows(GeneralSecurityException.class,
            () -> Sm4GcmParameters.builder().setIvSizeBytes(0).setTagSizeBytes(17)
                .setVariant(NO_PREFIX).build());
    }

    @Test
    public void testNotEqualandNotEqualHashCode() throws Exception {
        Sm4GcmParameters parameters1 = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX).build();

        Sm4GcmParameters parameters2 = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(14)
            .setVariant(NO_PREFIX).build();

        assertThat(parameters1).isNotEqualTo(parameters2);
        assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

        parameters2 = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(TINK).build();

        assertThat(parameters1).isNotEqualTo(parameters2);
        assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
    }
}
