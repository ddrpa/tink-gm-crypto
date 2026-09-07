package cc.ddrpa.crypto.tink.hybrid;

import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public final class Sm2EncryptionParametersTest {

    private static final Sm2EncryptionParameters.Variant NO_PREFIX =
            Sm2EncryptionParameters.Variant.NO_PREFIX;
    private static final Sm2EncryptionParameters.Variant TINK =
            Sm2EncryptionParameters.Variant.TINK;

    @Test
    public void buildParametersWithDefaultVariant_hasNoPrefix() throws Exception {
        Sm2EncryptionParameters parameters = Sm2EncryptionParameters.builder().build();
        assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
        assertThat(parameters.hasIdRequirement()).isFalse();
    }

    @Test
    public void buildParametersWithNoPrefixVariant() throws Exception {
        Sm2EncryptionParameters parameters =
                Sm2EncryptionParameters.builder().setVariant(NO_PREFIX).build();
        assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
        assertThat(parameters.hasIdRequirement()).isFalse();
    }

    @Test
    public void buildParametersWithTinkVariant() throws Exception {
        Sm2EncryptionParameters parameters =
                Sm2EncryptionParameters.builder().setVariant(TINK).build();
        assertThat(parameters.getVariant()).isEqualTo(TINK);
        assertThat(parameters.hasIdRequirement()).isTrue();
    }

    @Test
    public void buildWithVariantSetToNull_fails() {
        assertThrows(GeneralSecurityException.class,
                () -> Sm2EncryptionParameters.builder().setVariant(null).build());
    }

    @Test
    public void testEqualsAndEqualHashCode() throws Exception {
        Sm2EncryptionParameters parameters1 =
                Sm2EncryptionParameters.builder().setVariant(NO_PREFIX).build();
        Sm2EncryptionParameters parameters2 =
                Sm2EncryptionParameters.builder().setVariant(NO_PREFIX).build();
        assertThat(parameters1).isEqualTo(parameters2);
        assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());

        Sm2EncryptionParameters tinkParameters1 =
                Sm2EncryptionParameters.builder().setVariant(TINK).build();
        Sm2EncryptionParameters tinkParameters2 =
                Sm2EncryptionParameters.builder().setVariant(TINK).build();
        assertThat(tinkParameters1).isEqualTo(tinkParameters2);
        assertThat(tinkParameters1.hashCode()).isEqualTo(tinkParameters2.hashCode());
    }

    @Test
    public void testNotEqualAndNotEqualHashCode() throws Exception {
        Sm2EncryptionParameters noPrefixParameters =
                Sm2EncryptionParameters.builder().setVariant(NO_PREFIX).build();
        Sm2EncryptionParameters tinkParameters =
                Sm2EncryptionParameters.builder().setVariant(TINK).build();
        assertThat(noPrefixParameters).isNotEqualTo(tinkParameters);
        assertThat(noPrefixParameters.hashCode()).isNotEqualTo(tinkParameters.hashCode());
    }

    @Test
    public void testToStringContainsVariant() throws Exception {
        Sm2EncryptionParameters tinkParameters =
                Sm2EncryptionParameters.builder().setVariant(TINK).build();
        assertThat(tinkParameters.toString()).contains("TINK");
        Sm2EncryptionParameters noPrefixParameters =
                Sm2EncryptionParameters.builder().setVariant(NO_PREFIX).build();
        assertThat(noPrefixParameters.toString()).contains("NO_PREFIX");
    }
}
