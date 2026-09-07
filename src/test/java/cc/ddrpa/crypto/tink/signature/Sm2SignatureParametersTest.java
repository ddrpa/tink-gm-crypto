package cc.ddrpa.crypto.tink.signature;

import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public final class Sm2SignatureParametersTest {

    private static final Sm2SignatureParameters.Variant NO_PREFIX =
            Sm2SignatureParameters.Variant.NO_PREFIX;
    private static final Sm2SignatureParameters.Variant TINK = Sm2SignatureParameters.Variant.TINK;

    @Test
    public void buildParametersWithDefaultVariant_hasNoPrefix() throws Exception {
        Sm2SignatureParameters parameters = Sm2SignatureParameters.builder().build();
        assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
        assertThat(parameters.hasIdRequirement()).isFalse();
    }

    @Test
    public void buildParametersWithNoPrefixVariant() throws Exception {
        Sm2SignatureParameters parameters =
                Sm2SignatureParameters.builder().setVariant(NO_PREFIX).build();
        assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
        assertThat(parameters.hasIdRequirement()).isFalse();
    }

    @Test
    public void buildParametersWithTinkVariant() throws Exception {
        Sm2SignatureParameters parameters =
                Sm2SignatureParameters.builder().setVariant(TINK).build();
        assertThat(parameters.getVariant()).isEqualTo(TINK);
        assertThat(parameters.hasIdRequirement()).isTrue();
    }

    @Test
    public void buildWithVariantSetToNull_fails() {
        assertThrows(GeneralSecurityException.class,
                () -> Sm2SignatureParameters.builder().setVariant(null).build());
    }

    @Test
    public void testEqualsAndEqualHashCode() throws Exception {
        Sm2SignatureParameters parameters1 =
                Sm2SignatureParameters.builder().setVariant(NO_PREFIX).build();
        Sm2SignatureParameters parameters2 =
                Sm2SignatureParameters.builder().setVariant(NO_PREFIX).build();
        assertThat(parameters1).isEqualTo(parameters2);
        assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());

        Sm2SignatureParameters tinkParameters1 =
                Sm2SignatureParameters.builder().setVariant(TINK).build();
        Sm2SignatureParameters tinkParameters2 =
                Sm2SignatureParameters.builder().setVariant(TINK).build();
        assertThat(tinkParameters1).isEqualTo(tinkParameters2);
        assertThat(tinkParameters1.hashCode()).isEqualTo(tinkParameters2.hashCode());
    }

    @Test
    public void testNotEqualAndNotEqualHashCode() throws Exception {
        Sm2SignatureParameters noPrefixParameters =
                Sm2SignatureParameters.builder().setVariant(NO_PREFIX).build();
        Sm2SignatureParameters tinkParameters =
                Sm2SignatureParameters.builder().setVariant(TINK).build();
        assertThat(noPrefixParameters).isNotEqualTo(tinkParameters);
        assertThat(noPrefixParameters.hashCode()).isNotEqualTo(tinkParameters.hashCode());
    }

    @Test
    public void testToStringContainsVariant() throws Exception {
        Sm2SignatureParameters tinkParameters =
                Sm2SignatureParameters.builder().setVariant(TINK).build();
        assertThat(tinkParameters.toString()).contains("TINK");
        Sm2SignatureParameters noPrefixParameters =
                Sm2SignatureParameters.builder().setVariant(NO_PREFIX).build();
        assertThat(noPrefixParameters.toString()).contains("NO_PREFIX");
    }
}
