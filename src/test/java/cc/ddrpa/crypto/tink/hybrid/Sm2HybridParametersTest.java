package cc.ddrpa.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;

public final class Sm2HybridParametersTest {

    private static final Sm2HybridParameters.Variant NO_PREFIX =
        Sm2HybridParameters.Variant.NO_PREFIX;
    private static final Sm2HybridParameters.Variant TINK =
        Sm2HybridParameters.Variant.TINK;

    @Test
    public void buildParametersWithDefaultVariant_hasNoPrefix() throws Exception {
        Sm2HybridParameters parameters = Sm2HybridParameters.builder().build();
        assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
        assertThat(parameters.hasIdRequirement()).isFalse();
    }

    @Test
    public void buildParametersWithNoPrefixVariant() throws Exception {
        Sm2HybridParameters parameters =
            Sm2HybridParameters.builder().setVariant(NO_PREFIX).build();
        assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
        assertThat(parameters.hasIdRequirement()).isFalse();
    }

    @Test
    public void buildParametersWithTinkVariant() throws Exception {
        Sm2HybridParameters parameters =
            Sm2HybridParameters.builder().setVariant(TINK).build();
        assertThat(parameters.getVariant()).isEqualTo(TINK);
        assertThat(parameters.hasIdRequirement()).isTrue();
    }

    @Test
    public void buildWithVariantSetToNull_fails() {
        assertThrows(GeneralSecurityException.class,
            () -> Sm2HybridParameters.builder().setVariant(null).build());
    }

    @Test
    public void testEqualsAndEqualHashCode() throws Exception {
        Sm2HybridParameters parameters1 =
            Sm2HybridParameters.builder().setVariant(NO_PREFIX).build();
        Sm2HybridParameters parameters2 =
            Sm2HybridParameters.builder().setVariant(NO_PREFIX).build();
        assertThat(parameters1).isEqualTo(parameters2);
        assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());

        Sm2HybridParameters tinkParameters1 =
            Sm2HybridParameters.builder().setVariant(TINK).build();
        Sm2HybridParameters tinkParameters2 =
            Sm2HybridParameters.builder().setVariant(TINK).build();
        assertThat(tinkParameters1).isEqualTo(tinkParameters2);
        assertThat(tinkParameters1.hashCode()).isEqualTo(tinkParameters2.hashCode());
    }

    @Test
    public void testNotEqualAndNotEqualHashCode() throws Exception {
        Sm2HybridParameters noPrefixParameters =
            Sm2HybridParameters.builder().setVariant(NO_PREFIX).build();
        Sm2HybridParameters tinkParameters =
            Sm2HybridParameters.builder().setVariant(TINK).build();
        assertThat(noPrefixParameters).isNotEqualTo(tinkParameters);
        assertThat(noPrefixParameters.hashCode()).isNotEqualTo(tinkParameters.hashCode());
    }

    @Test
    public void testToStringContainsVariant() throws Exception {
        Sm2HybridParameters tinkParameters =
            Sm2HybridParameters.builder().setVariant(TINK).build();
        assertThat(tinkParameters.toString()).contains("TINK");
        Sm2HybridParameters noPrefixParameters =
            Sm2HybridParameters.builder().setVariant(NO_PREFIX).build();
        assertThat(noPrefixParameters.toString()).contains("NO_PREFIX");
    }
}
