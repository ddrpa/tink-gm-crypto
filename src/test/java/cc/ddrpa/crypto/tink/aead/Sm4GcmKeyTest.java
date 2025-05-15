package cc.ddrpa.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;

public final class Sm4GcmKeyTest {

    @Test
    public void buildNoPrefixVariantAndGetProperties() throws Exception {
        Sm4GcmParameters parameters = Sm4GcmParameters.builder().setIvSizeBytes(16)
            .setTagSizeBytes(16).setVariant(Sm4GcmParameters.Variant.NO_PREFIX).build();
        assertThat(parameters.hasIdRequirement()).isFalse();
        SecretBytes keyBytes = SecretBytes.randomBytes(16);
        Sm4GcmKey key = Sm4GcmKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
        assertThat(key.getParameters()).isEqualTo(parameters);
        assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
        assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[]{}));
        assertThat(key.getIdRequirementOrNull()).isNull();
    }

    @Test
    public void buildTinkVariantAndGetProperties() throws Exception {
        Sm4GcmParameters parameters = Sm4GcmParameters.builder().setIvSizeBytes(16)
            .setTagSizeBytes(16).setVariant(Sm4GcmParameters.Variant.TINK).build();
        assertThat(parameters.hasIdRequirement()).isTrue();
        SecretBytes keyBytes = SecretBytes.randomBytes(16);
        Sm4GcmKey key = Sm4GcmKey.builder().setParameters(parameters).setKeyBytes(keyBytes)
            .setIdRequirement(0x66AABBCC).build();
        assertThat(key.getParameters()).isEqualTo(parameters);
        assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
        assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
        assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
    }

    @Test
    public void emptyBuild_fails() {
        assertThrows(GeneralSecurityException.class, () -> Sm4GcmKey.builder().build());
    }

    @Test
    public void buildWithoutParameters_fails() {
        assertThrows(GeneralSecurityException.class,
            () -> Sm4GcmKey.builder().setKeyBytes(SecretBytes.randomBytes(32)).build());
    }

    @Test
    public void buildWithoutKeyBytes_fails() throws Exception {
        Sm4GcmParameters parameters = Sm4GcmParameters.builder().setIvSizeBytes(16)
            .setTagSizeBytes(16).setVariant(Sm4GcmParameters.Variant.NO_PREFIX).build();
        assertThrows(GeneralSecurityException.class,
            () -> Sm4GcmKey.builder().setParameters(parameters).build());
    }

    @Test
    public void paramtersRequireIdButIdIsNotSetInBuild_fails() throws Exception {
        Sm4GcmParameters parametersWithIdRequirement = Sm4GcmParameters.builder().setIvSizeBytes(16)
            .setTagSizeBytes(16).setVariant(Sm4GcmParameters.Variant.TINK).build();
        assertThat(parametersWithIdRequirement.hasIdRequirement()).isTrue();
        assertThrows(GeneralSecurityException.class,
            () -> Sm4GcmKey.builder().setKeyBytes(SecretBytes.randomBytes(16))
                .setParameters(parametersWithIdRequirement).build());
    }
}
