package cc.ddrpa.crypto.tink.aead.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cc.ddrpa.crypto.tink.aead.Sm4GcmKey;
import cc.ddrpa.crypto.tink.aead.Sm4GcmParameters;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Test for Sm4GcmSerialization.
 */
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
class Sm4GcmProtoSerializationTest {

    private static final String TYPE_URL = "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmKey";

    private static final SecretBytes KEY_BYTES_16 = SecretBytes.randomBytes(16);
    private static final ByteString KEY_BYTES_16_AS_BYTE_STRING = ByteString.copyFrom(
        KEY_BYTES_16.toByteArray(InsecureSecretKeyAccess.get()));

    private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

    @BeforeAll
    static void setUp() throws Exception {
        Sm4GcmProtoSerialization.register(registry);
    }

    private static Stream<ProtoParametersSerialization> invalidParametersSerializations() {
        return Stream.of(
            // Unknown output prefix
            ProtoParametersSerialization.create(TYPE_URL, OutputPrefixType.UNKNOWN_PREFIX,
                cc.ddrpa.crypto.tink.proto.Sm4GcmKeyFormat.newBuilder().build()),
            // Bad version
            ProtoParametersSerialization.create(TYPE_URL, OutputPrefixType.RAW,
                cc.ddrpa.crypto.tink.proto.Sm4GcmKeyFormat.newBuilder().setVersion(1)
                    .build()));
    }

    private static Stream<ProtoKeySerialization> invalidKeySerializations() {
        try {
            return Stream.of(
                // Bad Version Number (1)
                ProtoKeySerialization.create(TYPE_URL,
                    cc.ddrpa.crypto.tink.proto.Sm4GcmKey.newBuilder().setVersion(1)
                        .setKeyValue(KEY_BYTES_16_AS_BYTE_STRING).build().toByteString(),
                    KeyMaterialType.SYMMETRIC, OutputPrefixType.TINK, 1479),
                // Unknown prefix
                ProtoKeySerialization.create(TYPE_URL,
                    cc.ddrpa.crypto.tink.proto.Sm4GcmKey.newBuilder().setVersion(0)
                        .setKeyValue(KEY_BYTES_16_AS_BYTE_STRING).build().toByteString(),
                    KeyMaterialType.SYMMETRIC, OutputPrefixType.UNKNOWN_PREFIX, 1479));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void registerTwice() throws Exception {
        MutableSerializationRegistry registry = new MutableSerializationRegistry();
        Sm4GcmProtoSerialization.register(registry);
        Sm4GcmProtoSerialization.register(registry);
    }

    @Test
    void serializeParseParameters_noPrefix() throws Exception {
        Sm4GcmParameters parameters = Sm4GcmParameters.builder().setTagSizeBytes(16)
            .setIvSizeBytes(12).setVariant(Sm4GcmParameters.Variant.NO_PREFIX).build();

        ProtoParametersSerialization serialization = ProtoParametersSerialization.create(
            "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmKey", OutputPrefixType.RAW,
            cc.ddrpa.crypto.tink.proto.Sm4GcmKeyFormat.newBuilder().build());

        ProtoParametersSerialization serialized = registry.serializeParameters(parameters,
            ProtoParametersSerialization.class);
        assertEqualWhenValueParsed(cc.ddrpa.crypto.tink.proto.Sm4GcmKeyFormat.parser(),
            serialized, serialization);

        Parameters parsed = registry.parseParameters(serialization);
        assertThat(parsed).isEqualTo(parameters);
    }

    @Test
    void serializeParseParameters_tink() throws Exception {
        Sm4GcmParameters parameters = Sm4GcmParameters.builder().setTagSizeBytes(16)
            .setIvSizeBytes(12).setVariant(Sm4GcmParameters.Variant.TINK).build();

        ProtoParametersSerialization serialization = ProtoParametersSerialization.create(
            "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmKey", OutputPrefixType.TINK,
            cc.ddrpa.crypto.tink.proto.Sm4GcmKeyFormat.newBuilder().build());

        ProtoParametersSerialization serialized = registry.serializeParameters(parameters,
            ProtoParametersSerialization.class);
        assertEqualWhenValueParsed(cc.ddrpa.crypto.tink.proto.Sm4GcmKeyFormat.parser(),
            serialized, serialization);

        Parameters parsed = registry.parseParameters(serialization);
        assertThat(parsed).isEqualTo(parameters);
    }

    @Test
    void serializeParameters_badTagSize_fails() throws Exception {
        Sm4GcmParameters parameters = Sm4GcmParameters.builder().setTagSizeBytes(12)
            .setIvSizeBytes(12).setVariant(Sm4GcmParameters.Variant.NO_PREFIX).build();

        // Fails when tag size is not a 16-byte value
        assertThrows(GeneralSecurityException.class,
            () -> registry.serializeParameters(parameters, ProtoParametersSerialization.class));
    }

    @Test
    void serializeParameters_badIvSize_fails() throws Exception {
        Sm4GcmParameters parameters = Sm4GcmParameters.builder().setTagSizeBytes(16)
            .setIvSizeBytes(16).setVariant(Sm4GcmParameters.Variant.NO_PREFIX).build();

        // Fails when IV size is not a 12-byte value
        assertThrows(GeneralSecurityException.class,
            () -> registry.serializeParameters(parameters, ProtoParametersSerialization.class));
    }

    @Test
    void serializeParseKey_noPrefix() throws Exception {
        Sm4GcmParameters parameters = Sm4GcmParameters.builder().setTagSizeBytes(16)
            .setIvSizeBytes(12).setVariant(Sm4GcmParameters.Variant.NO_PREFIX).build();

        Sm4GcmKey key = Sm4GcmKey.builder().setParameters(parameters).setKeyBytes(KEY_BYTES_16)
            .build();

        cc.ddrpa.crypto.tink.proto.Sm4GcmKey protoSm4GcmKey = cc.ddrpa.crypto.tink.proto.Sm4GcmKey.newBuilder()
            .setVersion(0).setKeyValue(KEY_BYTES_16_AS_BYTE_STRING).build();

        ProtoKeySerialization serialization = ProtoKeySerialization.create(
            "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmKey", protoSm4GcmKey.toByteString(),
            KeyMaterialType.SYMMETRIC, OutputPrefixType.RAW,
            /* idRequirement= */ null);

        ProtoKeySerialization serialized = registry.serializeKey(key, ProtoKeySerialization.class,
            InsecureSecretKeyAccess.get());
        assertEqualWhenValueParsed(cc.ddrpa.crypto.tink.proto.Sm4GcmKey.parser(), serialized,
            serialization);

        Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @Test
    void serializeParseKey_tink() throws Exception {
        Sm4GcmParameters parameters = Sm4GcmParameters.builder().setTagSizeBytes(16)
            .setIvSizeBytes(12).setVariant(Sm4GcmParameters.Variant.TINK).build();

        Sm4GcmKey key = Sm4GcmKey.builder().setParameters(parameters).setKeyBytes(KEY_BYTES_16)
            .setIdRequirement(123).build();

        cc.ddrpa.crypto.tink.proto.Sm4GcmKey protoSm4GcmKey = cc.ddrpa.crypto.tink.proto.Sm4GcmKey.newBuilder()
            .setVersion(0).setKeyValue(KEY_BYTES_16_AS_BYTE_STRING).build();

        ProtoKeySerialization serialization = ProtoKeySerialization.create(
            "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmKey", protoSm4GcmKey.toByteString(),
            KeyMaterialType.SYMMETRIC, OutputPrefixType.TINK,
            /* idRequirement= */ 123);

        ProtoKeySerialization serialized = registry.serializeKey(key, ProtoKeySerialization.class,
            InsecureSecretKeyAccess.get());
        assertEqualWhenValueParsed(cc.ddrpa.crypto.tink.proto.Sm4GcmKey.parser(), serialized,
            serialization);

        Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @Test
    void testParseKeys_noAccess_throws() throws Exception {
        cc.ddrpa.crypto.tink.proto.Sm4GcmKey protoSm4GcmKey = cc.ddrpa.crypto.tink.proto.Sm4GcmKey.newBuilder()
            .setVersion(0).setKeyValue(KEY_BYTES_16_AS_BYTE_STRING).build();
        ProtoKeySerialization serialization = ProtoKeySerialization.create(
            "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmKey", protoSm4GcmKey.toByteString(),
            KeyMaterialType.SYMMETRIC, OutputPrefixType.TINK,
            /* idRequirement= */ 123);
        assertThrows(GeneralSecurityException.class, () -> registry.parseKey(serialization, null));
    }

    @Test
    void testSerializeKeys_noAccess_throws() throws Exception {
        Sm4GcmParameters parameters = Sm4GcmParameters.builder().setIvSizeBytes(12)
            .setTagSizeBytes(16).setVariant(Sm4GcmParameters.Variant.TINK).build();
        Sm4GcmKey key = Sm4GcmKey.builder().setParameters(parameters).setKeyBytes(KEY_BYTES_16)
            .setIdRequirement(123).build();
        assertThrows(GeneralSecurityException.class,
            () -> registry.serializeKey(key, ProtoKeySerialization.class, null));
    }

    @ParameterizedTest
    @MethodSource("invalidParametersSerializations")
    void testParseInvalidParameters_fails(
        ProtoParametersSerialization serializedParameters) {
        assertThrows(GeneralSecurityException.class,
            () -> registry.parseParameters(serializedParameters));
    }

    @ParameterizedTest
    @MethodSource("invalidKeySerializations")
    void testParseInvalidKeys_throws(ProtoKeySerialization serialization) {
        assertThrows(GeneralSecurityException.class,
            () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
    }
}
