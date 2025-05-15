package cc.ddrpa.crypto.tink.streamingaead.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKey;
import cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingParameters;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Test for Sm4GcmHkdfStreamingProtoSerialization.
 */
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
final class Sm4GcmHkdfStreamingProtoSerializationTest {

    private static final String TYPE_URL =
        "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey";
    private static final ProtoParametersSerialization[] INVALID_PARAMETERS_SERIALIZATIONS =
        new ProtoParametersSerialization[]{
            // Key size smaller than derived key size
            ProtoParametersSerialization.create(
                TYPE_URL,
                OutputPrefixType.RAW,
                cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.newBuilder()
                    .setKeySize(8)
                    .setParams(
                        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                            .setCiphertextSegmentSize(512 * 1024)
                            .setDerivedKeySize(16)
                            .setHkdfHashType(HashType.SHA1))
                    .build()),
            ProtoParametersSerialization.create(
                TYPE_URL,
                OutputPrefixType.RAW,
                cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.newBuilder()
                    .setKeySize(32)
                    .setParams(
                        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                            .setCiphertextSegmentSize(5)
                            .setDerivedKeySize(16)
                            .setHkdfHashType(HashType.SHA1))
                    .build()),
            ProtoParametersSerialization.create(
                TYPE_URL,
                OutputPrefixType.RAW,
                cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.newBuilder()
                    .setVersion(1)
                    .setKeySize(32)
                    .setParams(
                        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                            .setCiphertextSegmentSize(1024)
                            .setDerivedKeySize(16)
                            .setHkdfHashType(HashType.SHA1))
                    .build()),
            // Bad hash type
            ProtoParametersSerialization.create(
                TYPE_URL,
                OutputPrefixType.RAW,
                cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.newBuilder()
                    .setKeySize(32)
                    .setParams(
                        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                            .setCiphertextSegmentSize(5)
                            .setDerivedKeySize(16)
                            .setHkdfHashType(HashType.SHA224))
                    .build())
        };
    private static final SecretBytes KEY_BYTES_37 = SecretBytes.randomBytes(37);
    private static final ByteString KEY_BYTES_37_AS_BYTE_STRING =
        ByteString.copyFrom(KEY_BYTES_37.toByteArray(InsecureSecretKeyAccess.get()));
    private static final ProtoKeySerialization[] INVALID_KEY_SERIALIZATIONS =
        createInvalidKeySerializations();
    private static final SecretBytes KEY_BYTES_36 = SecretBytes.randomBytes(36);
    private static final ByteString KEY_BYTES_36_AS_BYTE_STRING =
        ByteString.copyFrom(KEY_BYTES_36.toByteArray(InsecureSecretKeyAccess.get()));
    private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

    @BeforeAll
    static void setUp() throws Exception {
        Sm4GcmHkdfStreamingProtoSerialization.register(registry);
    }

    private static ProtoKeySerialization[] createInvalidKeySerializations() {
        try {
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey validKey =
                cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.newBuilder()
                    .setVersion(0)
                    .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
                    .setParams(
                        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                            .setHkdfHashType(HashType.SHA512)
                            .setDerivedKeySize(16)
                            .setCiphertextSegmentSize(1024 * 1024))
                    .build();

            return new ProtoKeySerialization[]{
                // Wrong version
                ProtoKeySerialization.create(
                    "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                    validKey.toBuilder().setVersion(1).build().toByteString(),
                    KeyMaterialType.SYMMETRIC,
                    OutputPrefixType.RAW,
                    /* idRequirement= */ null),
                // Wrong Hash type
                ProtoKeySerialization.create(
                    "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                    validKey.toBuilder()
                        .setParams(
                            validKey.getParams().toBuilder().setHkdfHashType(HashType.SHA224))
                        .build()
                        .toByteString(),
                    KeyMaterialType.SYMMETRIC,
                    OutputPrefixType.RAW,
                    /* idRequirement= */ null),
                // Wrong Hash type
                ProtoKeySerialization.create(
                    "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                    validKey.toBuilder()
                        .setParams(
                            validKey.getParams().toBuilder().setHkdfHashType(HashType.SHA384))
                        .build()
                        .toByteString(),
                    KeyMaterialType.SYMMETRIC,
                    OutputPrefixType.RAW,
                    /* idRequirement= */ null),
                // Key Shorter than derivedKeySize
                ProtoKeySerialization.create(
                    "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                    validKey.toBuilder()
                        .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING.substring(0, 10))
                        .setParams(validKey.getParams().toBuilder().setDerivedKeySize(16))
                        .build()
                        .toByteString(),
                    KeyMaterialType.SYMMETRIC,
                    OutputPrefixType.RAW,
                    /* idRequirement= */ null),
                // Short CiphertextSegmentSize
                ProtoKeySerialization.create(
                    "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                    validKey.toBuilder()
                        .setParams(validKey.getParams().toBuilder().setCiphertextSegmentSize(24))
                        .build()
                        .toByteString(),
                    KeyMaterialType.SYMMETRIC,
                    OutputPrefixType.RAW,
                    /* idRequirement= */ null)
            };
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static Stream<Arguments> provideInvalidParametersSerializations() {
        return Stream.of(INVALID_PARAMETERS_SERIALIZATIONS)
            .map(Arguments::of);
    }

    private static Stream<Arguments> provideInvalidKeySerializations() {
        return Stream.of(INVALID_KEY_SERIALIZATIONS)
            .map(Arguments::of);
    }

    @Test
    void registerTwice() throws Exception {
        MutableSerializationRegistry registry = new MutableSerializationRegistry();
        Sm4GcmHkdfStreamingProtoSerialization.register(registry);
        Sm4GcmHkdfStreamingProtoSerialization.register(registry);
    }

    @Test
    void serializeParseParameters_simple() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(19)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();

        ProtoParametersSerialization serialization =
            ProtoParametersSerialization.create(
                TYPE_URL,
                OutputPrefixType.RAW,
                cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.newBuilder()
                    .setKeySize(19)
                    .setParams(
                        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                            .setCiphertextSegmentSize(1024 * 1024)
                            .setDerivedKeySize(16)
                            .setHkdfHashType(HashType.SHA256))
                    .build());

        ProtoParametersSerialization serialized =
            registry.serializeParameters(parameters, ProtoParametersSerialization.class);
        assertEqualWhenValueParsed(
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.parser(),
            serialized,
            serialization);

        Parameters parsed = registry.parseParameters(serialization);
        assertThat(parsed).isEqualTo(parameters);
    }

    @Test
    void serializeParseParameters_differentKeySize() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();

        ProtoParametersSerialization serialization =
            ProtoParametersSerialization.create(
                TYPE_URL,
                OutputPrefixType.RAW,
                cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.newBuilder()
                    .setKeySize(37)
                    .setParams(
                        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                            .setCiphertextSegmentSize(1024 * 1024)
                            .setDerivedKeySize(16)
                            .setHkdfHashType(HashType.SHA256))
                    .build());

        ProtoParametersSerialization serialized =
            registry.serializeParameters(parameters, ProtoParametersSerialization.class);
        assertEqualWhenValueParsed(
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.parser(),
            serialized,
            serialization);

        Parameters parsed = registry.parseParameters(serialization);
        assertThat(parsed).isEqualTo(parameters);
    }

    @Test
    void serializeParseParameters_differentDerivedKeySize() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();

        ProtoParametersSerialization serialization =
            ProtoParametersSerialization.create(
                TYPE_URL,
                OutputPrefixType.RAW,
                cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.newBuilder()
                    .setKeySize(37)
                    .setParams(
                        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                            .setCiphertextSegmentSize(1024 * 1024)
                            .setDerivedKeySize(16)
                            .setHkdfHashType(HashType.SHA256))
                    .build());

        ProtoParametersSerialization serialized =
            registry.serializeParameters(parameters, ProtoParametersSerialization.class);
        assertEqualWhenValueParsed(
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.parser(),
            serialized,
            serialization);

        Parameters parsed = registry.parseParameters(serialization);
        assertThat(parsed).isEqualTo(parameters);
    }

    @Test
    void serializeParseParameters_differentHashType() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA512)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();

        ProtoParametersSerialization serialization =
            ProtoParametersSerialization.create(
                TYPE_URL,
                OutputPrefixType.RAW,
                cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.newBuilder()
                    .setKeySize(37)
                    .setParams(
                        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                            .setCiphertextSegmentSize(1024 * 1024)
                            .setDerivedKeySize(16)
                            .setHkdfHashType(HashType.SHA512))
                    .build());

        ProtoParametersSerialization serialized =
            registry.serializeParameters(parameters, ProtoParametersSerialization.class);
        assertEqualWhenValueParsed(
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.parser(),
            serialized,
            serialization);

        Parameters parsed = registry.parseParameters(serialization);
        assertThat(parsed).isEqualTo(parameters);
    }

    @Test
    void serializeParseParameters_differentCiphertextSegmentSizeType() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA512)
                .setCiphertextSegmentSizeBytes(512 * 1024)
                .build();

        ProtoParametersSerialization serialization =
            ProtoParametersSerialization.create(
                TYPE_URL,
                OutputPrefixType.RAW,
                cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.newBuilder()
                    .setKeySize(37)
                    .setParams(
                        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                            .setCiphertextSegmentSize(512 * 1024)
                            .setDerivedKeySize(16)
                            .setHkdfHashType(HashType.SHA512))
                    .build());

        ProtoParametersSerialization serialized =
            registry.serializeParameters(parameters, ProtoParametersSerialization.class);
        assertEqualWhenValueParsed(
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.parser(),
            serialized,
            serialization);

        Parameters parsed = registry.parseParameters(serialization);
        assertThat(parsed).isEqualTo(parameters);
    }

    /**
     * Test that if "OutputPrefixType" is set to Tink, we just ignore it.
     */
    @Test
    void parseParameters_outputPrefixIgnored_tink() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA512)
                .setCiphertextSegmentSizeBytes(512 * 1024)
                .build();

        ProtoParametersSerialization serialization =
            ProtoParametersSerialization.create(
                TYPE_URL,
                OutputPrefixType.TINK,
                cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.newBuilder()
                    .setKeySize(37)
                    .setParams(
                        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                            .setCiphertextSegmentSize(512 * 1024)
                            .setDerivedKeySize(16)
                            .setHkdfHashType(HashType.SHA512))
                    .build());

        Parameters parsed = registry.parseParameters(serialization);
        assertThat(parsed).isEqualTo(parameters);
    }

    /**
     * Test that if "OutputPrefixType" is set to CRUNCHY, we just ignore it.
     */
    @Test
    void parseParameters_outputPrefixIgnored_crunchy() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA512)
                .setCiphertextSegmentSizeBytes(512 * 1024)
                .build();

        ProtoParametersSerialization serialization =
            ProtoParametersSerialization.create(
                TYPE_URL,
                OutputPrefixType.CRUNCHY,
                cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.newBuilder()
                    .setKeySize(37)
                    .setParams(
                        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                            .setCiphertextSegmentSize(512 * 1024)
                            .setDerivedKeySize(16)
                            .setHkdfHashType(HashType.SHA512))
                    .build());

        Parameters parsed = registry.parseParameters(serialization);
        assertThat(parsed).isEqualTo(parameters);
    }

    @Test
    void parseParameters_outputPrefixIgnored_legacy() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA512)
                .setCiphertextSegmentSizeBytes(512 * 1024)
                .build();

        ProtoParametersSerialization serialization =
            ProtoParametersSerialization.create(
                TYPE_URL,
                OutputPrefixType.LEGACY,
                cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.newBuilder()
                    .setKeySize(37)
                    .setParams(
                        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                            .setCiphertextSegmentSize(512 * 1024)
                            .setDerivedKeySize(16)
                            .setHkdfHashType(HashType.SHA512))
                    .build());

        Parameters parsed = registry.parseParameters(serialization);
        assertThat(parsed).isEqualTo(parameters);
    }

    @ParameterizedTest
    @MethodSource("provideInvalidParametersSerializations")
    void testParseInvalidParameters_fails(ProtoParametersSerialization serializedParameters)
        throws Exception {
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseParameters(serializedParameters));
    }

    @Test
    void serializeParseKey_simple() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA512)
                .setCiphertextSegmentSizeBytes(512 * 1024)
                .build();

        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters, KEY_BYTES_37);

        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey protoKey =
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
                .setParams(
                    cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                        .setHkdfHashType(HashType.SHA512)
                        .setDerivedKeySize(16)
                        .setCiphertextSegmentSize(512 * 1024))
                .build();

        ProtoKeySerialization serialization =
            ProtoKeySerialization.create(
                "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                protoKey.toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.RAW,
                /* idRequirement= */ null);

        ProtoKeySerialization serialized =
            registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
        assertEqualWhenValueParsed(
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.parser(), serialized, serialization);

        Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @Test
    void serializeParseKey_differentKeySizeBytes() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(36)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA512)
                .setCiphertextSegmentSizeBytes(512 * 1024)
                .build();

        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters, KEY_BYTES_36);

        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey protoKey =
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_36_AS_BYTE_STRING)
                .setParams(
                    cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                        .setHkdfHashType(HashType.SHA512)
                        .setDerivedKeySize(16)
                        .setCiphertextSegmentSize(512 * 1024))
                .build();

        ProtoKeySerialization serialization =
            ProtoKeySerialization.create(
                "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                protoKey.toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.RAW,
                /* idRequirement= */ null);

        ProtoKeySerialization serialized =
            registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
        assertEqualWhenValueParsed(
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.parser(), serialized, serialization);

        Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @Test
    void serializeParseKey_differentDerivedKeySize() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA512)
                .setCiphertextSegmentSizeBytes(512 * 1024)
                .build();

        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters, KEY_BYTES_37);

        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey protoKey =
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
                .setParams(
                    cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                        .setHkdfHashType(HashType.SHA512)
                        .setDerivedKeySize(16)
                        .setCiphertextSegmentSize(512 * 1024))
                .build();

        ProtoKeySerialization serialization =
            ProtoKeySerialization.create(
                "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                protoKey.toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.RAW,
                /* idRequirement= */ null);

        ProtoKeySerialization serialized =
            registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
        assertEqualWhenValueParsed(
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.parser(), serialized, serialization);

        Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @Test
    void serializeParseKey_differentHkdfHashType() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA1)
                .setCiphertextSegmentSizeBytes(512 * 1024)
                .build();

        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters, KEY_BYTES_37);

        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey protoKey =
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
                .setParams(
                    cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                        .setHkdfHashType(HashType.SHA1)
                        .setDerivedKeySize(16)
                        .setCiphertextSegmentSize(512 * 1024))
                .build();

        ProtoKeySerialization serialization =
            ProtoKeySerialization.create(
                "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                protoKey.toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.RAW,
                /* idRequirement= */ null);

        ProtoKeySerialization serialized =
            registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
        assertEqualWhenValueParsed(
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.parser(), serialized, serialization);

        Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @Test
    void serializeParseKey_differentCiphertextSegmentSize() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA512)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();

        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters, KEY_BYTES_37);

        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey protoKey =
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
                .setParams(
                    cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                        .setHkdfHashType(HashType.SHA512)
                        .setDerivedKeySize(16)
                        .setCiphertextSegmentSize(1024 * 1024))
                .build();

        ProtoKeySerialization serialization =
            ProtoKeySerialization.create(
                "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                protoKey.toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.RAW,
                /* idRequirement= */ null);

        ProtoKeySerialization serialized =
            registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
        assertEqualWhenValueParsed(
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.parser(), serialized, serialization);

        Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @Test
    void parseKey_ignoreOutputPrefixType_crunchy() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA512)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();

        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters, KEY_BYTES_37);

        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey protoKey =
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
                .setParams(
                    cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                        .setHkdfHashType(HashType.SHA512)
                        .setDerivedKeySize(16)
                        .setCiphertextSegmentSize(1024 * 1024))
                .build();

        ProtoKeySerialization serialization =
            ProtoKeySerialization.create(
                "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                protoKey.toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.CRUNCHY,
                123);

        Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @Test
    void parseKey_ignoreOutputPrefixType_tink() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA512)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();

        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters, KEY_BYTES_37);

        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey protoKey =
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
                .setParams(
                    cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                        .setHkdfHashType(HashType.SHA512)
                        .setDerivedKeySize(16)
                        .setCiphertextSegmentSize(1024 * 1024))
                .build();

        ProtoKeySerialization serialization =
            ProtoKeySerialization.create(
                "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                protoKey.toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.TINK,
                123);

        Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @Test
    void parseKey_ignoreOutputPrefixType_legacy() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters =
            Sm4GcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(37)
                .setDerivedSm4GcmKeySizeBytes(16)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA512)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build();

        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters, KEY_BYTES_37);

        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey protoKey =
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
                .setParams(
                    cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
                        .setHkdfHashType(HashType.SHA512)
                        .setDerivedKeySize(16)
                        .setCiphertextSegmentSize(1024 * 1024))
                .build();

        ProtoKeySerialization serialization =
            ProtoKeySerialization.create(
                "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                protoKey.toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.LEGACY,
                123);

        Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @ParameterizedTest
    @MethodSource("provideInvalidKeySerializations")
    void testParseInvalidKeys_throws(ProtoKeySerialization serialization) {
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
    }
}
