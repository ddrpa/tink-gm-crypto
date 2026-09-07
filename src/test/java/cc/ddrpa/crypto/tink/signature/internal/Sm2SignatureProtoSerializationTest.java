package cc.ddrpa.crypto.tink.signature.internal;

import cc.ddrpa.crypto.tink.signature.Sm2SignatureParameters;
import cc.ddrpa.crypto.tink.signature.Sm2SignaturePrivateKey;
import cc.ddrpa.crypto.tink.signature.Sm2SignaturePublicKey;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2Curve;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.*;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.GeneralSecurityException;
import java.util.stream.Stream;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for Sm2SignatureProtoSerialization.
 */
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
class Sm2SignatureProtoSerializationTest {

    private static final String PRIVATE_TYPE_URL =
            "type.googleapis.com/ddrpa.crypto.tink.Sm2SignaturePrivateKey";
    private static final String PUBLIC_TYPE_URL =
            "type.googleapis.com/ddrpa.crypto.tink.Sm2SignaturePublicKey";

    private static final byte[] PUBLIC_KEY_64;
    private static final byte[] PRIVATE_VALUE_32;
    private static final ByteString X;
    private static final ByteString Y;
    private static final ByteString KEY_VALUE;
    private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

    static {
        try {
            AsymmetricCipherKeyPair keyPair = Sm2KeyUtil.generateKeyPair();
            PRIVATE_VALUE_32 =
                    Sm2KeyUtil.toFixedLengthBytes(
                            Sm2KeyUtil.getPrivateKey(keyPair).getD(), Sm2Curve.COORDINATE_SIZE_BYTES);
            PUBLIC_KEY_64 =
                    Sm2Curve.encodePointWithoutPrefix(Sm2KeyUtil.getPublicKey(keyPair).getQ());
            X = ByteString.copyFrom(PUBLIC_KEY_64, 0, Sm2Curve.COORDINATE_SIZE_BYTES);
            Y = ByteString.copyFrom(
                    PUBLIC_KEY_64, Sm2Curve.COORDINATE_SIZE_BYTES, Sm2Curve.COORDINATE_SIZE_BYTES);
            KEY_VALUE = ByteString.copyFrom(PRIVATE_VALUE_32);
        } catch (GeneralSecurityException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @BeforeAll
    static void setUp() throws Exception {
        Sm2SignatureProtoSerialization.register(registry);
    }

    /**
     * Wraps {@link ProtoParametersSerialization#create} which expects the proto value bytes.
     */
    private static ProtoParametersSerialization createParametersSerialization(
            String typeUrl, OutputPrefixType outputPrefixType, MessageLite proto) {
        try {
            return ProtoParametersSerialization.create(typeUrl, outputPrefixType,
                    proto.toByteString());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static Sm2SignatureParameters parameters(Sm2SignatureParameters.Variant variant)
            throws GeneralSecurityException {
        return Sm2SignatureParameters.builder().setVariant(variant).build();
    }

    private static Sm2SignaturePublicKey createPublicKey(
            Sm2SignatureParameters.Variant variant, Integer idRequirement)
            throws GeneralSecurityException {
        return Sm2SignaturePublicKey.builder()
                .setParameters(parameters(variant))
                .setPublicKey(Bytes.copyFrom(PUBLIC_KEY_64))
                .setIdRequirement(idRequirement)
                .build();
    }

    private static Sm2SignaturePrivateKey createPrivateKey(
            Sm2SignatureParameters.Variant variant, Integer idRequirement)
            throws GeneralSecurityException {
        return Sm2SignaturePrivateKey.builder()
                .setPublicKey(createPublicKey(variant, idRequirement))
                .setPrivateValue(
                        SecretBytes.copyFrom(PRIVATE_VALUE_32, InsecureSecretKeyAccess.get()))
                .build();
    }

    private static Stream<ProtoParametersSerialization> invalidParametersSerializations() {
        return Stream.of(
                // Unknown output prefix
                createParametersSerialization(PRIVATE_TYPE_URL, OutputPrefixType.UNKNOWN_PREFIX,
                        cc.ddrpa.crypto.tink.proto.Sm2SignatureKeyFormat.newBuilder().build()),
                // Unsupported output prefix type (LEGACY)
                createParametersSerialization(PRIVATE_TYPE_URL, OutputPrefixType.LEGACY,
                        cc.ddrpa.crypto.tink.proto.Sm2SignatureKeyFormat.newBuilder().build()),
                // Bad version
                createParametersSerialization(PRIVATE_TYPE_URL, OutputPrefixType.RAW,
                        cc.ddrpa.crypto.tink.proto.Sm2SignatureKeyFormat.newBuilder().setVersion(1)
                                .build()));
    }

    private static Stream<ProtoKeySerialization> invalidPublicKeySerializations() {
        try {
            return Stream.of(
                    // Bad Version Number (1)
                    ProtoKeySerialization.create(PUBLIC_TYPE_URL,
                            cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder().setVersion(1)
                                    .setX(X).setY(Y).build().toByteString(),
                            KeyMaterialType.ASYMMETRIC_PUBLIC, OutputPrefixType.TINK, 1479),
                    // Unknown prefix
                    ProtoKeySerialization.create(PUBLIC_TYPE_URL,
                            cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder().setVersion(0)
                                    .setX(X).setY(Y).build().toByteString(),
                            KeyMaterialType.ASYMMETRIC_PUBLIC, OutputPrefixType.UNKNOWN_PREFIX, 1479),
                    // X coordinate of wrong length
                    ProtoKeySerialization.create(PUBLIC_TYPE_URL,
                            cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder().setVersion(0)
                                    .setX(ByteString.copyFrom(new byte[31])).setY(Y).build().toByteString(),
                            KeyMaterialType.ASYMMETRIC_PUBLIC, OutputPrefixType.RAW, null),
                    // Y coordinate of wrong length
                    ProtoKeySerialization.create(PUBLIC_TYPE_URL,
                            cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder().setVersion(0)
                                    .setX(X).setY(ByteString.copyFrom(new byte[33])).build().toByteString(),
                            KeyMaterialType.ASYMMETRIC_PUBLIC, OutputPrefixType.RAW, null),
                    // Point not on the curve
                    ProtoKeySerialization.create(PUBLIC_TYPE_URL,
                            cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder().setVersion(0)
                                    .setX(ByteString.copyFrom(new byte[32]))
                                    .setY(ByteString.copyFrom(new byte[32])).build().toByteString(),
                            KeyMaterialType.ASYMMETRIC_PUBLIC, OutputPrefixType.RAW, null));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static Stream<ProtoKeySerialization> invalidPrivateKeySerializations() {
        try {
            return Stream.of(
                    // Bad Version Number (1)
                    ProtoKeySerialization.create(PRIVATE_TYPE_URL,
                            cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey.newBuilder().setVersion(1)
                                    .setPublicKey(
                                            cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder()
                                                    .setVersion(0).setX(X).setY(Y))
                                    .setKeyValue(KEY_VALUE).build().toByteString(),
                            KeyMaterialType.ASYMMETRIC_PRIVATE, OutputPrefixType.TINK, 1479),
                    // Nested public key with bad version
                    ProtoKeySerialization.create(PRIVATE_TYPE_URL,
                            cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey.newBuilder().setVersion(0)
                                    .setPublicKey(
                                            cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder()
                                                    .setVersion(1).setX(X).setY(Y))
                                    .setKeyValue(KEY_VALUE).build().toByteString(),
                            KeyMaterialType.ASYMMETRIC_PRIVATE, OutputPrefixType.TINK, 1479),
                    // Unsupported output prefix type (CRUNCHY)
                    ProtoKeySerialization.create(PRIVATE_TYPE_URL,
                            cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey.newBuilder().setVersion(0)
                                    .setPublicKey(
                                            cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder()
                                                    .setVersion(0).setX(X).setY(Y))
                                    .setKeyValue(KEY_VALUE).build().toByteString(),
                            KeyMaterialType.ASYMMETRIC_PRIVATE, OutputPrefixType.CRUNCHY, 1479),
                    // Private key value of wrong length
                    ProtoKeySerialization.create(PRIVATE_TYPE_URL,
                            cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey.newBuilder().setVersion(0)
                                    .setPublicKey(
                                            cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder()
                                                    .setVersion(0).setX(X).setY(Y))
                                    .setKeyValue(ByteString.copyFrom(new byte[31])).build().toByteString(),
                            KeyMaterialType.ASYMMETRIC_PRIVATE, OutputPrefixType.TINK, 1479));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void registerTwice() throws Exception {
        MutableSerializationRegistry newRegistry = new MutableSerializationRegistry();
        Sm2SignatureProtoSerialization.register(newRegistry);
        Sm2SignatureProtoSerialization.register(newRegistry);
    }

    @Test
    void serializeParseParameters_noPrefix() throws Exception {
        Sm2SignatureParameters parameters = parameters(Sm2SignatureParameters.Variant.NO_PREFIX);

        ProtoParametersSerialization serialization = createParametersSerialization(
                PRIVATE_TYPE_URL, OutputPrefixType.RAW,
                cc.ddrpa.crypto.tink.proto.Sm2SignatureKeyFormat.newBuilder().build());

        ProtoParametersSerialization serialized = registry.serializeParameters(parameters);
        assertEqualWhenValueParsed(
                cc.ddrpa.crypto.tink.proto.Sm2SignatureKeyFormat.parser(), serialized, serialization);

        Parameters parsed = registry.parseParameters(serialization);
        assertThat(parsed).isEqualTo(parameters);
    }

    @Test
    void serializeParseParameters_tink() throws Exception {
        Sm2SignatureParameters parameters = parameters(Sm2SignatureParameters.Variant.TINK);

        ProtoParametersSerialization serialization = createParametersSerialization(
                PRIVATE_TYPE_URL, OutputPrefixType.TINK,
                cc.ddrpa.crypto.tink.proto.Sm2SignatureKeyFormat.newBuilder().build());

        ProtoParametersSerialization serialized = registry.serializeParameters(parameters);
        assertEqualWhenValueParsed(
                cc.ddrpa.crypto.tink.proto.Sm2SignatureKeyFormat.parser(), serialized, serialization);

        Parameters parsed = registry.parseParameters(serialization);
        assertThat(parsed).isEqualTo(parameters);
    }

    @Test
    void serializeParsePublicKey_noPrefix() throws Exception {
        Sm2SignaturePublicKey key = createPublicKey(Sm2SignatureParameters.Variant.NO_PREFIX, null);

        cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey protoPublicKey =
                cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder()
                        .setVersion(0).setX(X).setY(Y).build();
        ProtoKeySerialization serialization = ProtoKeySerialization.create(
                PUBLIC_TYPE_URL, protoPublicKey.toByteString(),
                KeyMaterialType.ASYMMETRIC_PUBLIC, OutputPrefixType.RAW,
                /* idRequirement= */ null);

        ProtoKeySerialization serialized = registry.serializeKey(key, /* access= */ null);
        assertEqualWhenValueParsed(
                cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.parser(), serialized, serialization);

        Key parsed = registry.parseKey(serialization, /* access= */ null);
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @Test
    void serializeParsePublicKey_tink() throws Exception {
        Sm2SignaturePublicKey key = createPublicKey(Sm2SignatureParameters.Variant.TINK, 123);

        cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey protoPublicKey =
                cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder()
                        .setVersion(0).setX(X).setY(Y).build();
        ProtoKeySerialization serialization = ProtoKeySerialization.create(
                PUBLIC_TYPE_URL, protoPublicKey.toByteString(),
                KeyMaterialType.ASYMMETRIC_PUBLIC, OutputPrefixType.TINK,
                /* idRequirement= */ 123);

        ProtoKeySerialization serialized = registry.serializeKey(key, /* access= */ null);
        assertEqualWhenValueParsed(
                cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.parser(), serialized, serialization);

        Key parsed = registry.parseKey(serialization, /* access= */ null);
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @Test
    void serializeParsePrivateKey_noPrefix() throws Exception {
        Sm2SignaturePrivateKey key =
                createPrivateKey(Sm2SignatureParameters.Variant.NO_PREFIX, null);

        cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey protoPrivateKey =
                cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey.newBuilder()
                        .setVersion(0)
                        .setPublicKey(
                                cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder()
                                        .setVersion(0).setX(X).setY(Y))
                        .setKeyValue(KEY_VALUE)
                        .build();
        ProtoKeySerialization serialization = ProtoKeySerialization.create(
                PRIVATE_TYPE_URL, protoPrivateKey.toByteString(),
                KeyMaterialType.ASYMMETRIC_PRIVATE, OutputPrefixType.RAW,
                /* idRequirement= */ null);

        ProtoKeySerialization serialized =
                registry.serializeKey(key, InsecureSecretKeyAccess.get());
        assertEqualWhenValueParsed(
                cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey.parser(), serialized, serialization);

        Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @Test
    void serializeParsePrivateKey_tink() throws Exception {
        Sm2SignaturePrivateKey key =
                createPrivateKey(Sm2SignatureParameters.Variant.TINK, 123);

        cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey protoPrivateKey =
                cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey.newBuilder()
                        .setVersion(0)
                        .setPublicKey(
                                cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder()
                                        .setVersion(0).setX(X).setY(Y))
                        .setKeyValue(KEY_VALUE)
                        .build();
        ProtoKeySerialization serialization = ProtoKeySerialization.create(
                PRIVATE_TYPE_URL, protoPrivateKey.toByteString(),
                KeyMaterialType.ASYMMETRIC_PRIVATE, OutputPrefixType.TINK,
                /* idRequirement= */ 123);

        ProtoKeySerialization serialized =
                registry.serializeKey(key, InsecureSecretKeyAccess.get());
        assertEqualWhenValueParsed(
                cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey.parser(), serialized, serialization);

        Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
        assertThat(parsed.equalsKey(key)).isTrue();
    }

    @Test
    void testParsePrivateKey_noAccess_throws() throws Exception {
        cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey protoPrivateKey =
                cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey.newBuilder()
                        .setVersion(0)
                        .setPublicKey(
                                cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder()
                                        .setVersion(0).setX(X).setY(Y))
                        .setKeyValue(KEY_VALUE)
                        .build();
        ProtoKeySerialization serialization = ProtoKeySerialization.create(
                PRIVATE_TYPE_URL, protoPrivateKey.toByteString(),
                KeyMaterialType.ASYMMETRIC_PRIVATE, OutputPrefixType.TINK,
                /* idRequirement= */ 123);
        assertThrows(GeneralSecurityException.class, () -> registry.parseKey(serialization, null));
    }

    @Test
    void testSerializePrivateKey_noAccess_throws() throws Exception {
        Sm2SignaturePrivateKey key =
                createPrivateKey(Sm2SignatureParameters.Variant.TINK, 123);
        assertThrows(GeneralSecurityException.class,
                () -> registry.serializeKey(key, /* secretKeyAccess= */ null));
    }

    @Test
    void testParseParameters_wrongTypeUrl_throws() throws Exception {
        ProtoParametersSerialization serialization = createParametersSerialization(
                PUBLIC_TYPE_URL, OutputPrefixType.RAW,
                cc.ddrpa.crypto.tink.proto.Sm2SignatureKeyFormat.newBuilder().build());
        assertThrows(GeneralSecurityException.class,
                () -> registry.parseParameters(serialization));
    }

    @Test
    void testParseKey_wrongTypeUrl_throws() throws Exception {
        cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey protoPublicKey =
                cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder()
                        .setVersion(0).setX(X).setY(Y).build();
        // A private-key serialization can not be parsed as a public key.
        ProtoKeySerialization serialization = ProtoKeySerialization.create(
                PRIVATE_TYPE_URL, protoPublicKey.toByteString(),
                KeyMaterialType.ASYMMETRIC_PUBLIC, OutputPrefixType.RAW,
                /* idRequirement= */ null);
        assertThrows(GeneralSecurityException.class,
                () -> registry.parseKey(serialization, /* access= */ null));
    }

    @ParameterizedTest
    @MethodSource("invalidParametersSerializations")
    void testParseInvalidParameters_fails(ProtoParametersSerialization serializedParameters) {
        assertThrows(GeneralSecurityException.class,
                () -> registry.parseParameters(serializedParameters));
    }

    @ParameterizedTest
    @MethodSource("invalidPublicKeySerializations")
    void testParseInvalidPublicKeys_throws(ProtoKeySerialization serialization) {
        assertThrows(GeneralSecurityException.class,
                () -> registry.parseKey(serialization, /* access= */ null));
    }

    @ParameterizedTest
    @MethodSource("invalidPrivateKeySerializations")
    void testParseInvalidPrivateKeys_throws(ProtoKeySerialization serialization) {
        assertThrows(GeneralSecurityException.class,
                () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
    }
}
