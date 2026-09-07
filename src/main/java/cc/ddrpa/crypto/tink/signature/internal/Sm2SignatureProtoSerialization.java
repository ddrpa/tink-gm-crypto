package cc.ddrpa.crypto.tink.signature.internal;

import cc.ddrpa.crypto.tink.signature.Sm2SignatureParameters;
import cc.ddrpa.crypto.tink.signature.Sm2SignaturePrivateKey;
import cc.ddrpa.crypto.tink.signature.Sm2SignaturePublicKey;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2Curve;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.*;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;

import javax.annotation.Nullable;
import java.security.GeneralSecurityException;

/**
 * Methods to serialize and parse {@link Sm2SignaturePrivateKey} and {@link Sm2SignaturePublicKey}
 * objects and {@link Sm2SignatureParameters} objects.
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class Sm2SignatureProtoSerialization {

    private static final String PRIVATE_TYPE_URL =
            "type.googleapis.com/ddrpa.crypto.tink.Sm2SignaturePrivateKey";

    private static final String PUBLIC_TYPE_URL =
            "type.googleapis.com/ddrpa.crypto.tink.Sm2SignaturePublicKey";

    private static final ParametersSerializer<Sm2SignatureParameters> PARAMETERS_SERIALIZER =
            ParametersSerializer.create(
                    Sm2SignatureProtoSerialization::serializeParameters, Sm2SignatureParameters.class);

    private static final ParametersParser PARAMETERS_PARSER =
            ParametersParser.create(Sm2SignatureProtoSerialization::parseParameters, PRIVATE_TYPE_URL);

    private static final KeySerializer<Sm2SignaturePublicKey> PUBLIC_KEY_SERIALIZER =
            KeySerializer.create(
                    Sm2SignatureProtoSerialization::serializePublicKey, Sm2SignaturePublicKey.class);

    private static final KeyParser PUBLIC_KEY_PARSER =
            KeyParser.create(Sm2SignatureProtoSerialization::parsePublicKey, PUBLIC_TYPE_URL);

    private static final KeySerializer<Sm2SignaturePrivateKey> PRIVATE_KEY_SERIALIZER =
            KeySerializer.create(
                    Sm2SignatureProtoSerialization::serializePrivateKey, Sm2SignaturePrivateKey.class);

    private static final KeyParser PRIVATE_KEY_PARSER =
            KeyParser.create(Sm2SignatureProtoSerialization::parsePrivateKey, PRIVATE_TYPE_URL);

    private Sm2SignatureProtoSerialization() {
    }

    private static OutputPrefixType toProtoOutputPrefixType(Sm2SignatureParameters.Variant variant)
            throws GeneralSecurityException {
        if (Sm2SignatureParameters.Variant.TINK.equals(variant)) {
            return OutputPrefixType.TINK;
        }
        if (Sm2SignatureParameters.Variant.NO_PREFIX.equals(variant)) {
            return OutputPrefixType.RAW;
        }
        throw new GeneralSecurityException("Unable to serialize variant: " + variant);
    }

    private static Sm2SignatureParameters.Variant toVariant(OutputPrefixType outputPrefixType)
            throws GeneralSecurityException {
        if (OutputPrefixType.TINK.equals(outputPrefixType)) {
            return Sm2SignatureParameters.Variant.TINK;
        }
        if (OutputPrefixType.RAW.equals(outputPrefixType)) {
            return Sm2SignatureParameters.Variant.NO_PREFIX;
        }
        throw new GeneralSecurityException(
                "Unable to parse OutputPrefixType: " + outputPrefixType);
    }

    private static cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey getProtoPublicKey(
            Sm2SignaturePublicKey key) throws GeneralSecurityException {
        byte[] publicKeyBytes = key.getPublicKey().toByteArray();
        if (publicKeyBytes.length != 2 * Sm2Curve.COORDINATE_SIZE_BYTES) {
            throw new GeneralSecurityException(
                    "SM2 public key must be exactly "
                            + (2 * Sm2Curve.COORDINATE_SIZE_BYTES)
                            + " bytes (X || Y)");
        }
        return cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.newBuilder()
                .setVersion(0)
                .setX(
                        ByteString.copyFrom(
                                publicKeyBytes, 0, Sm2Curve.COORDINATE_SIZE_BYTES))
                .setY(
                        ByteString.copyFrom(
                                publicKeyBytes,
                                Sm2Curve.COORDINATE_SIZE_BYTES,
                                Sm2Curve.COORDINATE_SIZE_BYTES))
                .build();
    }

    private static ProtoParametersSerialization serializeParameters(
            Sm2SignatureParameters parameters) throws GeneralSecurityException {
        return ProtoParametersSerialization.create(
                PRIVATE_TYPE_URL,
                toProtoOutputPrefixType(parameters.getVariant()),
                cc.ddrpa.crypto.tink.proto.Sm2SignatureKeyFormat.newBuilder()
                        .setVersion(0)
                        .build()
                        .toByteString());
    }

    private static ProtoKeySerialization serializePublicKey(
            Sm2SignaturePublicKey key, @Nullable SecretKeyAccess access)
            throws GeneralSecurityException {
        return ProtoKeySerialization.create(
                PUBLIC_TYPE_URL,
                getProtoPublicKey(key).toByteString(),
                KeyMaterialType.ASYMMETRIC_PUBLIC,
                toProtoOutputPrefixType(key.getParameters().getVariant()),
                key.getIdRequirementOrNull());
    }

    private static ProtoKeySerialization serializePrivateKey(
            Sm2SignaturePrivateKey key, @Nullable SecretKeyAccess access)
            throws GeneralSecurityException {
        return ProtoKeySerialization.create(
                PRIVATE_TYPE_URL,
                cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey.newBuilder()
                        .setVersion(0)
                        .setPublicKey(getProtoPublicKey(key.getPublicKey()))
                        .setKeyValue(
                                ByteString.copyFrom(
                                        key.getPrivateValue().toByteArray(SecretKeyAccess.requireAccess(access))))
                        .build()
                        .toByteString(),
                KeyMaterialType.ASYMMETRIC_PRIVATE,
                toProtoOutputPrefixType(key.getParameters().getVariant()),
                key.getIdRequirementOrNull());
    }

    private static Sm2SignatureParameters parseParameters(
            ProtoParametersSerialization serialization) throws GeneralSecurityException {
        if (!serialization.getTypeUrl().equals(PRIVATE_TYPE_URL)) {
            throw new IllegalArgumentException(
                    "Wrong type URL in call to Sm2SignatureProtoSerialization.parseParameters: "
                            + serialization.getTypeUrl());
        }
        cc.ddrpa.crypto.tink.proto.Sm2SignatureKeyFormat format;
        try {
            format =
                    cc.ddrpa.crypto.tink.proto.Sm2SignatureKeyFormat.parseFrom(
                            serialization.getValue(),
                            ExtensionRegistryLite.getEmptyRegistry());
        } catch (InvalidProtocolBufferException e) {
            throw new GeneralSecurityException("Parsing Sm2SignatureParameters failed: ", e);
        }
        if (format.getVersion() != 0) {
            throw new GeneralSecurityException("Only version 0 parameters are accepted");
        }
        return Sm2SignatureParameters.builder()
                .setVariant(toVariant(serialization.getOutputPrefixType()))
                .build();
    }

    private static byte[] getPublicKeyBytes(
            cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey protoPublicKey)
            throws GeneralSecurityException {
        byte[] x = protoPublicKey.getX().toByteArray();
        byte[] y = protoPublicKey.getY().toByteArray();
        if (x.length != Sm2Curve.COORDINATE_SIZE_BYTES
                || y.length != Sm2Curve.COORDINATE_SIZE_BYTES) {
            throw new GeneralSecurityException(
                    "SM2 public key coordinates must be exactly "
                            + Sm2Curve.COORDINATE_SIZE_BYTES
                            + " bytes each");
        }
        byte[] publicKeyBytes = new byte[2 * Sm2Curve.COORDINATE_SIZE_BYTES];
        System.arraycopy(x, 0, publicKeyBytes, 0, Sm2Curve.COORDINATE_SIZE_BYTES);
        System.arraycopy(
                y, 0, publicKeyBytes, Sm2Curve.COORDINATE_SIZE_BYTES, Sm2Curve.COORDINATE_SIZE_BYTES);
        return publicKeyBytes;
    }

    @SuppressWarnings("UnusedException")
    private static Sm2SignaturePublicKey parsePublicKey(
            ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
            throws GeneralSecurityException {
        if (!serialization.getTypeUrl().equals(PUBLIC_TYPE_URL)) {
            throw new IllegalArgumentException(
                    "Wrong type URL in call to Sm2SignatureProtoSerialization.parsePublicKey: "
                            + serialization.getTypeUrl());
        }
        try {
            cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey protoKey =
                    cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.parseFrom(
                            serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
            if (protoKey.getVersion() != 0) {
                throw new GeneralSecurityException("Only version 0 keys are accepted");
            }
            byte[] publicKeyBytes = getPublicKeyBytes(protoKey);
            return Sm2SignaturePublicKey.builder()
                    .setParameters(
                            Sm2SignatureParameters.builder()
                                    .setVariant(toVariant(serialization.getOutputPrefixType()))
                                    .build())
                    .setPublicKey(Bytes.copyFrom(publicKeyBytes))
                    .setIdRequirement(serialization.getIdRequirementOrNull())
                    .build();
        } catch (InvalidProtocolBufferException e) {
            throw new GeneralSecurityException("Parsing Sm2SignaturePublicKey failed");
        }
    }

    @SuppressWarnings("UnusedException")
    private static Sm2SignaturePrivateKey parsePrivateKey(
            ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
            throws GeneralSecurityException {
        if (!serialization.getTypeUrl().equals(PRIVATE_TYPE_URL)) {
            throw new IllegalArgumentException(
                    "Wrong type URL in call to Sm2SignatureProtoSerialization.parsePrivateKey: "
                            + serialization.getTypeUrl());
        }
        try {
            cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey protoKey =
                    cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey.parseFrom(
                            serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
            if (protoKey.getVersion() != 0) {
                throw new GeneralSecurityException("Only version 0 keys are accepted");
            }
            cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey protoPublicKey =
                    protoKey.getPublicKey();
            if (protoPublicKey.getVersion() != 0) {
                throw new GeneralSecurityException("Only version 0 keys are accepted");
            }
            byte[] publicKeyBytes = getPublicKeyBytes(protoPublicKey);
            byte[] privateKeyBytes = protoKey.getKeyValue().toByteArray();
            if (privateKeyBytes.length != Sm2Curve.COORDINATE_SIZE_BYTES) {
                throw new GeneralSecurityException(
                        "SM2 private key must be exactly "
                                + Sm2Curve.COORDINATE_SIZE_BYTES
                                + " bytes");
            }
            Sm2SignaturePublicKey publicKey =
                    Sm2SignaturePublicKey.builder()
                            .setParameters(
                                    Sm2SignatureParameters.builder()
                                            .setVariant(toVariant(serialization.getOutputPrefixType()))
                                            .build())
                            .setPublicKey(Bytes.copyFrom(publicKeyBytes))
                            .setIdRequirement(serialization.getIdRequirementOrNull())
                            .build();
            return Sm2SignaturePrivateKey.builder()
                    .setPublicKey(publicKey)
                    .setPrivateValue(
                            SecretBytes.copyFrom(
                                    privateKeyBytes, SecretKeyAccess.requireAccess(access)))
                    .build();
        } catch (InvalidProtocolBufferException e) {
            throw new GeneralSecurityException("Parsing Sm2SignaturePrivateKey failed");
        }
    }

    public static void register() throws GeneralSecurityException {
        register(MutableSerializationRegistry.globalInstance());
    }

    public static void register(MutableSerializationRegistry registry)
            throws GeneralSecurityException {
        registry.registerParametersSerializer(PARAMETERS_SERIALIZER);
        registry.registerParametersParser(PARAMETERS_PARSER);
        registry.registerKeySerializer(PUBLIC_KEY_SERIALIZER);
        registry.registerKeyParser(PUBLIC_KEY_PARSER);
        registry.registerKeySerializer(PRIVATE_KEY_SERIALIZER);
        registry.registerKeyParser(PRIVATE_KEY_PARSER);
    }

    public static void register(SerializationRegistry.Builder registryBuilder)
            throws GeneralSecurityException {
        registryBuilder.registerParametersSerializer(PARAMETERS_SERIALIZER);
        registryBuilder.registerParametersParser(PARAMETERS_PARSER);
        registryBuilder.registerKeySerializer(PUBLIC_KEY_SERIALIZER);
        registryBuilder.registerKeyParser(PUBLIC_KEY_PARSER);
        registryBuilder.registerKeySerializer(PRIVATE_KEY_SERIALIZER);
        registryBuilder.registerKeyParser(PRIVATE_KEY_PARSER);
    }
}
