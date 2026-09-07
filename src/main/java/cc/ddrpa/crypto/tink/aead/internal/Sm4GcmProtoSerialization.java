package cc.ddrpa.crypto.tink.aead.internal;

import cc.ddrpa.crypto.tink.aead.Sm4GcmKey;
import cc.ddrpa.crypto.tink.aead.Sm4GcmParameters;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.*;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;

import javax.annotation.Nullable;
import java.security.GeneralSecurityException;

/**
 * Methods to serialize and parse {@link Sm4GcmKey} objects and {@link Sm4GcmParameters} objects
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class Sm4GcmProtoSerialization {

    private static final String TYPE_URL = "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmKey";

    private static final ParametersSerializer<Sm4GcmParameters> PARAMETERS_SERIALIZER =
            ParametersSerializer.create(
                    Sm4GcmProtoSerialization::serializeParameters, Sm4GcmParameters.class);
    private static final ParametersParser PARAMETERS_PARSER =
            ParametersParser.create(Sm4GcmProtoSerialization::parseParameters, TYPE_URL);
    private static final KeySerializer<Sm4GcmKey> KEY_SERIALIZER =
            KeySerializer.create(Sm4GcmProtoSerialization::serializeKey, Sm4GcmKey.class);
    private static final KeyParser KEY_PARSER =
            KeyParser.create(Sm4GcmProtoSerialization::parseKey, TYPE_URL);

    private Sm4GcmProtoSerialization() {
    }

    private static OutputPrefixType toProtoOutputPrefixType(Sm4GcmParameters.Variant variant)
            throws GeneralSecurityException {
        if (Sm4GcmParameters.Variant.TINK.equals(variant)) {
            return OutputPrefixType.TINK;
        }
        if (Sm4GcmParameters.Variant.NO_PREFIX.equals(variant)) {
            return OutputPrefixType.RAW;
        }
        throw new GeneralSecurityException("Unable to serialize variant: " + variant);
    }

    private static Sm4GcmParameters.Variant toVariant(OutputPrefixType outputPrefixType)
            throws GeneralSecurityException {
        if (OutputPrefixType.TINK.equals(outputPrefixType)) {
            return Sm4GcmParameters.Variant.TINK;
        }
        if (OutputPrefixType.RAW.equals(outputPrefixType)) {
            return Sm4GcmParameters.Variant.NO_PREFIX;
        }
        throw new GeneralSecurityException("Unable to parse OutputPrefixType: " + outputPrefixType);
    }

    private static void validateParameters(Sm4GcmParameters parameters)
            throws GeneralSecurityException {
        /** Current implementation restricts tag size to 16 bytes */
        if (parameters.getTagSizeBytes() != 16) {
            throw new GeneralSecurityException(
                    String.format(
                            "Invalid tag size in bytes %d. Currently Tink only supports serialization of SM4 GCM"
                                    + " keys with tag size equal to 16 bytes.",
                            parameters.getTagSizeBytes()));
        }
        /** Current implementation restricts IV size to 12 bytes */
        if (parameters.getIvSizeBytes() != 12) {
            throw new GeneralSecurityException(
                    String.format(
                            "Invalid IV size in bytes %d. Currently Tink only supports serialization of SM4 GCM"
                                    + " keys with IV size equal to 12 bytes.",
                            parameters.getIvSizeBytes()));
        }
    }

    private static ProtoParametersSerialization serializeParameters(Sm4GcmParameters parameters)
            throws GeneralSecurityException {
        validateParameters(parameters);
        return ProtoParametersSerialization.create(
                TYPE_URL,
                toProtoOutputPrefixType(parameters.getVariant()),
                cc.ddrpa.crypto.tink.proto.Sm4GcmKeyFormat.newBuilder()
                        .build()
                        .toByteString());
    }

    private static ProtoKeySerialization serializeKey(Sm4GcmKey key,
                                                      @Nullable SecretKeyAccess access)
            throws GeneralSecurityException {
        validateParameters(key.getParameters());
        return ProtoKeySerialization.create(
                TYPE_URL,
                cc.ddrpa.crypto.tink.proto.Sm4GcmKey.newBuilder()
                        .setKeyValue(
                                ByteString.copyFrom(
                                        key.getKeyBytes().toByteArray(SecretKeyAccess.requireAccess(access))))
                        .build()
                        .toByteString(),
                KeyMaterialType.SYMMETRIC,
                toProtoOutputPrefixType(key.getParameters().getVariant()),
                key.getIdRequirementOrNull());
    }

    private static Sm4GcmParameters parseParameters(ProtoParametersSerialization serialization)
            throws GeneralSecurityException {
        if (!serialization.getTypeUrl().equals(TYPE_URL)) {
            throw new IllegalArgumentException(
                    "Wrong type URL in call to Sm4GcmProtoSerialization.parseParameters: "
                            + serialization.getTypeUrl());
        }
        cc.ddrpa.crypto.tink.proto.Sm4GcmKeyFormat format;
        try {
            format =
                    cc.ddrpa.crypto.tink.proto.Sm4GcmKeyFormat.parseFrom(
                            serialization.getValue(),
                            ExtensionRegistryLite.getEmptyRegistry());
        } catch (InvalidProtocolBufferException e) {
            throw new GeneralSecurityException("Parsing Sm4GcmParameters failed: ", e);
        }
        if (format.getVersion() != 0) {
            throw new GeneralSecurityException("Only version 0 parameters are accepted");
        }
        return Sm4GcmParameters.builder()
                /**
                 * Currently, the Tink subtle implementation has the following restrictions: IV is a
                 * uniformly random initialization vector of length 12 and the tag is restricted to 16
                 * bytes.
                 */
                .setIvSizeBytes(12)
                .setTagSizeBytes(16)
                .setVariant(toVariant(serialization.getOutputPrefixType()))
                .build();
    }

    @SuppressWarnings("UnusedException")
    private static Sm4GcmKey parseKey(
            ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
            throws GeneralSecurityException {
        if (!serialization.getTypeUrl().equals(TYPE_URL)) {
            throw new IllegalArgumentException(
                    "Wrong type URL in call to Sm4GcmProtoSerialization.parseKey");
        }
        try {
            cc.ddrpa.crypto.tink.proto.Sm4GcmKey protoKey =
                    cc.ddrpa.crypto.tink.proto.Sm4GcmKey.parseFrom(
                            serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
            if (protoKey.getVersion() != 0) {
                throw new GeneralSecurityException("Only version 0 keys are accepted");
            }
            Sm4GcmParameters parameters =
                    Sm4GcmParameters.builder()
                            .setIvSizeBytes(12)
                            .setTagSizeBytes(16)
                            .setVariant(toVariant(serialization.getOutputPrefixType()))
                            .build();
            return Sm4GcmKey.builder()
                    .setParameters(parameters)
                    .setKeyBytes(
                            SecretBytes.copyFrom(
                                    protoKey.getKeyValue().toByteArray(),
                                    SecretKeyAccess.requireAccess(access)))
                    .setIdRequirement(serialization.getIdRequirementOrNull())
                    .build();
        } catch (InvalidProtocolBufferException e) {
            throw new GeneralSecurityException("Parsing Sm4GcmKey failed");
        }
    }

    public static void register() throws GeneralSecurityException {
        register(MutableSerializationRegistry.globalInstance());
    }

    public static void register(MutableSerializationRegistry registry)
            throws GeneralSecurityException {
        registry.registerParametersSerializer(PARAMETERS_SERIALIZER);
        registry.registerParametersParser(PARAMETERS_PARSER);
        registry.registerKeySerializer(KEY_SERIALIZER);
        registry.registerKeyParser(KEY_PARSER);
    }

    public static void register(SerializationRegistry.Builder registryBuilder)
            throws GeneralSecurityException {
        registryBuilder.registerParametersSerializer(PARAMETERS_SERIALIZER);
        registryBuilder.registerParametersParser(PARAMETERS_PARSER);
        registryBuilder.registerKeySerializer(KEY_SERIALIZER);
        registryBuilder.registerKeyParser(KEY_PARSER);
    }
}
