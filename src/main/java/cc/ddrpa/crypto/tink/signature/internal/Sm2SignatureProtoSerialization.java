package cc.ddrpa.crypto.tink.signature.internal;

import cc.ddrpa.crypto.tink.proto.Sm2PrivateKey;
import cc.ddrpa.crypto.tink.proto.Sm2PrivateKeyFormat;
import cc.ddrpa.crypto.tink.proto.Sm2PublicKey;
import cc.ddrpa.crypto.tink.proto.Sm2SignatureEncoding;
import cc.ddrpa.crypto.tink.proto.Sm2SignatureParams;
import cc.ddrpa.crypto.tink.signature.Sm2SignatureParameters;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse SM2 signature keys and parameters.
 */
@AccessesPartialKey
public final class Sm2SignatureProtoSerialization {

    private static final String PRIVATE_TYPE_URL = "type.googleapis.com/ddrpa.crypto.tink.Sm2PrivateKey";
    private static final String PUBLIC_TYPE_URL = "type.googleapis.com/ddrpa.crypto.tink.Sm2PublicKey";
    private static final Bytes PRIVATE_TYPE_URL_BYTES = Bytes.copyFrom(PRIVATE_TYPE_URL.getBytes());
    private static final Bytes PUBLIC_TYPE_URL_BYTES = Bytes.copyFrom(PUBLIC_TYPE_URL.getBytes());

    private static final ParametersSerializer<Sm2SignatureParameters, ProtoParametersSerialization>
            PARAMETERS_SERIALIZER =
            ParametersSerializer.create(
                    Sm2SignatureProtoSerialization::serializeParameters,
                    Sm2SignatureParameters.class,
                    ProtoParametersSerialization.class);

    private static final ParametersParser<ProtoParametersSerialization>
            PARAMETERS_PARSER =
            ParametersParser.create(
                    Sm2SignatureProtoSerialization::parseParameters,
                    PRIVATE_TYPE_URL_BYTES,
                    ProtoParametersSerialization.class);

    private static final KeySerializer<cc.ddrpa.crypto.tink.signature.Sm2PrivateKey, ProtoKeySerialization>
            PRIVATE_KEY_SERIALIZER =
            KeySerializer.create(
                    Sm2SignatureProtoSerialization::serializePrivateKey,
                    cc.ddrpa.crypto.tink.signature.Sm2PrivateKey.class,
                    ProtoKeySerialization.class);

    private static final KeyParser<ProtoKeySerialization> PRIVATE_KEY_PARSER =
            KeyParser.create(
                    Sm2SignatureProtoSerialization::parsePrivateKey,
                    PRIVATE_TYPE_URL_BYTES,
                    ProtoKeySerialization.class);

    private static final KeySerializer<cc.ddrpa.crypto.tink.signature.Sm2PublicKey, ProtoKeySerialization>
            PUBLIC_KEY_SERIALIZER =
            KeySerializer.create(
                    Sm2SignatureProtoSerialization::serializePublicKey,
                    cc.ddrpa.crypto.tink.signature.Sm2PublicKey.class,
                    ProtoKeySerialization.class);

    private static final KeyParser<ProtoKeySerialization> PUBLIC_KEY_PARSER =
            KeyParser.create(
                    Sm2SignatureProtoSerialization::parsePublicKey,
                    PUBLIC_TYPE_URL_BYTES,
                    ProtoKeySerialization.class);

    private static OutputPrefixType toProtoOutputPrefixType(Sm2SignatureParameters.Variant variant)
            throws GeneralSecurityException {
        if (Sm2SignatureParameters.Variant.TINK.equals(variant)) {
            return OutputPrefixType.TINK;
        }
        if (Sm2SignatureParameters.Variant.NO_PREFIX.equals(variant)) {
            return OutputPrefixType.RAW;
        }
        if (Sm2SignatureParameters.Variant.LEGACY.equals(variant)) {
            return OutputPrefixType.LEGACY;
        }
        if (Sm2SignatureParameters.Variant.CRUNCHY.equals(variant)) {
            return OutputPrefixType.CRUNCHY;
        }
        throw new GeneralSecurityException("Unable to serialize variant: " + variant);
    }

    private static Sm2SignatureParameters.Variant toVariant(OutputPrefixType outputPrefixType)
            throws GeneralSecurityException {
        switch (outputPrefixType) {
            case TINK:
                return Sm2SignatureParameters.Variant.TINK;
            case RAW:
                return Sm2SignatureParameters.Variant.NO_PREFIX;
            case LEGACY:
                return Sm2SignatureParameters.Variant.LEGACY;
            case CRUNCHY:
                return Sm2SignatureParameters.Variant.CRUNCHY;
            default:
                throw new GeneralSecurityException(
                        "Unable to parse OutputPrefixType: " + outputPrefixType.getNumber());
        }
    }

    private static Sm2SignatureEncoding toProtoSignatureEncoding(
            Sm2SignatureParameters.SignatureEncoding encoding) throws GeneralSecurityException {
        if (Sm2SignatureParameters.SignatureEncoding.DER.equals(encoding)) {
            return Sm2SignatureEncoding.DER;
        }
        if (Sm2SignatureParameters.SignatureEncoding.IEEE_P1363.equals(encoding)) {
            return Sm2SignatureEncoding.IEEE_P1363;
        }
        throw new GeneralSecurityException("Unable to serialize signature encoding: " + encoding);
    }

    private static Sm2SignatureParameters.SignatureEncoding toSignatureEncoding(
            Sm2SignatureEncoding encoding) throws GeneralSecurityException {
        switch (encoding) {
            case DER:
                return Sm2SignatureParameters.SignatureEncoding.DER;
            case IEEE_P1363:
                return Sm2SignatureParameters.SignatureEncoding.IEEE_P1363;
            default:
                throw new GeneralSecurityException(
                        "Unable to parse signature encoding: " + encoding.getNumber());
        }
    }

    private static ProtoParametersSerialization serializeParameters(Sm2SignatureParameters parameters)
            throws GeneralSecurityException {
        Sm2SignatureParams.Builder paramsBuilder = Sm2SignatureParams.newBuilder()
                .setHashType(parameters.getHashType())
                .setEncoding(toProtoSignatureEncoding(parameters.getSignatureEncoding()));

        return ProtoParametersSerialization.create(
                PRIVATE_TYPE_URL,
                OutputPrefixType.RAW,
                Sm2PrivateKeyFormat.newBuilder()
                        .setVersion(0)
                        .setParams(paramsBuilder.build())
                        .build());
    }

    private static ProtoKeySerialization serializePublicKey(
            cc.ddrpa.crypto.tink.signature.Sm2PublicKey key, @Nullable SecretKeyAccess access)
            throws GeneralSecurityException {
        Sm2PublicKey.Builder protoBuilder = Sm2PublicKey.newBuilder()
                .setVersion(0)
                .setParams(
                        Sm2SignatureParams.newBuilder()
                                .setHashType(key.getParameters().getHashType())
                                .setEncoding(toProtoSignatureEncoding(key.getParameters().getSignatureEncoding()))
                                .build())
                .setX(ByteString.copyFrom(key.getPublicKeyX().toByteArray()))
                .setY(ByteString.copyFrom(key.getPublicKeyY().toByteArray()));

        return ProtoKeySerialization.create(
                PUBLIC_TYPE_URL,
                protoBuilder.build().toByteString(),
                KeyMaterialType.ASYMMETRIC_PUBLIC,
                toProtoOutputPrefixType(key.getParameters().getVariant()),
                key.getIdRequirementOrNull());
    }

    private static ProtoKeySerialization serializePrivateKey(
            cc.ddrpa.crypto.tink.signature.Sm2PrivateKey key, @Nullable SecretKeyAccess access)
            throws GeneralSecurityException {
        Sm2PrivateKey.Builder protoBuilder = Sm2PrivateKey.newBuilder()
                .setVersion(0)
                .setParams(
                        Sm2SignatureParams.newBuilder()
                                .setHashType(key.getParameters().getHashType())
                                .setEncoding(toProtoSignatureEncoding(key.getParameters().getSignatureEncoding()))
                                .build())
                .setKeyValue(ByteString.copyFrom(
                        key.getPrivateKeyValue().toByteArray(SecretKeyAccess.requireAccess(access))))
                .setPublicKey(
                        Sm2PublicKey.newBuilder()
                                .setVersion(0)
                                .setParams(
                                        Sm2SignatureParams.newBuilder()
                                                .setHashType(key.getParameters().getHashType())
                                                .setEncoding(toProtoSignatureEncoding(
                                                        key.getParameters().getSignatureEncoding()))
                                                .build())
                                .setX(ByteString.copyFrom(key.getPublicKey().getPublicKeyX().toByteArray()))
                                .setY(ByteString.copyFrom(key.getPublicKey().getPublicKeyY().toByteArray()))
                                .build());

        return ProtoKeySerialization.create(
                PRIVATE_TYPE_URL,
                protoBuilder.build().toByteString(),
                KeyMaterialType.ASYMMETRIC_PRIVATE,
                toProtoOutputPrefixType(key.getParameters().getVariant()),
                key.getIdRequirementOrNull());
    }

    private static Sm2SignatureParameters parseParameters(ProtoParametersSerialization serialization)
            throws GeneralSecurityException {
        if (!serialization.getKeyTemplate().getTypeUrl().equals(PRIVATE_TYPE_URL)) {
            throw new IllegalArgumentException(
                    "Wrong type URL in call to Sm2SignatureProtoSerialization.parseParameters: "
                            + serialization.getKeyTemplate().getTypeUrl());
        }

        Sm2PrivateKeyFormat format;
        try {
            format = Sm2PrivateKeyFormat.parseFrom(
                    serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
        } catch (InvalidProtocolBufferException e) {
            throw new GeneralSecurityException("Parsing Sm2PrivateKeyFormat failed: ", e);
        }

        return Sm2SignatureParameters.builder()
                .setHashAlgorithm(format.getParams().getHashType() == com.google.crypto.tink.proto.HashType.SHA256
                        ? Sm2SignatureParameters.HashAlgorithm.SHA256
                        : Sm2SignatureParameters.HashAlgorithm.SM3)
                .setSignatureEncoding(toSignatureEncoding(format.getParams().getEncoding()))
                .setVariant(toVariant(serialization.getKeyTemplate().getOutputPrefixType()))
                .build();
    }

    private static cc.ddrpa.crypto.tink.signature.Sm2PublicKey parsePublicKey(
            ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
            throws GeneralSecurityException {
        if (!serialization.getTypeUrl().equals(PUBLIC_TYPE_URL)) {
            throw new IllegalArgumentException(
                    "Wrong type URL in call to Sm2SignatureProtoSerialization.parsePublicKey: "
                            + serialization.getTypeUrl());
        }

        Sm2PublicKey protoKey;
        try {
            protoKey = Sm2PublicKey.parseFrom(
                    serialization.getValue().toByteArray(), ExtensionRegistryLite.getEmptyRegistry());
        } catch (InvalidProtocolBufferException e) {
            throw new GeneralSecurityException("Parsing Sm2PublicKey failed: ", e);
        }

        Sm2SignatureParameters parameters = Sm2SignatureParameters.builder()
                .setHashAlgorithm(protoKey.getParams().getHashType() == com.google.crypto.tink.proto.HashType.SHA256
                        ? Sm2SignatureParameters.HashAlgorithm.SHA256
                        : Sm2SignatureParameters.HashAlgorithm.SM3)
                .setSignatureEncoding(toSignatureEncoding(protoKey.getParams().getEncoding()))
                .setVariant(toVariant(serialization.getOutputPrefixType()))
                .build();

        return cc.ddrpa.crypto.tink.signature.Sm2PublicKey.builder()
                .setParameters(parameters)
                .setPublicKeyX(Bytes.copyFrom(protoKey.getX().toByteArray()))
                .setPublicKeyY(Bytes.copyFrom(protoKey.getY().toByteArray()))
                .setIdRequirement(serialization.getIdRequirementOrNull())
                .build();
    }

    private static cc.ddrpa.crypto.tink.signature.Sm2PrivateKey parsePrivateKey(
            ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
            throws GeneralSecurityException {
        if (!serialization.getTypeUrl().equals(PRIVATE_TYPE_URL)) {
            throw new IllegalArgumentException(
                    "Wrong type URL in call to Sm2SignatureProtoSerialization.parsePrivateKey: "
                            + serialization.getTypeUrl());
        }

        Sm2PrivateKey protoKey;
        try {
            protoKey = Sm2PrivateKey.parseFrom(
                    serialization.getValue().toByteArray(), ExtensionRegistryLite.getEmptyRegistry());
        } catch (InvalidProtocolBufferException e) {
            throw new GeneralSecurityException("Parsing Sm2PrivateKey failed: ", e);
        }

        Sm2SignatureParameters parameters = Sm2SignatureParameters.builder()
                .setHashAlgorithm(protoKey.getParams().getHashType() == com.google.crypto.tink.proto.HashType.SHA256
                        ? Sm2SignatureParameters.HashAlgorithm.SHA256
                        : Sm2SignatureParameters.HashAlgorithm.SM3)
                .setSignatureEncoding(toSignatureEncoding(protoKey.getParams().getEncoding()))
                .setVariant(toVariant(serialization.getOutputPrefixType()))
                .build();

        cc.ddrpa.crypto.tink.signature.Sm2PublicKey publicKey = 
                cc.ddrpa.crypto.tink.signature.Sm2PublicKey.builder()
                        .setParameters(parameters)
                        .setPublicKeyX(Bytes.copyFrom(protoKey.getPublicKey().getX().toByteArray()))
                        .setPublicKeyY(Bytes.copyFrom(protoKey.getPublicKey().getY().toByteArray()))
                        .setIdRequirement(serialization.getIdRequirementOrNull())
                        .build();

        return cc.ddrpa.crypto.tink.signature.Sm2PrivateKey.builder()
                .setParameters(parameters)
                .setPrivateKeyValue(
                        SecretBytes.copyFrom(
                                protoKey.getKeyValue().toByteArray(), 
                                SecretKeyAccess.requireAccess(access)))
                .setPublicKey(publicKey)
                .build();
    }

    public static void register() throws GeneralSecurityException {
        register(MutableSerializationRegistry.globalInstance());
    }

    public static void register(MutableSerializationRegistry registry) throws GeneralSecurityException {
        registry.registerParametersSerializer(PARAMETERS_SERIALIZER);
        registry.registerParametersParser(PARAMETERS_PARSER);
        registry.registerKeySerializer(PRIVATE_KEY_SERIALIZER);
        registry.registerKeyParser(PRIVATE_KEY_PARSER);
        registry.registerKeySerializer(PUBLIC_KEY_SERIALIZER);
        registry.registerKeyParser(PUBLIC_KEY_PARSER);
    }

    private Sm2SignatureProtoSerialization() {}
}