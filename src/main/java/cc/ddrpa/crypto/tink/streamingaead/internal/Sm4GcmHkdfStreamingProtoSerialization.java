// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
/// /////////////////////////////////////////////////////////////////////////////

package cc.ddrpa.crypto.tink.streamingaead.internal;

import cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKey;
import cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingParameters;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.SerializationRegistry;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link Sm4GcmHkdfStreamingKey} objects and
 * {@link Sm4GcmHkdfStreamingParameters} objects
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class Sm4GcmHkdfStreamingProtoSerialization {

    private static final String TYPE_URL =
        "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey";

    private static final ParametersSerializer<Sm4GcmHkdfStreamingParameters>
        PARAMETERS_SERIALIZER = ParametersSerializer.create(
            Sm4GcmHkdfStreamingProtoSerialization::serializeParameters,
            Sm4GcmHkdfStreamingParameters.class);
    private static final ParametersParser PARAMETERS_PARSER = ParametersParser.create(
        Sm4GcmHkdfStreamingProtoSerialization::parseParameters, TYPE_URL);
    private static final KeySerializer<Sm4GcmHkdfStreamingKey> KEY_SERIALIZER =
        KeySerializer.create(
            Sm4GcmHkdfStreamingProtoSerialization::serializeKey, Sm4GcmHkdfStreamingKey.class);
    private static final KeyParser KEY_PARSER = KeyParser.create(
        Sm4GcmHkdfStreamingProtoSerialization::parseKey, TYPE_URL);

    private Sm4GcmHkdfStreamingProtoSerialization() {
    }

    private static HashType toProtoHashType(Sm4GcmHkdfStreamingParameters.HashType hashType)
        throws GeneralSecurityException {
        if (Sm4GcmHkdfStreamingParameters.HashType.SHA1.equals(hashType)) {
            return HashType.SHA1;
        }
        if (Sm4GcmHkdfStreamingParameters.HashType.SHA256.equals(hashType)) {
            return HashType.SHA256;
        }
        if (Sm4GcmHkdfStreamingParameters.HashType.SHA512.equals(hashType)) {
            return HashType.SHA512;
        }
        throw new GeneralSecurityException("Unable to serialize HashType " + hashType);
    }

    private static Sm4GcmHkdfStreamingParameters.HashType toHashType(HashType hashType)
        throws GeneralSecurityException {
        switch (hashType) {
            case SHA1:
                return Sm4GcmHkdfStreamingParameters.HashType.SHA1;
            case SHA256:
                return Sm4GcmHkdfStreamingParameters.HashType.SHA256;
            case SHA512:
                return Sm4GcmHkdfStreamingParameters.HashType.SHA512;
            default:
                throw new GeneralSecurityException(
                    "Unable to parse HashType: " + hashType.getNumber());
        }
    }

    private static cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams toProtoParams(
        Sm4GcmHkdfStreamingParameters parameters) throws GeneralSecurityException {
        return cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams.newBuilder()
            .setCiphertextSegmentSize(parameters.getCiphertextSegmentSizeBytes())
            .setDerivedKeySize(parameters.getDerivedSm4GcmKeySizeBytes())
            .setHkdfHashType(toProtoHashType(parameters.getHkdfHashType())).build();
    }

    private static ProtoParametersSerialization serializeParameters(
        Sm4GcmHkdfStreamingParameters parameters) throws GeneralSecurityException {
        return ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.newBuilder()
                .setKeySize(parameters.getKeySizeBytes()).setParams(toProtoParams(parameters))
                .build().toByteString());
    }

    private static ProtoKeySerialization serializeKey(Sm4GcmHkdfStreamingKey key,
        @Nullable SecretKeyAccess access) throws GeneralSecurityException {
        return ProtoKeySerialization.create(TYPE_URL,
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.newBuilder().setKeyValue(
                    ByteString.copyFrom(
                        key.getInitialKeyMaterial().toByteArray(SecretKeyAccess.requireAccess(access))))
                .setParams(toProtoParams(key.getParameters())).build().toByteString(),
            KeyMaterialType.SYMMETRIC, OutputPrefixType.RAW, key.getIdRequirementOrNull());
    }

    private static Sm4GcmHkdfStreamingParameters toParametersObject(
        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingParams params, int keySize)
        throws GeneralSecurityException {
        return Sm4GcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(keySize)
            .setDerivedSm4GcmKeySizeBytes(params.getDerivedKeySize())
            .setCiphertextSegmentSizeBytes(params.getCiphertextSegmentSize())
            .setHkdfHashType(toHashType(params.getHkdfHashType()))
            .build();
    }

    private static Sm4GcmHkdfStreamingParameters parseParameters(
        ProtoParametersSerialization serialization) throws GeneralSecurityException {
        if (!serialization.getTypeUrl().equals(TYPE_URL)) {
            throw new IllegalArgumentException(
                "Wrong type URL in call to Sm4GcmHkdfStreamingParameters.parseParameters: "
                    + serialization.getTypeUrl());
        }
        cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat format;
        try {
            format = cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKeyFormat.parseFrom(
                serialization.getValue(),
                ExtensionRegistryLite.getEmptyRegistry());
        } catch (InvalidProtocolBufferException e) {
            throw new GeneralSecurityException("Parsing Sm4GcmHkdfStreamingParameters failed: ", e);
        }
        if (format.getVersion() != 0) {
            throw new GeneralSecurityException("Only version 0 parameters are accepted");
        }
        return toParametersObject(format.getParams(), format.getKeySize());
    }

    @SuppressWarnings("UnusedException")
    private static Sm4GcmHkdfStreamingKey parseKey(ProtoKeySerialization serialization,
        @Nullable SecretKeyAccess access) throws GeneralSecurityException {
        if (!serialization.getTypeUrl().equals(TYPE_URL)) {
            throw new IllegalArgumentException(
                "Wrong type URL in call to Sm4GcmHkdfStreamingParameters.parseParameters");
        }
        try {
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey protoKey = cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.parseFrom(
                serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
            if (protoKey.getVersion() != 0) {
                throw new GeneralSecurityException("Only version 0 keys are accepted");
            }
            Sm4GcmHkdfStreamingParameters parameters = toParametersObject(protoKey.getParams(),
                protoKey.getKeyValue().size());
            return Sm4GcmHkdfStreamingKey.create(parameters,
                SecretBytes.copyFrom(protoKey.getKeyValue().toByteArray(),
                    SecretKeyAccess.requireAccess(access)));
        } catch (InvalidProtocolBufferException e) {
            throw new GeneralSecurityException("Parsing Sm4GcmHkdfStreamingKey failed");
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
