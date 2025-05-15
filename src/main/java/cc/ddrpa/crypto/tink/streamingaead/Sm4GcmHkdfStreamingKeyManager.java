package cc.ddrpa.crypto.tink.streamingaead;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import cc.ddrpa.crypto.tink.streamingaead.internal.Sm4GcmHkdfStreamingProtoSerialization;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableKeyDerivationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Sm4GcmHkdfStreaming;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code Sm4GcmHkdfStreamingKey} keys and produces new instances of
 * {@code Sm4GcmHkdfStreaming}.
 */
public final class Sm4GcmHkdfStreamingKeyManager {

    private static final PrimitiveConstructor<Sm4GcmHkdfStreamingKey, StreamingAead>
        SM4_GCM_HKDF_STREAMING_AEAD_PRIMITIVE_CONSTRUCTOR =
        PrimitiveConstructor.create(
            Sm4GcmHkdfStreaming::create,
            Sm4GcmHkdfStreamingKey.class,
            StreamingAead.class);

    private static final KeyManager<StreamingAead> legacyKeyManager =
        LegacyKeyManagerImpl.create(
            getKeyType(),
            StreamingAead.class,
            KeyMaterialType.SYMMETRIC,
            cc.ddrpa.crypto.tink.proto.Sm4GcmHkdfStreamingKey.parser());
    @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
    private static final MutableKeyCreationRegistry.KeyCreator<Sm4GcmHkdfStreamingParameters>
        KEY_CREATOR = Sm4GcmHkdfStreamingKeyManager::creatSm4GcmHkdfStreamingKey;
    @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
    private static final MutableKeyDerivationRegistry.InsecureKeyCreator<
        Sm4GcmHkdfStreamingParameters>
        KEY_DERIVER = Sm4GcmHkdfStreamingKeyManager::createSm4GcmHkdfStreamingKeyFromRandomness;

    private Sm4GcmHkdfStreamingKeyManager() {
    }

    static String getKeyType() {
        return "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey";
    }

    @AccessesPartialKey
    private static Sm4GcmHkdfStreamingKey creatSm4GcmHkdfStreamingKey(
        Sm4GcmHkdfStreamingParameters parameters, @Nullable Integer idRequirement)
        throws GeneralSecurityException {
        return Sm4GcmHkdfStreamingKey.create(
            parameters, SecretBytes.randomBytes(parameters.getKeySizeBytes()));
    }

    @AccessesPartialKey
    static Sm4GcmHkdfStreamingKey createSm4GcmHkdfStreamingKeyFromRandomness(
        Sm4GcmHkdfStreamingParameters parameters,
        InputStream stream,
        @Nullable Integer idRequirement,
        SecretKeyAccess access)
        throws GeneralSecurityException {
        return Sm4GcmHkdfStreamingKey.create(
            parameters, Util.readIntoSecretBytes(stream, parameters.getKeySizeBytes(), access));
    }

    private static Map<String, Parameters> namedParameters() {
        Map<String, Parameters> result = new HashMap<>();
        result.put("SM4_GCM_HKDF_4KB", exceptionIsBug(() -> Sm4GcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setDerivedSm4GcmKeySizeBytes(16)
            .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(4096)
            .build()));
        result.put("SM4_GCM_HKDF_1MB", exceptionIsBug(() -> Sm4GcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setDerivedSm4GcmKeySizeBytes(16)
            .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build()));
        return Collections.unmodifiableMap(result);
    }

    public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
        if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
            throw new GeneralSecurityException(
                "Registering SM4-GCM HKDF Streaming AEAD is not supported in FIPS mode");
        }
        Sm4GcmHkdfStreamingProtoSerialization.register();
        MutableParametersRegistry.globalInstance().putAll(namedParameters());
        MutableKeyDerivationRegistry.globalInstance()
            .add(KEY_DERIVER, Sm4GcmHkdfStreamingParameters.class);
        MutableKeyCreationRegistry.globalInstance()
            .add(KEY_CREATOR, Sm4GcmHkdfStreamingParameters.class);
        MutablePrimitiveRegistry.globalInstance()
            .registerPrimitiveConstructor(SM4_GCM_HKDF_STREAMING_AEAD_PRIMITIVE_CONSTRUCTOR);
        KeyManagerRegistry.globalInstance().registerKeyManager(legacyKeyManager, newKeyAllowed);
    }

    /**
     * @return a {@link KeyTemplate} that generates new instances of Sm4GcmHkdfStreaming keys with
     * the following parameters:
     * <ul>
     *   <li>Size of the main key: 16 bytes
     *   <li>HKDF algo: HMAC-SHA256
     *   <li>Size of SM4-GCM derived keys: 16 bytes
     *   <li>Ciphertext segment size: 4096 bytes
     * </ul>
     */
    public static KeyTemplate sm4GcmHkdf4KBTemplate() {
        return exceptionIsBug(
            () ->
                KeyTemplate.createFrom(
                    Sm4GcmHkdfStreamingParameters.builder()
                        .setKeySizeBytes(16)
                        .setDerivedSm4GcmKeySizeBytes(16)
                        .setCiphertextSegmentSizeBytes(4 * 1024)
                        .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                        .build()));
    }

    /**
     * @return a {@link KeyTemplate} that generates new instances of Sm4GcmHkdfStreaming keys with
     * the following parameters:
     * <ul>
     *   <li>Size of the main key: 16 bytes
     *   <li>HKDF algo: HMAC-SHA256
     *   <li>Size of SM4-GCM derived keys: 16 bytes
     *   <li>Ciphertext segment size: 1MB
     * </ul>
     */
    public static KeyTemplate sm4GcmHkdf1MBTemplate() {
        return exceptionIsBug(
            () ->
                KeyTemplate.createFrom(
                    Sm4GcmHkdfStreamingParameters.builder()
                        .setKeySizeBytes(16)
                        .setDerivedSm4GcmKeySizeBytes(16)
                        .setCiphertextSegmentSizeBytes(1024 * 1024)
                        .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
                        .build()));
    }
}
