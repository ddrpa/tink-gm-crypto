package cc.ddrpa.crypto.tink.aead;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import cc.ddrpa.crypto.tink.aead.internal.Sm4GcmProtoSerialization;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
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
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code Sm4GcmKey} keys and produces new instances of
 * {@code Sm4GcmJce}.
 */
public final class Sm4GcmKeyManager {

    private static final PrimitiveConstructor<Sm4GcmKey, Aead> SM4_GCM_PRIMITIVE_CONSTRUCTOR =
        PrimitiveConstructor.create(Sm4GcmJce::create, Sm4GcmKey.class, Aead.class);
    private static final KeyManager<Aead> legacyKeyManager =
        LegacyKeyManagerImpl.create(
            getKeyType(),
            Aead.class,
            KeyMaterialType.SYMMETRIC,
            cc.ddrpa.crypto.tink.proto.Sm4GcmKey.parser());
    @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
    private static final MutableKeyDerivationRegistry.InsecureKeyCreator<Sm4GcmParameters>
        KEY_DERIVER = Sm4GcmKeyManager::createSm4GcmKeyFromRandomness;
    @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
    private static final MutableKeyCreationRegistry.KeyCreator<Sm4GcmParameters> KEY_CREATOR =
        Sm4GcmKeyManager::createSm4GcmKey;
    private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
        TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

    private Sm4GcmKeyManager() {
    }

    private static void validate(Sm4GcmParameters parameters)
        throws GeneralSecurityException {
        if (parameters.getKeySizeBytes() == 24) {
            throw new GeneralSecurityException("192 bit SM4 GCM Parameters are not valid");
        }
    }

    static String getKeyType() {
        return "type.googleapis.com/ddrpa.crypto.tink.Sm4GcmKey";
    }

    private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put("SM4_GCM", Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.TINK)
            .build());
        result.put(
            "SM4_GCM_RAW",
            Sm4GcmParameters.builder()
                .setIvSizeBytes(12)
                .setTagSizeBytes(16)
                .setVariant(Sm4GcmParameters.Variant.NO_PREFIX)
                .build());
        return Collections.unmodifiableMap(result);
    }

    @AccessesPartialKey
    public static Sm4GcmKey createSm4GcmKeyFromRandomness(
        Sm4GcmParameters parameters,
        InputStream stream,
        @Nullable Integer idRequirement,
        SecretKeyAccess access)
        throws GeneralSecurityException {
        validate(parameters);
        return Sm4GcmKey.builder()
            .setParameters(parameters)
            .setIdRequirement(idRequirement)
            .setKeyBytes(Util.readIntoSecretBytes(stream, parameters.getKeySizeBytes(), access))
            .build();
    }

    @AccessesPartialKey
    private static Sm4GcmKey createSm4GcmKey(
        Sm4GcmParameters parameters, @Nullable Integer idRequirement)
        throws GeneralSecurityException {
        validate(parameters);
        return Sm4GcmKey.builder()
            .setParameters(parameters)
            .setIdRequirement(idRequirement)
            .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
            .build();
    }

    public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
        if (!FIPS.isCompatible()) {
            throw new GeneralSecurityException(
                "Can not use SM4-GCM in FIPS-mode, as BoringCrypto module is not available.");
        }
        Sm4GcmProtoSerialization.register();
        MutablePrimitiveRegistry.globalInstance()
            .registerPrimitiveConstructor(SM4_GCM_PRIMITIVE_CONSTRUCTOR);
        MutableParametersRegistry.globalInstance().putAll(namedParameters());
        MutableKeyDerivationRegistry.globalInstance().add(KEY_DERIVER, Sm4GcmParameters.class);
        MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, Sm4GcmParameters.class);
        KeyManagerRegistry.globalInstance()
            .registerKeyManagerWithFipsCompatibility(legacyKeyManager, FIPS, newKeyAllowed);
    }

    /**
     * @return a {@link KeyTemplate} that generates new instances of SM4-GCM with the following
     * parameters:
     * <ul>
     *   <li>Key size: 16 bytes
     *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
     * </ul>
     * <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance
     * generated by this key template does not support associated data. It might not work at all
     * in older versions.
     */
    public static KeyTemplate sm4GcmTemplate() {
        return exceptionIsBug(
            () ->
                KeyTemplate.createFrom(
                    Sm4GcmParameters.builder()
                        .setIvSizeBytes(12)
                        .setTagSizeBytes(16)
                        .setVariant(Sm4GcmParameters.Variant.TINK)
                        .build()));
    }

    /**
     * @return a {@link KeyTemplate} that generates new instances of SM4-GCM with the following
     * parameters:
     * <ul>
     *   <li>Key size: 16 bytes
     *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
     * </ul>
     * <p>Keys generated from this template should create ciphertexts compatible with other
     * libraries.
     * <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance
     * generated by this key template does not support associated data. It might not work at all
     * in older versions.
     */
    public static KeyTemplate rawSm4GcmTemplate() {
        return exceptionIsBug(
            () ->
                KeyTemplate.createFrom(
                    Sm4GcmParameters.builder()
                        .setIvSizeBytes(12)
                        .setTagSizeBytes(16)
                        .setVariant(Sm4GcmParameters.Variant.NO_PREFIX)
                        .build()));
    }
}
