package cc.ddrpa.crypto.tink.hybrid;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import cc.ddrpa.crypto.tink.hybrid.internal.Sm2EncryptionHybridDecrypt;
import cc.ddrpa.crypto.tink.hybrid.internal.Sm2EncryptionHybridEncrypt;
import cc.ddrpa.crypto.tink.hybrid.internal.Sm2EncryptionProtoSerialization;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2Curve;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyCreator;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

/**
 * This key manager generates new {@code Sm2EncryptionPrivateKey} keys and produces new instances
 * of {@code Sm2EncryptionHybridEncrypt} (from the public key) and
 * {@code Sm2EncryptionHybridDecrypt} (from the private key).
 */
public final class Sm2EncryptionKeyManager {

    private static final PrimitiveConstructor<Sm2EncryptionPrivateKey, HybridDecrypt>
        HYBRID_DECRYPT_PRIMITIVE_CONSTRUCTOR =
        PrimitiveConstructor.create(
            Sm2EncryptionHybridDecrypt::create,
            Sm2EncryptionPrivateKey.class,
            HybridDecrypt.class);

    private static final PrimitiveConstructor<Sm2EncryptionPublicKey, HybridEncrypt>
        HYBRID_ENCRYPT_PRIMITIVE_CONSTRUCTOR =
        PrimitiveConstructor.create(
            Sm2EncryptionHybridEncrypt::create,
            Sm2EncryptionPublicKey.class,
            HybridEncrypt.class);

    private static final PrivateKeyManager<HybridDecrypt> legacyPrivateKeyManager =
        LegacyKeyManagerImpl.createPrivateKeyManager(
            getKeyType(),
            HybridDecrypt.class,
            cc.ddrpa.crypto.tink.proto.Sm2EncryptionPrivateKey.parser());

    private static final KeyManager<HybridEncrypt> legacyPublicKeyManager =
        LegacyKeyManagerImpl.create(
            Sm2EncryptionPublicKeyManager.getKeyType(),
            HybridEncrypt.class,
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            cc.ddrpa.crypto.tink.proto.Sm2EncryptionPublicKey.parser());

    @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
    private static final KeyCreator<Sm2EncryptionParameters> KEY_CREATOR =
        Sm2EncryptionKeyManager::createSm2EncryptionKey;

    private Sm2EncryptionKeyManager() {
    }

    static String getKeyType() {
        return "type.googleapis.com/ddrpa.crypto.tink.Sm2EncryptionPrivateKey";
    }

    @AccessesPartialKey
    private static Sm2EncryptionPrivateKey createSm2EncryptionKey(
        Sm2EncryptionParameters parameters, @Nullable Integer idRequirement)
        throws GeneralSecurityException {
        AsymmetricCipherKeyPair keyPair = Sm2KeyUtil.generateKeyPair();
        byte[] publicKeyBytes =
            Sm2Curve.encodePointWithoutPrefix(Sm2KeyUtil.getPublicKey(keyPair).getQ());
        byte[] privateKeyBytes =
            Sm2KeyUtil.toFixedLengthBytes(
                Sm2KeyUtil.getPrivateKey(keyPair).getD(), Sm2Curve.COORDINATE_SIZE_BYTES);

        Sm2EncryptionPublicKey publicKey =
            Sm2EncryptionPublicKey.builder()
                .setParameters(parameters)
                .setIdRequirement(idRequirement)
                .setPublicKey(Bytes.copyFrom(publicKeyBytes))
                .build();
        return Sm2EncryptionPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(
                SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()))
            .build();
    }

    private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put(
            "SM2_ENCRYPTION",
            Sm2EncryptionParameters.builder()
                .setVariant(Sm2EncryptionParameters.Variant.TINK)
                .build());
        result.put(
            "SM2_ENCRYPTION_RAW",
            Sm2EncryptionParameters.builder()
                .setVariant(Sm2EncryptionParameters.Variant.NO_PREFIX)
                .build());
        return Collections.unmodifiableMap(result);
    }

    /**
     * Registers the {@link Sm2EncryptionKeyManager} and the {@link Sm2EncryptionPublicKeyManager}
     * with the registry, so that the SM2 encryption keys can be used with Tink.
     */
    public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
        if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
            throw new GeneralSecurityException(
                "Registering SM2 Encryption is not supported in FIPS mode");
        }
        Sm2EncryptionProtoSerialization.register();
        MutableParametersRegistry.globalInstance().putAll(namedParameters());
        MutablePrimitiveRegistry.globalInstance()
            .registerPrimitiveConstructor(HYBRID_ENCRYPT_PRIMITIVE_CONSTRUCTOR);
        MutablePrimitiveRegistry.globalInstance()
            .registerPrimitiveConstructor(HYBRID_DECRYPT_PRIMITIVE_CONSTRUCTOR);
        MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, Sm2EncryptionParameters.class);
        KeyManagerRegistry.globalInstance()
            .registerKeyManager(legacyPrivateKeyManager, newKeyAllowed);
        KeyManagerRegistry.globalInstance().registerKeyManager(legacyPublicKeyManager, false);
    }

    /**
     * @return a {@link KeyTemplate} that generates new instances of SM2 encryption key pairs with
     * the following parameters:
     * <ul>
     *   <li>Hash function: SM3
     *   <li>Curve: sm2p256v1
     *   <li>Ciphertext layout: C1C3C2 (C1 as a 65 byte uncompressed point, C3 a 32 byte SM3
     *       digest)
     *   <li>Associated data: not supported (contextInfo must be null or empty)
     *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
     * </ul>
     */
    public static KeyTemplate sm2EncryptionTemplate() {
        return exceptionIsBug(
            () ->
                KeyTemplate.createFrom(
                    Sm2EncryptionParameters.builder()
                        .setVariant(Sm2EncryptionParameters.Variant.TINK)
                        .build()));
    }

    /**
     * @return a {@link KeyTemplate} that generates new instances of SM2 encryption key pairs with
     * the following parameters:
     * <ul>
     *   <li>Hash function: SM3
     *   <li>Curve: sm2p256v1
     *   <li>Ciphertext layout: C1C3C2 (C1 as a 65 byte uncompressed point, C3 a 32 byte SM3
     *       digest)
     *   <li>Associated data: not supported (contextInfo must be null or empty)
     *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
     * </ul>
     * <p>Keys generated from this template produce raw ciphertexts of exactly {@code 65 + 32 +
     * plaintext.length} bytes. It is compatible with most other libraries implementing GB/T 32918.
     */
    public static KeyTemplate rawSm2EncryptionTemplate() {
        return exceptionIsBug(
            () ->
                KeyTemplate.createFrom(
                    Sm2EncryptionParameters.builder()
                        .setVariant(Sm2EncryptionParameters.Variant.NO_PREFIX)
                        .build()));
    }
}
