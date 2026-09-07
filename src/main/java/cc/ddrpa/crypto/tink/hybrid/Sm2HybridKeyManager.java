package cc.ddrpa.crypto.tink.hybrid;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import cc.ddrpa.crypto.tink.hybrid.internal.Sm2HybridDecrypt;
import cc.ddrpa.crypto.tink.hybrid.internal.Sm2HybridEncrypt;
import cc.ddrpa.crypto.tink.hybrid.internal.Sm2HybridProtoSerialization;
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
 * This key manager generates new {@code Sm2HybridPrivateKey} keys and produces new instances of
 * {@code Sm2HybridEncrypt} (from the public key) and {@code Sm2HybridDecrypt} (from the private
 * key).
 */
public final class Sm2HybridKeyManager {

    private static final PrimitiveConstructor<Sm2HybridPrivateKey, HybridDecrypt>
        HYBRID_DECRYPT_PRIMITIVE_CONSTRUCTOR =
        PrimitiveConstructor.create(
            Sm2HybridDecrypt::create,
            Sm2HybridPrivateKey.class,
            HybridDecrypt.class);

    private static final PrimitiveConstructor<Sm2HybridPublicKey, HybridEncrypt>
        HYBRID_ENCRYPT_PRIMITIVE_CONSTRUCTOR =
        PrimitiveConstructor.create(
            Sm2HybridEncrypt::create,
            Sm2HybridPublicKey.class,
            HybridEncrypt.class);

    private static final PrivateKeyManager<HybridDecrypt> legacyPrivateKeyManager =
        LegacyKeyManagerImpl.createPrivateKeyManager(
            getKeyType(),
            HybridDecrypt.class,
            cc.ddrpa.crypto.tink.proto.Sm2HybridPrivateKey.parser());

    private static final KeyManager<HybridEncrypt> legacyPublicKeyManager =
        LegacyKeyManagerImpl.create(
            Sm2HybridPublicKeyManager.getKeyType(),
            HybridEncrypt.class,
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            cc.ddrpa.crypto.tink.proto.Sm2HybridPublicKey.parser());

    @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
    private static final KeyCreator<Sm2HybridParameters> KEY_CREATOR =
        Sm2HybridKeyManager::createSm2HybridKey;

    private Sm2HybridKeyManager() {
    }

    static String getKeyType() {
        return "type.googleapis.com/ddrpa.crypto.tink.Sm2HybridPrivateKey";
    }

    @AccessesPartialKey
    private static Sm2HybridPrivateKey createSm2HybridKey(
        Sm2HybridParameters parameters, @Nullable Integer idRequirement)
        throws GeneralSecurityException {
        AsymmetricCipherKeyPair keyPair = Sm2KeyUtil.generateKeyPair();
        byte[] publicKeyBytes =
            Sm2Curve.encodePointWithoutPrefix(Sm2KeyUtil.getPublicKey(keyPair).getQ());
        byte[] privateKeyBytes =
            Sm2KeyUtil.toFixedLengthBytes(
                Sm2KeyUtil.getPrivateKey(keyPair).getD(), Sm2Curve.COORDINATE_SIZE_BYTES);

        Sm2HybridPublicKey publicKey =
            Sm2HybridPublicKey.builder()
                .setParameters(parameters)
                .setIdRequirement(idRequirement)
                .setPublicKey(Bytes.copyFrom(publicKeyBytes))
                .build();
        return Sm2HybridPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(
                SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()))
            .build();
    }

    private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put(
            "SM2_HYBRID",
            Sm2HybridParameters.builder()
                .setVariant(Sm2HybridParameters.Variant.TINK)
                .build());
        result.put(
            "SM2_HYBRID_RAW",
            Sm2HybridParameters.builder()
                .setVariant(Sm2HybridParameters.Variant.NO_PREFIX)
                .build());
        return Collections.unmodifiableMap(result);
    }

    /**
     * Registers the {@link Sm2HybridKeyManager} and the {@link Sm2HybridPublicKeyManager} with the
     * registry, so that the SM2 hybrid encryption keys can be used with Tink.
     */
    public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
        if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
            throw new GeneralSecurityException(
                "Registering SM2 Hybrid Encryption is not supported in FIPS mode");
        }
        Sm2HybridProtoSerialization.register();
        MutableParametersRegistry.globalInstance().putAll(namedParameters());
        MutablePrimitiveRegistry.globalInstance()
            .registerPrimitiveConstructor(HYBRID_ENCRYPT_PRIMITIVE_CONSTRUCTOR);
        MutablePrimitiveRegistry.globalInstance()
            .registerPrimitiveConstructor(HYBRID_DECRYPT_PRIMITIVE_CONSTRUCTOR);
        MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, Sm2HybridParameters.class);
        KeyManagerRegistry.globalInstance()
            .registerKeyManager(legacyPrivateKeyManager, newKeyAllowed);
        KeyManagerRegistry.globalInstance().registerKeyManager(legacyPublicKeyManager, false);
    }

    /**
     * @return a {@link KeyTemplate} that generates new instances of SM2 hybrid key pairs with the
     * following parameters:
     * <ul>
     *   <li>KEM: SM2 key agreement over sm2p256v1 (ephemeral per encryption)
     *   <li>KDF: SM2-KDF (GB/T 32918.4) over SM3
     *   <li>DEM: SM4-GCM with 12 byte nonce and 16 byte tag
     *   <li>Ciphertext layout: C1 (65 bytes, 0x04 || X || Y) || nonce || SM4-GCM ciphertext
     *   <li>Associated data: any contextInfo bytes are authenticated (null treated as empty)
     *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
     * </ul>
     */
    public static KeyTemplate sm2HybridTemplate() {
        return exceptionIsBug(
            () ->
                KeyTemplate.createFrom(
                    Sm2HybridParameters.builder()
                        .setVariant(Sm2HybridParameters.Variant.TINK)
                        .build()));
    }

    /**
     * @return a {@link KeyTemplate} that generates new instances of SM2 hybrid key pairs with the
     * following parameters:
     * <ul>
     *   <li>KEM: SM2 key agreement over sm2p256v1 (ephemeral per encryption)
     *   <li>KDF: SM2-KDF (GB/T 32918.4) over SM3
     *   <li>DEM: SM4-GCM with 12 byte nonce and 16 byte tag
     *   <li>Ciphertext layout: C1 (65 bytes, 0x04 || X || Y) || nonce || SM4-GCM ciphertext
     *   <li>Associated data: any contextInfo bytes are authenticated (null treated as empty)
     *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
     * </ul>
     * <p>Keys generated from this template produce raw ciphertexts of exactly {@code 65 + 12 +
     * plaintext.length + 16} bytes.
     */
    public static KeyTemplate rawSm2HybridTemplate() {
        return exceptionIsBug(
            () ->
                KeyTemplate.createFrom(
                    Sm2HybridParameters.builder()
                        .setVariant(Sm2HybridParameters.Variant.NO_PREFIX)
                        .build()));
    }
}
