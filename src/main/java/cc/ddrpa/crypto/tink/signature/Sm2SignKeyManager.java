package cc.ddrpa.crypto.tink.signature;

import cc.ddrpa.crypto.tink.signature.internal.Sm2PublicKeySign;
import cc.ddrpa.crypto.tink.signature.internal.Sm2PublicKeyVerify;
import cc.ddrpa.crypto.tink.signature.internal.Sm2SignatureProtoSerialization;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2Curve;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.*;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.*;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import javax.annotation.Nullable;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

/**
 * This key manager generates new {@code Sm2SignaturePrivateKey} keys and produces new instances of
 * {@code Sm2PublicKeySign}.
 */
public final class Sm2SignKeyManager {

    private static final PrimitiveConstructor<Sm2SignaturePrivateKey, PublicKeySign>
            PUBLIC_KEY_SIGN_PRIMITIVE_CONSTRUCTOR =
            PrimitiveConstructor.create(
                    Sm2PublicKeySign::create, Sm2SignaturePrivateKey.class, PublicKeySign.class);

    private static final PrimitiveConstructor<Sm2SignaturePublicKey, PublicKeyVerify>
            PUBLIC_KEY_VERIFY_PRIMITIVE_CONSTRUCTOR =
            PrimitiveConstructor.create(
                    Sm2PublicKeyVerify::create, Sm2SignaturePublicKey.class, PublicKeyVerify.class);

    private static final PrivateKeyManager<PublicKeySign> legacyPrivateKeyManager =
            LegacyKeyManagerImpl.createPrivateKeyManager(
                    getKeyType(),
                    PublicKeySign.class,
                    cc.ddrpa.crypto.tink.proto.Sm2SignaturePrivateKey.parser());

    private static final KeyManager<PublicKeyVerify> legacyPublicKeyManager =
            LegacyKeyManagerImpl.create(
                    Sm2VerifyKeyManager.getKeyType(),
                    PublicKeyVerify.class,
                    KeyMaterialType.ASYMMETRIC_PUBLIC,
                    cc.ddrpa.crypto.tink.proto.Sm2SignaturePublicKey.parser());

    @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
    private static final KeyCreator<Sm2SignatureParameters> KEY_CREATOR =
            Sm2SignKeyManager::createSm2SignatureKey;

    private Sm2SignKeyManager() {
    }

    static String getKeyType() {
        return "type.googleapis.com/ddrpa.crypto.tink.Sm2SignaturePrivateKey";
    }

    @AccessesPartialKey
    private static Sm2SignaturePrivateKey createSm2SignatureKey(
            Sm2SignatureParameters parameters, @Nullable Integer idRequirement)
            throws GeneralSecurityException {
        AsymmetricCipherKeyPair keyPair = Sm2KeyUtil.generateKeyPair();
        byte[] publicKeyBytes =
                Sm2Curve.encodePointWithoutPrefix(Sm2KeyUtil.getPublicKey(keyPair).getQ());
        byte[] privateKeyBytes =
                Sm2KeyUtil.toFixedLengthBytes(
                        Sm2KeyUtil.getPrivateKey(keyPair).getD(), Sm2Curve.COORDINATE_SIZE_BYTES);

        Sm2SignaturePublicKey publicKey =
                Sm2SignaturePublicKey.builder()
                        .setParameters(parameters)
                        .setIdRequirement(idRequirement)
                        .setPublicKey(Bytes.copyFrom(publicKeyBytes))
                        .build();
        return Sm2SignaturePrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateValue(
                        SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()))
                .build();
    }

    private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put(
                "SM2_SIGN",
                Sm2SignatureParameters.builder()
                        .setVariant(Sm2SignatureParameters.Variant.TINK)
                        .build());
        result.put(
                "SM2_SIGN_RAW",
                Sm2SignatureParameters.builder()
                        .setVariant(Sm2SignatureParameters.Variant.NO_PREFIX)
                        .build());
        return Collections.unmodifiableMap(result);
    }

    /**
     * Registers the {@link Sm2SignKeyManager} and the {@link Sm2VerifyKeyManager} with the
     * registry, so that the SM2 signature keys can be used with Tink.
     */
    public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
        if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
            throw new GeneralSecurityException(
                    "Registering SM2 Signature is not supported in FIPS mode");
        }
        Sm2SignatureProtoSerialization.register();
        MutableParametersRegistry.globalInstance().putAll(namedParameters());
        MutablePrimitiveRegistry.globalInstance()
                .registerPrimitiveConstructor(PUBLIC_KEY_SIGN_PRIMITIVE_CONSTRUCTOR);
        MutablePrimitiveRegistry.globalInstance()
                .registerPrimitiveConstructor(PUBLIC_KEY_VERIFY_PRIMITIVE_CONSTRUCTOR);
        MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, Sm2SignatureParameters.class);
        KeyManagerRegistry.globalInstance()
                .registerKeyManager(legacyPrivateKeyManager, newKeyAllowed);
        KeyManagerRegistry.globalInstance().registerKeyManager(legacyPublicKeyManager, false);
    }

    /**
     * @return a {@link KeyTemplate} that generates new instances of SM2 signature keys with the
     * following parameters:
     * <ul>
     *   <li>Hash function: SM3
     *   <li>Curve: sm2p256v1
     *   <li>Signature encoding: raw {@code r || s} (64 bytes, no DER wrapper)
     *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
     * </ul>
     */
    public static KeyTemplate sm2SignTemplate() {
        return exceptionIsBug(
                () ->
                        KeyTemplate.createFrom(
                                Sm2SignatureParameters.builder()
                                        .setVariant(Sm2SignatureParameters.Variant.TINK)
                                        .build()));
    }

    /**
     * @return a {@link KeyTemplate} that generates new instances of SM2 signature keys with the
     * following parameters:
     * <ul>
     *   <li>Hash function: SM3
     *   <li>Curve: sm2p256v1
     *   <li>Signature encoding: raw {@code r || s} (64 bytes, no DER wrapper)
     *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
     * </ul>
     * <p>Keys generated from this template should create raw signatures of exactly 64 bytes. It is
     * compatible with most other libraries implementing GB/T 32918.
     */
    public static KeyTemplate rawSm2SignTemplate() {
        return exceptionIsBug(
                () ->
                        KeyTemplate.createFrom(
                                Sm2SignatureParameters.builder()
                                        .setVariant(Sm2SignatureParameters.Variant.NO_PREFIX)
                                        .build()));
    }
}
