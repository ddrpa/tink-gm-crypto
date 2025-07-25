package cc.ddrpa.crypto.tink.signature;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import cc.ddrpa.crypto.tink.signature.internal.Sm2SignatureProtoSerialization;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Sm2Signature;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code Sm2PrivateKey} keys and produces new instances of
 * {@code PublicKeySign} and {@code PublicKeyVerify}.
 */
public final class Sm2SignatureKeyManager {

    private static final PrimitiveConstructor<Sm2PrivateKey, PublicKeySign> PRIVATE_KEY_SIGN_CONSTRUCTOR =
            PrimitiveConstructor.create(
                    Sm2SignatureKeyManager::createSignPrimitive, Sm2PrivateKey.class, PublicKeySign.class);

    private static final PrimitiveConstructor<Sm2PublicKey, PublicKeyVerify> PUBLIC_KEY_VERIFY_CONSTRUCTOR =
            PrimitiveConstructor.create(
                    Sm2SignatureKeyManager::createVerifyPrimitive, Sm2PublicKey.class, PublicKeyVerify.class);

    private static final KeyManager<PublicKeySign> legacyPrivateKeyManager =
            LegacyKeyManagerImpl.create(
                    getPrivateKeyType(),
                    PublicKeySign.class,
                    KeyMaterialType.ASYMMETRIC_PRIVATE,
                    cc.ddrpa.crypto.tink.proto.Sm2PrivateKey.parser());

    private static final KeyManager<PublicKeyVerify> legacyPublicKeyManager =
            LegacyKeyManagerImpl.create(
                    getPublicKeyType(),
                    PublicKeyVerify.class,
                    KeyMaterialType.ASYMMETRIC_PUBLIC,
                    cc.ddrpa.crypto.tink.proto.Sm2PublicKey.parser());

    @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
    private static final MutableKeyCreationRegistry.KeyCreator<Sm2SignatureParameters> KEY_CREATOR =
            Sm2SignatureKeyManager::createSm2PrivateKey;

    private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
            TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

    private Sm2SignatureKeyManager() {}

    static String getPrivateKeyType() {
        return "type.googleapis.com/ddrpa.crypto.tink.Sm2PrivateKey";
    }

    static String getPublicKeyType() {
        return "type.googleapis.com/ddrpa.crypto.tink.Sm2PublicKey";
    }

    private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put("SM2_SHA256_DER", 
                Sm2SignatureParameters.builder()
                        .setHashAlgorithm(Sm2SignatureParameters.HashAlgorithm.SHA256)
                        .setSignatureEncoding(Sm2SignatureParameters.SignatureEncoding.DER)
                        .setVariant(Sm2SignatureParameters.Variant.TINK)
                        .build());
        result.put("SM2_SHA256_DER_RAW",
                Sm2SignatureParameters.builder()
                        .setHashAlgorithm(Sm2SignatureParameters.HashAlgorithm.SHA256)
                        .setSignatureEncoding(Sm2SignatureParameters.SignatureEncoding.DER)
                        .setVariant(Sm2SignatureParameters.Variant.NO_PREFIX)
                        .build());
        result.put("SM2_SM3_DER",
                Sm2SignatureParameters.builder()
                        .setHashAlgorithm(Sm2SignatureParameters.HashAlgorithm.SM3)
                        .setSignatureEncoding(Sm2SignatureParameters.SignatureEncoding.DER)
                        .setVariant(Sm2SignatureParameters.Variant.TINK)
                        .build());
        result.put("SM2_SM3_DER_RAW",
                Sm2SignatureParameters.builder()
                        .setHashAlgorithm(Sm2SignatureParameters.HashAlgorithm.SM3)
                        .setSignatureEncoding(Sm2SignatureParameters.SignatureEncoding.DER)
                        .setVariant(Sm2SignatureParameters.Variant.NO_PREFIX)
                        .build());
        return Collections.unmodifiableMap(result);
    }

    @AccessesPartialKey
    private static Sm2PrivateKey createSm2PrivateKey(
            Sm2SignatureParameters parameters, @Nullable Integer idRequirement)
            throws GeneralSecurityException {
        // Generate new key pair
        Sm2Signature.KeyPair keyPair = Sm2Signature.generateKeyPair();

        Sm2PublicKey publicKey = Sm2PublicKey.builder()
                .setParameters(parameters)
                .setPublicKeyX(com.google.crypto.tink.util.Bytes.copyFrom(keyPair.getPublicKeyX()))
                .setPublicKeyY(com.google.crypto.tink.util.Bytes.copyFrom(keyPair.getPublicKeyY()))
                .setIdRequirement(idRequirement)
                .build();

        return Sm2PrivateKey.builder()
                .setParameters(parameters)
                .setPrivateKeyValue(SecretBytes.copyFrom(keyPair.getPrivateKey(), InsecureSecretKeyAccess.get()))
                .setPublicKey(publicKey)
                .build();
    }

    @AccessesPartialKey
    private static PublicKeySign createSignPrimitive(Sm2PrivateKey key) throws GeneralSecurityException {
        Sm2Signature.HashAlgorithm hashAlgorithm = 
                key.getParameters().getHashAlgorithm() == Sm2SignatureParameters.HashAlgorithm.SM3
                        ? Sm2Signature.HashAlgorithm.SM3 
                        : Sm2Signature.HashAlgorithm.SHA256;

        Sm2Signature.SignatureEncoding encoding =
                key.getParameters().getSignatureEncoding() == Sm2SignatureParameters.SignatureEncoding.IEEE_P1363
                        ? Sm2Signature.SignatureEncoding.IEEE_P1363
                        : Sm2Signature.SignatureEncoding.DER;

        final Sm2Signature signer = new Sm2Signature(
                key.getPrivateKeyValue().toByteArray(InsecureSecretKeyAccess.get()),
                key.getPublicKey().getPublicKeyX().toByteArray(),
                key.getPublicKey().getPublicKeyY().toByteArray(),
                hashAlgorithm,
                encoding);

        final byte[] outputPrefix = key.getOutputPrefix().toByteArray();

        return new PublicKeySign() {
            @Override
            public byte[] sign(byte[] data) throws GeneralSecurityException {
                byte[] signature = signer.sign(data);
                if (outputPrefix.length == 0) {
                    return signature;
                }
                byte[] result = new byte[outputPrefix.length + signature.length];
                System.arraycopy(outputPrefix, 0, result, 0, outputPrefix.length);
                System.arraycopy(signature, 0, result, outputPrefix.length, signature.length);
                return result;
            }
        };
    }

    @AccessesPartialKey
    private static PublicKeyVerify createVerifyPrimitive(Sm2PublicKey key) throws GeneralSecurityException {
        Sm2Signature.HashAlgorithm hashAlgorithm = 
                key.getParameters().getHashAlgorithm() == Sm2SignatureParameters.HashAlgorithm.SM3
                        ? Sm2Signature.HashAlgorithm.SM3 
                        : Sm2Signature.HashAlgorithm.SHA256;

        Sm2Signature.SignatureEncoding encoding =
                key.getParameters().getSignatureEncoding() == Sm2SignatureParameters.SignatureEncoding.IEEE_P1363
                        ? Sm2Signature.SignatureEncoding.IEEE_P1363
                        : Sm2Signature.SignatureEncoding.DER;

        final Sm2Signature verifier = new Sm2Signature(
                key.getPublicKeyX().toByteArray(),
                key.getPublicKeyY().toByteArray(),
                hashAlgorithm,
                encoding);

        final byte[] outputPrefix = key.getOutputPrefix().toByteArray();

        return new PublicKeyVerify() {
            @Override
            public void verify(byte[] signature, byte[] data) throws GeneralSecurityException {
                if (outputPrefix.length > 0) {
                    if (signature.length < outputPrefix.length) {
                        throw new GeneralSecurityException("SM2 signature verification failed");
                    }
                    // Check that signature starts with the expected prefix
                    for (int i = 0; i < outputPrefix.length; i++) {
                        if (signature[i] != outputPrefix[i]) {
                            throw new GeneralSecurityException("SM2 signature verification failed");
                        }
                    }
                    // Remove the prefix
                    byte[] actualSignature = new byte[signature.length - outputPrefix.length];
                    System.arraycopy(signature, outputPrefix.length, actualSignature, 0, actualSignature.length);
                    signature = actualSignature;
                }

                if (!verifier.verify(signature, data)) {
                    throw new GeneralSecurityException("SM2 signature verification failed");
                }
            }
        };
    }

    public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
        Sm2SignatureProtoSerialization.register();
        MutablePrimitiveRegistry.globalInstance()
                .registerPrimitiveConstructor(PRIVATE_KEY_SIGN_CONSTRUCTOR);
        MutablePrimitiveRegistry.globalInstance()
                .registerPrimitiveConstructor(PUBLIC_KEY_VERIFY_CONSTRUCTOR);
        MutableParametersRegistry.globalInstance().putAll(namedParameters());
        MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, Sm2SignatureParameters.class);
        KeyManagerRegistry.globalInstance()
                .registerKeyManagerWithFipsCompatibility(legacyPrivateKeyManager, FIPS, newKeyAllowed);
        KeyManagerRegistry.globalInstance()
                .registerKeyManagerWithFipsCompatibility(legacyPublicKeyManager, FIPS, newKeyAllowed);
    }

    /**
     * @return a {@link KeyTemplate} that generates new instances of SM2 signature with the following
     *     parameters:
     *     <ul>
     *       <li>Hash algorithm: SM3
     *       <li>Signature encoding: DER
     *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
     *     </ul>
     */
    public static KeyTemplate sm2Sm3Template() {
        return exceptionIsBug(
                () ->
                        KeyTemplate.createFrom(
                                Sm2SignatureParameters.builder()
                                        .setHashAlgorithm(Sm2SignatureParameters.HashAlgorithm.SM3)
                                        .setSignatureEncoding(Sm2SignatureParameters.SignatureEncoding.DER)
                                        .setVariant(Sm2SignatureParameters.Variant.TINK)
                                        .build()));
    }

    /**
     * @return a {@link KeyTemplate} that generates new instances of SM2 signature with the following
     *     parameters:
     *     <ul>
     *       <li>Hash algorithm: SHA256
     *       <li>Signature encoding: DER
     *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
     *     </ul>
     */
    public static KeyTemplate sm2Sha256Template() {
        return exceptionIsBug(
                () ->
                        KeyTemplate.createFrom(
                                Sm2SignatureParameters.builder()
                                        .setHashAlgorithm(Sm2SignatureParameters.HashAlgorithm.SHA256)
                                        .setSignatureEncoding(Sm2SignatureParameters.SignatureEncoding.DER)
                                        .setVariant(Sm2SignatureParameters.Variant.TINK)
                                        .build()));
    }

    /**
     * @return a {@link KeyTemplate} that generates new instances of SM2 signature with the following
     *     parameters:
     *     <ul>
     *       <li>Hash algorithm: SM3
     *       <li>Signature encoding: DER  
     *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
     *     </ul>
     */
    public static KeyTemplate rawSm2Sm3Template() {
        return exceptionIsBug(
                () ->
                        KeyTemplate.createFrom(
                                Sm2SignatureParameters.builder()
                                        .setHashAlgorithm(Sm2SignatureParameters.HashAlgorithm.SM3)
                                        .setSignatureEncoding(Sm2SignatureParameters.SignatureEncoding.DER)
                                        .setVariant(Sm2SignatureParameters.Variant.NO_PREFIX)
                                        .build()));
    }
}