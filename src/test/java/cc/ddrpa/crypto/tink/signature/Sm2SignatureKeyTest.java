package cc.ddrpa.crypto.tink.signature;

import cc.ddrpa.crypto.tink.sm2.internal.Sm2Curve;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.Test;

import javax.annotation.Nullable;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public final class Sm2SignatureKeyTest {

    private static final Sm2SignatureParameters.Variant NO_PREFIX =
            Sm2SignatureParameters.Variant.NO_PREFIX;
    private static final Sm2SignatureParameters.Variant TINK = Sm2SignatureParameters.Variant.TINK;

    private static KeyMaterial generateKeyMaterial() throws GeneralSecurityException {
        AsymmetricCipherKeyPair keyPair = Sm2KeyUtil.generateKeyPair();
        KeyMaterial material = new KeyMaterial();
        material.privateValue =
                Sm2KeyUtil.toFixedLengthBytes(
                        Sm2KeyUtil.getPrivateKey(keyPair).getD(), Sm2Curve.COORDINATE_SIZE_BYTES);
        material.publicKey =
                Sm2Curve.encodePointWithoutPrefix(Sm2KeyUtil.getPublicKey(keyPair).getQ());
        return material;
    }

    private static Sm2SignatureParameters parameters(Sm2SignatureParameters.Variant variant)
            throws GeneralSecurityException {
        return Sm2SignatureParameters.builder().setVariant(variant).build();
    }

    private static SecretBytes secretBytes(byte[] bytes) {
        return SecretBytes.copyFrom(bytes, InsecureSecretKeyAccess.get());
    }

    private static Sm2SignaturePublicKey buildPublicKey(
            Sm2SignatureParameters parameters, byte[] publicKey, @Nullable Integer idRequirement)
            throws GeneralSecurityException {
        return Sm2SignaturePublicKey.builder()
                .setParameters(parameters)
                .setPublicKey(Bytes.copyFrom(publicKey))
                .setIdRequirement(idRequirement)
                .build();
    }

    private static Sm2SignaturePrivateKey buildPrivateKey(
            Sm2SignaturePublicKey publicKey, byte[] privateValue) throws GeneralSecurityException {
        return Sm2SignaturePrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateValue(secretBytes(privateValue))
                .build();
    }

    @Test
    public void buildNoPrefixPublicKeyAndGetProperties() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2SignatureParameters parameters = parameters(NO_PREFIX);
        Sm2SignaturePublicKey key = buildPublicKey(parameters, material.publicKey, null);
        assertThat(key.getParameters()).isEqualTo(parameters);
        assertThat(key.getPublicKey().toByteArray()).isEqualTo(material.publicKey);
        assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[]{}));
        assertThat(key.getIdRequirementOrNull()).isNull();
    }

    // --------------------------- Public key tests ---------------------------

    @Test
    public void buildTinkPublicKeyAndGetProperties() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2SignatureParameters parameters = parameters(TINK);
        Sm2SignaturePublicKey key = buildPublicKey(parameters, material.publicKey, 0x66AABBCC);
        assertThat(key.getParameters()).isEqualTo(parameters);
        assertThat(key.getPublicKey().toByteArray()).isEqualTo(material.publicKey);
        assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
        assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
    }

    @Test
    public void testPublicKeyEqualities() throws Exception {
        KeyMaterial material1 = generateKeyMaterial();
        KeyMaterial material2 = generateKeyMaterial();
        Sm2SignatureParameters noPrefixParams = parameters(NO_PREFIX);
        Sm2SignatureParameters tinkParams = parameters(TINK);

        new KeyTester()
                .addEqualityGroup(
                        "no prefix public key",
                        buildPublicKey(noPrefixParams, material1.publicKey, null),
                        buildPublicKey(noPrefixParams, material1.publicKey, null))
                .addEqualityGroup(
                        "different public key material",
                        buildPublicKey(noPrefixParams, material2.publicKey, null))
                .addEqualityGroup(
                        "tink public key id 1",
                        buildPublicKey(tinkParams, material1.publicKey, 1))
                .addEqualityGroup(
                        "tink public key id 2",
                        buildPublicKey(tinkParams, material1.publicKey, 2))
                .doTests();
    }

    @Test
    public void emptyBuild_fails() {
        assertThrows(GeneralSecurityException.class, () -> Sm2SignaturePublicKey.builder().build());
    }

    @Test
    public void buildWithoutParameters_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        assertThrows(GeneralSecurityException.class,
                () -> Sm2SignaturePublicKey.builder()
                        .setPublicKey(Bytes.copyFrom(material.publicKey))
                        .build());
    }

    @Test
    public void buildWithoutPublicKey_fails() throws Exception {
        assertThrows(GeneralSecurityException.class,
                () -> Sm2SignaturePublicKey.builder()
                        .setParameters(parameters(NO_PREFIX))
                        .build());
    }

    @Test
    public void buildWithWrongPublicKeyLength_fails() throws Exception {
        assertThrows(GeneralSecurityException.class,
                () -> Sm2SignaturePublicKey.builder()
                        .setParameters(parameters(NO_PREFIX))
                        .setPublicKey(Bytes.copyFrom(new byte[63]))
                        .build());
    }

    @Test
    public void buildWithPointNotOnCurve_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        // Flip the last byte of Y; with overwhelming probability the resulting point is not on the
        // curve.
        byte[] offCurve = Arrays.copyOf(material.publicKey, material.publicKey.length);
        offCurve[offCurve.length - 1] ^= 0x01;
        assertThrows(GeneralSecurityException.class,
                () -> buildPublicKey(parameters(NO_PREFIX), offCurve, null));
    }

    @Test
    public void buildWithIdRequirementButIdNotSet_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        assertThrows(GeneralSecurityException.class,
                () -> buildPublicKey(parameters(TINK), material.publicKey, null));
    }

    @Test
    public void buildWithIdSetButParametersDoNotRequireId_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        assertThrows(GeneralSecurityException.class,
                () -> buildPublicKey(parameters(NO_PREFIX), material.publicKey, 123));
    }

    @Test
    public void buildNoPrefixPrivateKeyAndGetProperties() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2SignatureParameters parameters = parameters(NO_PREFIX);
        Sm2SignaturePublicKey publicKey = buildPublicKey(parameters, material.publicKey, null);
        Sm2SignaturePrivateKey key = buildPrivateKey(publicKey, material.privateValue);
        assertThat(key.getParameters()).isEqualTo(parameters);
        assertThat(key.getPublicKey().equalsKey(publicKey)).isTrue();
        assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[]{}));
        assertThat(key.getIdRequirementOrNull()).isNull();
        assertThat(key.getPrivateValue().toByteArray(InsecureSecretKeyAccess.get()))
                .isEqualTo(material.privateValue);
    }

    // --------------------------- Private key tests ---------------------------

    @Test
    public void buildTinkPrivateKeyAndGetProperties() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2SignatureParameters parameters = parameters(TINK);
        Sm2SignaturePublicKey publicKey = buildPublicKey(parameters, material.publicKey, 123);
        Sm2SignaturePrivateKey key = buildPrivateKey(publicKey, material.privateValue);
        assertThat(key.getParameters()).isEqualTo(parameters);
        assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("010000007B")));
        assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
    }

    @Test
    public void testPrivateKeyEqualities() throws Exception {
        KeyMaterial material1 = generateKeyMaterial();
        KeyMaterial material2 = generateKeyMaterial();
        Sm2SignatureParameters noPrefixParams = parameters(NO_PREFIX);
        Sm2SignatureParameters tinkParams = parameters(TINK);
        Sm2SignaturePublicKey publicKey1 =
                buildPublicKey(noPrefixParams, material1.publicKey, null);
        Sm2SignaturePublicKey publicKey2 =
                buildPublicKey(noPrefixParams, material2.publicKey, null);
        Sm2SignaturePublicKey tinkPublicKey1 =
                buildPublicKey(tinkParams, material1.publicKey, 1);

        new KeyTester()
                .addEqualityGroup(
                        "no prefix private key",
                        buildPrivateKey(publicKey1, material1.privateValue),
                        buildPrivateKey(publicKey1, material1.privateValue))
                .addEqualityGroup(
                        "different private value",
                        buildPrivateKey(publicKey1, material2.privateValue))
                .addEqualityGroup(
                        "different public key material",
                        buildPrivateKey(publicKey2, material2.privateValue))
                .addEqualityGroup(
                        "tink private key",
                        buildPrivateKey(tinkPublicKey1, material1.privateValue))
                .doTests();
    }

    @Test
    public void buildWithoutPublicKey_failsForPrivateKey() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        assertThrows(GeneralSecurityException.class,
                () -> Sm2SignaturePrivateKey.builder()
                        .setPrivateValue(secretBytes(material.privateValue))
                        .build());
    }

    @Test
    public void buildWithoutPrivateValue_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2SignaturePublicKey publicKey = buildPublicKey(parameters(NO_PREFIX),
                material.publicKey, null);
        assertThrows(GeneralSecurityException.class,
                () -> Sm2SignaturePrivateKey.builder().setPublicKey(publicKey).build());
    }

    @Test
    public void buildWithWrongPrivateValueLength_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2SignaturePublicKey publicKey = buildPublicKey(parameters(NO_PREFIX),
                material.publicKey, null);
        assertThrows(GeneralSecurityException.class,
                () -> Sm2SignaturePrivateKey.builder()
                        .setPublicKey(publicKey)
                        .setPrivateValue(secretBytes(new byte[31]))
                        .build());
    }

    @Test
    public void buildWithZeroPrivateValue_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2SignaturePublicKey publicKey = buildPublicKey(parameters(NO_PREFIX),
                material.publicKey, null);
        assertThrows(GeneralSecurityException.class,
                () -> Sm2SignaturePrivateKey.builder()
                        .setPublicKey(publicKey)
                        .setPrivateValue(secretBytes(new byte[32]))
                        .build());
    }

    @Test
    public void buildWithPrivateValueEqualToOrder_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2SignaturePublicKey publicKey = buildPublicKey(parameters(NO_PREFIX),
                material.publicKey, null);
        // The order n of the sm2p256v1 curve, encoded in exactly 32 bytes.
        byte[] order =
                Sm2KeyUtil.toFixedLengthBytes(
                        Sm2Curve.getDomainParameters().getN(), Sm2Curve.COORDINATE_SIZE_BYTES);
        assertThrows(GeneralSecurityException.class,
                () -> Sm2SignaturePrivateKey.builder()
                        .setPublicKey(publicKey)
                        .setPrivateValue(secretBytes(order))
                        .build());
    }

    @Test
    public void testDifferentKeyTypesEquality_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2SignaturePublicKey publicKey = buildPublicKey(parameters(NO_PREFIX),
                material.publicKey, null);
        Sm2SignaturePrivateKey privateKey = buildPrivateKey(publicKey, material.privateValue);
        XChaCha20Poly1305Key xChaCha20Poly1305Key =
                XChaCha20Poly1305Key.create(SecretBytes.randomBytes(32));
        assertThat(publicKey.equalsKey(xChaCha20Poly1305Key)).isFalse();
        assertThat(privateKey.equalsKey(xChaCha20Poly1305Key)).isFalse();
    }

    private static final class KeyMaterial {

        byte[] publicKey;
        byte[] privateValue;
    }
}
