package cc.ddrpa.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cc.ddrpa.crypto.tink.sm2.internal.Sm2Curve;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.annotation.Nullable;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.Test;

public final class Sm2EncryptionKeyTest {

    private static final Sm2EncryptionParameters.Variant NO_PREFIX =
        Sm2EncryptionParameters.Variant.NO_PREFIX;
    private static final Sm2EncryptionParameters.Variant TINK =
        Sm2EncryptionParameters.Variant.TINK;

    private static final class KeyMaterial {

        byte[] publicKey;
        byte[] privateValue;
    }

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

    private static Sm2EncryptionParameters parameters(Sm2EncryptionParameters.Variant variant)
        throws GeneralSecurityException {
        return Sm2EncryptionParameters.builder().setVariant(variant).build();
    }

    private static SecretBytes secretBytes(byte[] bytes) {
        return SecretBytes.copyFrom(bytes, InsecureSecretKeyAccess.get());
    }

    private static Sm2EncryptionPublicKey buildPublicKey(
        Sm2EncryptionParameters parameters, byte[] publicKey, @Nullable Integer idRequirement)
        throws GeneralSecurityException {
        return Sm2EncryptionPublicKey.builder()
            .setParameters(parameters)
            .setPublicKey(Bytes.copyFrom(publicKey))
            .setIdRequirement(idRequirement)
            .build();
    }

    private static Sm2EncryptionPrivateKey buildPrivateKey(
        Sm2EncryptionPublicKey publicKey, byte[] privateValue) throws GeneralSecurityException {
        return Sm2EncryptionPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(secretBytes(privateValue))
            .build();
    }

    // --------------------------- Public key tests ---------------------------

    @Test
    public void buildNoPrefixPublicKeyAndGetProperties() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2EncryptionParameters parameters = parameters(NO_PREFIX);
        Sm2EncryptionPublicKey key = buildPublicKey(parameters, material.publicKey, null);
        assertThat(key.getParameters()).isEqualTo(parameters);
        assertThat(key.getPublicKey().toByteArray()).isEqualTo(material.publicKey);
        assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[]{}));
        assertThat(key.getIdRequirementOrNull()).isNull();
    }

    @Test
    public void buildTinkPublicKeyAndGetProperties() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2EncryptionParameters parameters = parameters(TINK);
        Sm2EncryptionPublicKey key = buildPublicKey(parameters, material.publicKey, 0x66AABBCC);
        assertThat(key.getParameters()).isEqualTo(parameters);
        assertThat(key.getPublicKey().toByteArray()).isEqualTo(material.publicKey);
        assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
        assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
    }

    @Test
    public void testPublicKeyEqualities() throws Exception {
        KeyMaterial material1 = generateKeyMaterial();
        KeyMaterial material2 = generateKeyMaterial();
        Sm2EncryptionParameters noPrefixParams = parameters(NO_PREFIX);
        Sm2EncryptionParameters tinkParams = parameters(TINK);

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
        assertThrows(GeneralSecurityException.class,
            () -> Sm2EncryptionPublicKey.builder().build());
    }

    @Test
    public void buildWithoutParameters_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        assertThrows(GeneralSecurityException.class,
            () -> Sm2EncryptionPublicKey.builder()
                .setPublicKey(Bytes.copyFrom(material.publicKey))
                .build());
    }

    @Test
    public void buildWithoutPublicKey_fails() throws Exception {
        assertThrows(GeneralSecurityException.class,
            () -> Sm2EncryptionPublicKey.builder()
                .setParameters(parameters(NO_PREFIX))
                .build());
    }

    @Test
    public void buildWithWrongPublicKeyLength_fails() throws Exception {
        assertThrows(GeneralSecurityException.class,
            () -> Sm2EncryptionPublicKey.builder()
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

    // --------------------------- Private key tests ---------------------------

    @Test
    public void buildNoPrefixPrivateKeyAndGetProperties() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2EncryptionParameters parameters = parameters(NO_PREFIX);
        Sm2EncryptionPublicKey publicKey = buildPublicKey(parameters, material.publicKey, null);
        Sm2EncryptionPrivateKey key = buildPrivateKey(publicKey, material.privateValue);
        assertThat(key.getParameters()).isEqualTo(parameters);
        assertThat(key.getPublicKey().equalsKey(publicKey)).isTrue();
        assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[]{}));
        assertThat(key.getIdRequirementOrNull()).isNull();
        assertThat(key.getPrivateValue().toByteArray(InsecureSecretKeyAccess.get()))
            .isEqualTo(material.privateValue);
    }

    @Test
    public void buildTinkPrivateKeyAndGetProperties() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2EncryptionParameters parameters = parameters(TINK);
        Sm2EncryptionPublicKey publicKey = buildPublicKey(parameters, material.publicKey, 123);
        Sm2EncryptionPrivateKey key = buildPrivateKey(publicKey, material.privateValue);
        assertThat(key.getParameters()).isEqualTo(parameters);
        assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("010000007B")));
        assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
    }

    @Test
    public void testPrivateKeyEqualities() throws Exception {
        KeyMaterial material1 = generateKeyMaterial();
        KeyMaterial material2 = generateKeyMaterial();
        Sm2EncryptionParameters noPrefixParams = parameters(NO_PREFIX);
        Sm2EncryptionParameters tinkParams = parameters(TINK);
        Sm2EncryptionPublicKey publicKey1 =
            buildPublicKey(noPrefixParams, material1.publicKey, null);
        Sm2EncryptionPublicKey publicKey2 =
            buildPublicKey(noPrefixParams, material2.publicKey, null);
        Sm2EncryptionPublicKey tinkPublicKey1 =
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
            () -> Sm2EncryptionPrivateKey.builder()
                .setPrivateValue(secretBytes(material.privateValue))
                .build());
    }

    @Test
    public void buildWithoutPrivateValue_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2EncryptionPublicKey publicKey = buildPublicKey(parameters(NO_PREFIX),
            material.publicKey, null);
        assertThrows(GeneralSecurityException.class,
            () -> Sm2EncryptionPrivateKey.builder().setPublicKey(publicKey).build());
    }

    @Test
    public void buildWithWrongPrivateValueLength_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2EncryptionPublicKey publicKey = buildPublicKey(parameters(NO_PREFIX),
            material.publicKey, null);
        assertThrows(GeneralSecurityException.class,
            () -> Sm2EncryptionPrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateValue(secretBytes(new byte[31]))
                .build());
    }

    @Test
    public void buildWithZeroPrivateValue_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2EncryptionPublicKey publicKey = buildPublicKey(parameters(NO_PREFIX),
            material.publicKey, null);
        assertThrows(GeneralSecurityException.class,
            () -> Sm2EncryptionPrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateValue(secretBytes(new byte[32]))
                .build());
    }

    @Test
    public void buildWithPrivateValueEqualToOrder_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2EncryptionPublicKey publicKey = buildPublicKey(parameters(NO_PREFIX),
            material.publicKey, null);
        // The order n of the sm2p256v1 curve, encoded in exactly 32 bytes.
        byte[] order =
            Sm2KeyUtil.toFixedLengthBytes(
                Sm2Curve.getDomainParameters().getN(), Sm2Curve.COORDINATE_SIZE_BYTES);
        assertThrows(GeneralSecurityException.class,
            () -> Sm2EncryptionPrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateValue(secretBytes(order))
                .build());
    }

    @Test
    public void testDifferentKeyTypesEquality_fails() throws Exception {
        KeyMaterial material = generateKeyMaterial();
        Sm2EncryptionPublicKey publicKey = buildPublicKey(parameters(NO_PREFIX),
            material.publicKey, null);
        Sm2EncryptionPrivateKey privateKey = buildPrivateKey(publicKey, material.privateValue);
        XChaCha20Poly1305Key xChaCha20Poly1305Key =
            XChaCha20Poly1305Key.create(SecretBytes.randomBytes(32));
        assertThat(publicKey.equalsKey(xChaCha20Poly1305Key)).isFalse();
        assertThat(privateKey.equalsKey(xChaCha20Poly1305Key)).isFalse();
    }
}
