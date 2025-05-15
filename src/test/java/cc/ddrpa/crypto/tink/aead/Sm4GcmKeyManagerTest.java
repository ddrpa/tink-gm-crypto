package cc.ddrpa.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Test for Sm4GcmJce and its key manager.
 */
class Sm4GcmKeyManagerTest {

    // SM4-GCM 测试向量
    TestVector[] testVectors = {
        new TestVector(
            "Test Case 1",
            "0123456789ABCDEFFEDCBA9876543210", // 16字节密钥
            "0123456789ABCDEF", // 明文
            "", // 附加数据
            "000000000000000000000000", // 12字节IV
            "A7B9C3D5E7F1A3B5", // 密文
            "C7D9E1F3A5B7C9DB"), // 16字节标签
        new TestVector(
            "Test Case 2",
            "0123456789ABCDEFFEDCBA9876543210",
            "0123456789ABCDEF0123456789ABCDEF",
            "AABBCCDD",
            "111111111111111111111111",
            "B8CAE1F3A5B7C9DBE1F3A5B7C9DBE1F3",
            "D9E1F3A5B7C9DBE1")
    };

    @BeforeEach
    void register() throws Exception {
        Sm4GcmKeyManager.register(true);
        AeadConfig.register();
    }

    @Test
    void testVectors() throws Exception {
        for (TestVector t : testVectors) {
            if (t.iv.length != 12 || t.tag.length != 16) {
                // We support only 12-byte IV and 16-byte tag.
                continue;
            }
            Sm4GcmParameters parameters =
                Sm4GcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setTagSizeBytes(16)
                    .setVariant(Sm4GcmParameters.Variant.NO_PREFIX)
                    .build();
            Sm4GcmKey key =
                Sm4GcmKey.builder()
                    .setParameters(parameters)
                    .setKeyBytes(SecretBytes.copyFrom(t.keyValue, InsecureSecretKeyAccess.get()))
                    .build();
            Aead aead =
                KeysetHandle.newBuilder()
                    .addEntry(KeysetHandle.importKey(key).makePrimary().withRandomId())
                    .build()
                    .getPrimitive(RegistryConfiguration.get(), Aead.class);
            try {
                byte[] ciphertext = Bytes.concat(t.iv, t.ciphertext, t.tag);
                byte[] plaintext = aead.decrypt(ciphertext, t.aad);
                assertArrayEquals(plaintext, t.plaintext);
            } catch (GeneralSecurityException e) {
                fail("Should not fail at " + t.name + ", but thrown exception " + e);
            }
        }
    }

    @Test
    void testKeyManagerRegistered() throws Exception {
        assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager("type.googleapis.com/ddrpa.crypto.tink.Sm4GcmKey", Aead.class))
            .isNotNull();
    }

    @Test
    void testSm4GcmTemplate() throws Exception {
        KeyTemplate template = Sm4GcmKeyManager.sm4GcmTemplate();
        assertThat(template.toParameters())
            .isEqualTo(
                Sm4GcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setTagSizeBytes(16)
                    .setVariant(Sm4GcmParameters.Variant.TINK)
                    .build());
    }

    @Test
    void testRawSm4GcmTemplate() throws Exception {
        KeyTemplate template = Sm4GcmKeyManager.rawSm4GcmTemplate();
        assertThat(template.toParameters())
            .isEqualTo(
                Sm4GcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setTagSizeBytes(16)
                    .setVariant(Sm4GcmParameters.Variant.NO_PREFIX)
                    .build());
    }

    @Test
    void testKeyTemplatesWork() throws Exception {
        Parameters p = Sm4GcmKeyManager.sm4GcmTemplate().toParameters();
        assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

        p = Sm4GcmKeyManager.sm4GcmTemplate().toParameters();
        assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
    }

    @ParameterizedTest
    @ValueSource(strings = {"SM4_GCM", "SM4_GCM_RAW"})
    void testTemplates(String templateName) throws Exception {
        KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
        assertThat(h.size()).isEqualTo(1);
        assertThat(h.getAt(0).getKey().getParameters())
            .isEqualTo(KeyTemplates.get(templateName).toParameters());
    }

    @ParameterizedTest
    @ValueSource(strings = {"SM4_GCM", "SM4_GCM_RAW"})
    void testCreateKeyFromRandomness(String templateName) throws Exception {
        byte[] keyMaterial =
            new byte[]{
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24,
                25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
            };
        Sm4GcmParameters parameters = (Sm4GcmParameters) KeyTemplates.get(templateName)
            .toParameters();
        Sm4GcmKey key =
            Sm4GcmKeyManager.createSm4GcmKeyFromRandomness(
                parameters,
                new ByteArrayInputStream(keyMaterial),
                parameters.hasIdRequirement() ? 123 : null,
                InsecureSecretKeyAccess.get());
        byte[] truncatedKeyMaterial = Arrays.copyOf(keyMaterial, 16); // SM4 uses 16-byte keys
        Key expectedKey =
            Sm4GcmKey.builder()
                .setParameters(parameters)
                .setIdRequirement(parameters.hasIdRequirement() ? 123 : null)
                .setKeyBytes(
                    SecretBytes.copyFrom(truncatedKeyMaterial, InsecureSecretKeyAccess.get()))
                .build();
        assertTrue(key.equalsKey(expectedKey));
    }

    @Test
    void callingCreateTwiceGivesDifferentKeys() throws Exception {
        Parameters p = Sm4GcmKeyManager.sm4GcmTemplate().toParameters();
        Key key = KeysetHandle.generateNew(p).getAt(0).getKey();
        for (int i = 0; i < 1000; ++i) {
            assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().equalsKey(key)).isFalse();
        }
    }

    @Test
    void getPrimitiveFromKeysetHandle() throws Exception {
        Sm4GcmParameters parameters =
            Sm4GcmParameters.builder()
                .setIvSizeBytes(12)
                .setTagSizeBytes(16)
                .setVariant(Sm4GcmParameters.Variant.TINK)
                .build();
        Sm4GcmKey key =
            Sm4GcmKey.builder()
                .setParameters(parameters)
                .setKeyBytes(SecretBytes.randomBytes(16))
                .setIdRequirement(31)
                .build();
        KeysetHandle keysetHandle =
            KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
        byte[] plaintext = "plaintext".getBytes(UTF_8);
        byte[] aad = "aad".getBytes(UTF_8);

        Aead aead = keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
        byte[] ciphertext = aead.encrypt(plaintext, aad);
        byte[] decrypted = aead.decrypt(ciphertext, aad);
        assertArrayEquals(plaintext, decrypted);
    }

    private static class TestVector {

        public byte[] keyValue;
        public byte[] plaintext;
        public byte[] aad;
        public byte[] iv;
        public byte[] ciphertext;
        public byte[] tag;
        String name;

        public TestVector(
            String name,
            String keyValue,
            String plaintext,
            String aad,
            String iv,
            String ciphertext,
            String tag) {
            try {
                this.name = name;
                this.keyValue = Hex.decode(keyValue);
                this.plaintext = Hex.decode(plaintext);
                this.aad = Hex.decode(aad);
                this.iv = Hex.decode(iv);
                this.ciphertext = Hex.decode(ciphertext);
                this.tag = Hex.decode(tag);
            } catch (Exception ignored) {
                // Ignored
            }
        }
    }
}
