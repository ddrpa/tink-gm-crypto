package cc.ddrpa.crypto.tink.hybrid;

import cc.ddrpa.crypto.tink.aead.internal.Sm4GcmJceUtil;
import cc.ddrpa.crypto.tink.hybrid.internal.Sm2HybridDecrypt;
import cc.ddrpa.crypto.tink.hybrid.internal.Sm2HybridEncrypt;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2Curve;
import com.google.crypto.tink.*;
import com.google.crypto.tink.hybrid.HybridDecryptWrapper;
import com.google.crypto.tink.hybrid.HybridEncryptWrapper;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for Sm2HybridKeyManager and Sm2HybridPublicKeyManager.
 */
class Sm2HybridKeyManagerTest {

    // Layout of the SM2 hybrid (F2, "SM2-KEM + SM4-GCM DEM") ciphertext body:
    // C1 (65 bytes, 0x04 || X || Y) + nonce (12 bytes) + SM4-GCM output (ciphertext || tag).
    private static final int C1_SIZE = Sm2Curve.UNCOMPRESSED_POINT_SIZE;
    private static final int NONCE_SIZE = Sm4GcmJceUtil.IV_SIZE_IN_BYTES;
    private static final int TAG_SIZE = Sm4GcmJceUtil.TAG_SIZE_IN_BYTES;
    /**
     * Minimal ciphertext body length: C1 + nonce + tag (empty plaintext).
     */
    private static final int MIN_BODY_SIZE = C1_SIZE + NONCE_SIZE + TAG_SIZE;

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static SecretBytes secretBytes(byte[] bytes) {
        return SecretBytes.copyFrom(bytes, InsecureSecretKeyAccess.get());
    }

    private static HybridDecrypt getDecrypt(KeysetHandle privateHandle)
            throws GeneralSecurityException {
        return privateHandle.getPrimitive(RegistryConfiguration.get(), HybridDecrypt.class);
    }

    private static HybridEncrypt getEncrypt(KeysetHandle publicHandle)
            throws GeneralSecurityException {
        return publicHandle.getPrimitive(RegistryConfiguration.get(), HybridEncrypt.class);
    }

    /**
     * Asserts that {@code decrypt.decrypt} fails with the uniform generic message shared by all
     * ciphertext failures (wrong prefix, wrong length, malformed or off-curve C1, SM4-GCM
     * authentication failure, wrong contextInfo, ...).
     */
    private static void assertDecryptionFailsWithGenericMessage(
            HybridDecrypt decrypt, byte[] ciphertext, byte[] contextInfo) {
        GeneralSecurityException e = assertThrows(GeneralSecurityException.class,
                () -> decrypt.decrypt(ciphertext, contextInfo));
        assertThat(e.getMessage()).isEqualTo("Decryption failed");
    }

    @BeforeEach
    void register() throws Exception {
        // Registers the HybridEncrypt / HybridDecrypt wrappers (used by KeysetHandle to obtain
        // primitives from keysets), without pulling in the whole HybridConfig.
        HybridEncryptWrapper.register();
        HybridDecryptWrapper.register();
        Sm2HybridKeyManager.registerPair(true);
    }

    @Test
    void testKeyManagersRegistered() throws Exception {
        assertThat(KeyManagerRegistry.globalInstance()
                .getKeyManager(Sm2HybridKeyManager.getKeyType(), HybridDecrypt.class)).isNotNull();
        assertThat(KeyManagerRegistry.globalInstance()
                .getKeyManager(Sm2HybridPublicKeyManager.getKeyType(), HybridEncrypt.class))
                .isNotNull();
    }

    @Test
    void encryptDecryptRoundTripThroughKeysetHandle() throws Exception {
        // Exercise both templates (TINK and RAW), several plaintexts (including the empty
        // plaintext, which SM4-GCM supports) and null/empty contextInfo.
        KeysetHandle tinkPrivateHandle =
                KeysetHandle.generateNew(Sm2HybridKeyManager.sm2HybridTemplate().toParameters());
        KeysetHandle rawPrivateHandle =
                KeysetHandle.generateNew(Sm2HybridKeyManager.rawSm2HybridTemplate().toParameters());
        for (KeysetHandle privateHandle : new KeysetHandle[]{tinkPrivateHandle, rawPrivateHandle}) {
            HybridDecrypt decrypt = getDecrypt(privateHandle);
            HybridEncrypt encrypt = getEncrypt(privateHandle.getPublicKeysetHandle());
            byte[][] plaintexts = {
                    new byte[]{},
                    "hello sm2 hybrid encryption".getBytes(UTF_8),
                    "a somewhat longer message to encrypt and then to decrypt again".getBytes(UTF_8)
            };
            // null and empty contextInfo are both "no associated data" and must behave
            // identically.
            byte[][] contextInfos = {null, new byte[]{}};
            for (byte[] plaintext : plaintexts) {
                for (byte[] contextInfo : contextInfos) {
                    byte[] ciphertext = encrypt.encrypt(plaintext, contextInfo);
                    assertThat(decrypt.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);
                }
            }
        }
    }

    @Test
    void emptyPlaintextRoundTrips() throws Exception {
        KeysetHandle tinkPrivateHandle =
                KeysetHandle.generateNew(Sm2HybridKeyManager.sm2HybridTemplate().toParameters());
        KeysetHandle rawPrivateHandle =
                KeysetHandle.generateNew(Sm2HybridKeyManager.rawSm2HybridTemplate().toParameters());

        // Keyset level, TINK variant.
        HybridEncrypt tinkEncrypt = getEncrypt(tinkPrivateHandle.getPublicKeysetHandle());
        HybridDecrypt tinkDecrypt = getDecrypt(tinkPrivateHandle);
        byte[] tinkCiphertext = tinkEncrypt.encrypt(new byte[]{}, null);
        assertThat(tinkCiphertext.length).isEqualTo(5 + MIN_BODY_SIZE);
        assertThat(tinkDecrypt.decrypt(tinkCiphertext, null)).isEqualTo(new byte[]{});

        // Keyset level, RAW variant: the body is exactly the minimal 93 bytes.
        HybridEncrypt rawEncrypt = getEncrypt(rawPrivateHandle.getPublicKeysetHandle());
        HybridDecrypt rawDecrypt = getDecrypt(rawPrivateHandle);
        byte[] rawCiphertext = rawEncrypt.encrypt(new byte[]{}, "empty plaintext".getBytes(UTF_8));
        assertThat(rawCiphertext.length).isEqualTo(MIN_BODY_SIZE);
        assertThat(rawDecrypt.decrypt(rawCiphertext, "empty plaintext".getBytes(UTF_8)))
                .isEqualTo(new byte[]{});

        // Primitive level.
        Sm2HybridPublicKey publicKey =
                (Sm2HybridPublicKey) rawPrivateHandle.getPublicKeysetHandle().getAt(0).getKey();
        Sm2HybridPrivateKey privateKey = (Sm2HybridPrivateKey) rawPrivateHandle.getAt(0).getKey();
        HybridEncrypt directEncrypt = Sm2HybridEncrypt.create(publicKey);
        HybridDecrypt directDecrypt = Sm2HybridDecrypt.create(privateKey);
        byte[] directCiphertext = directEncrypt.encrypt(new byte[]{}, null);
        assertThat(directCiphertext.length).isEqualTo(MIN_BODY_SIZE);
        assertThat(directDecrypt.decrypt(directCiphertext, null)).isEqualTo(new byte[]{});
    }

    @Test
    void contextInfoIsAuthenticated() throws Exception {
        KeysetHandle privateHandle =
                KeysetHandle.generateNew(Sm2HybridKeyManager.sm2HybridTemplate().toParameters());
        KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
        Sm2HybridPublicKey publicKey = (Sm2HybridPublicKey) publicHandle.getAt(0).getKey();
        Sm2HybridPrivateKey privateKey =
                (Sm2HybridPrivateKey) privateHandle.getAt(0).getKey();
        // Use the direct primitives for the exact semantic assertions (the wrapper only surfaces a
        // generic error).
        HybridEncrypt directEncrypt = Sm2HybridEncrypt.create(publicKey);
        HybridDecrypt directDecrypt = Sm2HybridDecrypt.create(privateKey);

        byte[] plaintext = "message with context".getBytes(UTF_8);
        byte[] contextX = "context X".getBytes(UTF_8);
        byte[] contextY = "context Y".getBytes(UTF_8);

        // Encrypting with context X, decrypting with the same context X works.
        byte[] ciphertextX = directEncrypt.encrypt(plaintext, contextX);
        assertThat(directDecrypt.decrypt(ciphertextX, contextX)).isEqualTo(plaintext);
        // Decrypting with a different context Y fails through the SM4-GCM tag (uniform error).
        assertDecryptionFailsWithGenericMessage(directDecrypt, ciphertextX, contextY);
        // Decrypting with null context (no AAD) also fails.
        assertDecryptionFailsWithGenericMessage(directDecrypt, ciphertextX, null);

        // null and empty contextInfo are interchangeable: encrypting with empty and decrypting
        // with null (and vice versa) succeeds.
        byte[] ciphertextEmpty = directEncrypt.encrypt(plaintext, new byte[]{});
        assertThat(directDecrypt.decrypt(ciphertextEmpty, null)).isEqualTo(plaintext);
        byte[] ciphertextNull = directEncrypt.encrypt(plaintext, null);
        assertThat(directDecrypt.decrypt(ciphertextNull, new byte[]{})).isEqualTo(plaintext);

        // Keyset level: at least one wrong-context case must fail too.
        HybridDecrypt decrypt = getDecrypt(privateHandle);
        HybridEncrypt encrypt = getEncrypt(publicHandle);
        byte[] keysetCiphertext = encrypt.encrypt(plaintext, contextX);
        assertThat(decrypt.decrypt(keysetCiphertext, contextX)).isEqualTo(plaintext);
        assertThrows(GeneralSecurityException.class,
                () -> decrypt.decrypt(keysetCiphertext, contextY));
    }

    @Test
    void rawCiphertextsHaveStandardLayout() throws Exception {
        KeysetHandle privateHandle =
                KeysetHandle.generateNew(
                        Sm2HybridKeyManager.rawSm2HybridTemplate().toParameters());
        HybridDecrypt decrypt = getDecrypt(privateHandle);
        KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
        HybridEncrypt encrypt = getEncrypt(publicHandle);

        byte[] plaintext = "raw sm2 hybrid encryption".getBytes(UTF_8);
        byte[] contextInfo = "ctx for raw".getBytes(UTF_8);
        byte[] ciphertext = encrypt.encrypt(plaintext, contextInfo);
        // A raw (NO_PREFIX) ciphertext is exactly the 65 + 12 + plaintext.length + 16 byte
        // C1 || nonce || SM4-GCM body, starting with the 0x04 uncompressed point prefix.
        assertThat(ciphertext.length).isEqualTo(C1_SIZE + NONCE_SIZE + plaintext.length + TAG_SIZE);
        assertThat(ciphertext[0]).isEqualTo((byte) 0x04);
        assertThat(decrypt.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);

        // The empty plaintext yields exactly the minimal 93 byte body.
        byte[] emptyCiphertext = encrypt.encrypt(new byte[]{}, null);
        assertThat(emptyCiphertext.length).isEqualTo(MIN_BODY_SIZE);
        assertThat(decrypt.decrypt(emptyCiphertext, null)).isEqualTo(new byte[]{});

        // Encrypting the same plaintext twice must produce different ciphertexts (fresh ephemeral
        // SM2 key and fresh nonce per call).
        byte[] ciphertext2 = encrypt.encrypt(plaintext, contextInfo);
        assertThat(ciphertext).isNotEqualTo(ciphertext2);
        assertThat(decrypt.decrypt(ciphertext2, contextInfo)).isEqualTo(plaintext);
    }

    @Test
    void tinkCiphertextsArePrefixedWithKeyId() throws Exception {
        KeysetHandle privateHandle =
                KeysetHandle.generateNew(Sm2HybridKeyManager.sm2HybridTemplate().toParameters());
        int id = privateHandle.getAt(0).getId();
        Sm2HybridPrivateKey privateKey =
                (Sm2HybridPrivateKey) privateHandle.getAt(0).getKey();
        assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(id);

        HybridDecrypt decrypt = getDecrypt(privateHandle);
        HybridEncrypt encrypt = getEncrypt(privateHandle.getPublicKeysetHandle());
        byte[] plaintext = "message".getBytes(UTF_8);
        byte[] contextInfo = "prefixed".getBytes(UTF_8);
        byte[] ciphertext = encrypt.encrypt(plaintext, contextInfo);

        // TINK prefix: 0x01 followed by the 4-byte big-endian key id, then the standard
        // C1 || nonce || SM4-GCM body.
        assertThat(ciphertext.length)
                .isEqualTo(5 + C1_SIZE + NONCE_SIZE + plaintext.length + TAG_SIZE);
        assertThat(ciphertext[0]).isEqualTo((byte) 1);
        assertThat(Arrays.copyOf(ciphertext, 5))
                .isEqualTo(privateKey.getOutputPrefix().toByteArray());
        assertThat(ciphertext).isEqualTo(concat(privateKey.getOutputPrefix().toByteArray(),
                Arrays.copyOfRange(ciphertext, 5, ciphertext.length)));
        assertThat(decrypt.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);
    }

    @Test
    void twoKeyKeysetWorks() throws Exception {
        KeysetHandle keyAHandle =
                KeysetHandle.generateNew(Sm2HybridKeyManager.sm2HybridTemplate().toParameters());
        KeysetHandle keyBHandle =
                KeysetHandle.generateNew(Sm2HybridKeyManager.sm2HybridTemplate().toParameters());
        // Extremely unlikely, but make sure the two keys have different ids (hence different
        // prefixes).
        while (keyBHandle.getAt(0).getId() == keyAHandle.getAt(0).getId()) {
            keyBHandle =
                    KeysetHandle.generateNew(
                            Sm2HybridKeyManager.sm2HybridTemplate().toParameters());
        }
        Sm2HybridPrivateKey keyA = (Sm2HybridPrivateKey) keyAHandle.getAt(0).getKey();
        Sm2HybridPrivateKey keyB = (Sm2HybridPrivateKey) keyBHandle.getAt(0).getKey();

        KeysetHandle twoKeyHandle =
                KeysetHandle.newBuilder()
                        .addEntry(KeysetHandle.importKey(keyA).makePrimary())
                        .addEntry(KeysetHandle.importKey(keyB))
                        .build();
        assertThat(twoKeyHandle.size()).isEqualTo(2);

        HybridDecrypt twoKeyDecrypt = getDecrypt(twoKeyHandle);
        HybridEncrypt keyAEncrypt = getEncrypt(keyAHandle.getPublicKeysetHandle());
        HybridEncrypt keyBEncrypt = getEncrypt(keyBHandle.getPublicKeysetHandle());
        byte[] data = "prefix dispatch".getBytes(UTF_8);
        byte[] contextInfo = "two keys".getBytes(UTF_8);

        // Ciphertexts encrypted by either key decrypt with the two-key private handle (dispatched
        // via the output prefix).
        byte[] keyACiphertext = keyAEncrypt.encrypt(data, contextInfo);
        assertThat(twoKeyDecrypt.decrypt(keyACiphertext, contextInfo)).isEqualTo(data);
        byte[] keyBCiphertext = keyBEncrypt.encrypt(data, contextInfo);
        assertThat(twoKeyDecrypt.decrypt(keyBCiphertext, contextInfo)).isEqualTo(data);

        // A ciphertext encrypted by key B does not decrypt with a private handle which only
        // contains key A.
        HybridDecrypt keyADecrypt = getDecrypt(keyAHandle);
        assertThrows(GeneralSecurityException.class,
                () -> keyADecrypt.decrypt(keyBCiphertext, contextInfo));
        // A ciphertext from a foreign key (not in the keyset) does not decrypt either.
        KeysetHandle foreignHandle =
                KeysetHandle.generateNew(
                        Sm2HybridKeyManager.sm2HybridTemplate().toParameters());
        HybridEncrypt foreignEncrypt = getEncrypt(foreignHandle.getPublicKeysetHandle());
        byte[] foreignCiphertext = foreignEncrypt.encrypt(data, contextInfo);
        assertThrows(GeneralSecurityException.class,
                () -> twoKeyDecrypt.decrypt(foreignCiphertext, contextInfo));
    }

    @Test
    void tamperedCiphertextsFailUniformly() throws Exception {
        KeysetHandle rawPrivateHandle =
                KeysetHandle.generateNew(
                        Sm2HybridKeyManager.rawSm2HybridTemplate().toParameters());
        Sm2HybridPrivateKey rawPrivateKey =
                (Sm2HybridPrivateKey) rawPrivateHandle.getAt(0).getKey();
        HybridEncrypt rawEncrypt = getEncrypt(rawPrivateHandle.getPublicKeysetHandle());
        HybridDecrypt rawDecrypt = getDecrypt(rawPrivateHandle);
        HybridDecrypt rawDirectDecrypt = Sm2HybridDecrypt.create(rawPrivateKey);

        KeysetHandle tinkPrivateHandle =
                KeysetHandle.generateNew(Sm2HybridKeyManager.sm2HybridTemplate().toParameters());
        Sm2HybridPrivateKey tinkPrivateKey =
                (Sm2HybridPrivateKey) tinkPrivateHandle.getAt(0).getKey();
        HybridEncrypt tinkEncrypt = getEncrypt(tinkPrivateHandle.getPublicKeysetHandle());
        HybridDecrypt tinkDirectDecrypt = Sm2HybridDecrypt.create(tinkPrivateKey);

        byte[] plaintext = "tamper me please".getBytes(UTF_8);
        byte[] contextX = "ctx X".getBytes(UTF_8);
        byte[] contextY = "ctx Y".getBytes(UTF_8);

        // --- Tampering with a raw ciphertext, exercised on the direct primitive so that the
        // uniform generic message is observable. ---
        byte[] rawCiphertext = rawEncrypt.encrypt(plaintext, contextX);
        assertThat(rawDirectDecrypt.decrypt(rawCiphertext, contextX)).isEqualTo(plaintext);

        // Flip one byte inside the SM4-GCM tag (the last byte).
        byte[] flippedTag = Arrays.copyOf(rawCiphertext, rawCiphertext.length);
        flippedTag[flippedTag.length - 1] ^= 0x01;
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt, flippedTag, contextX);
        // Corrupt one byte of the nonce (bytes [65, 77) of the body).
        byte[] corruptedNonce = Arrays.copyOf(rawCiphertext, rawCiphertext.length);
        corruptedNonce[C1_SIZE] ^= 0x01;
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt, corruptedNonce, contextX);
        // Corrupt one byte of the SM4-GCM ciphertext part (immediately after the nonce).
        byte[] corruptedCiphertext = Arrays.copyOf(rawCiphertext, rawCiphertext.length);
        corruptedCiphertext[C1_SIZE + NONCE_SIZE] ^= 0x01;
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt, corruptedCiphertext, contextX);
        // Truncate below the minimal body length (93 bytes) and to random tiny inputs.
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt,
                Arrays.copyOf(rawCiphertext, rawCiphertext.length - 1), contextX);
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt,
                Arrays.copyOf(rawCiphertext, MIN_BODY_SIZE - 1), contextX);
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt, new byte[10], contextX);
        // Replace the 0x04 prefix of C1.
        byte[] badC1Prefix = Arrays.copyOf(rawCiphertext, rawCiphertext.length);
        badC1Prefix[0] = 0x05;
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt, badC1Prefix, contextX);
        // Replace C1 with an off-curve point (flip the last byte of Y inside C1).
        byte[] offCurveC1 = Arrays.copyOf(rawCiphertext, rawCiphertext.length);
        offCurveC1[C1_SIZE - 1] ^= 0x01;
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt, offCurveC1, contextX);
        // Wrong contextInfo must fail through the SM4-GCM tag.
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt, rawCiphertext, contextY);
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt, rawCiphertext, null);

        // The same tampered values also fail through the keyset wrapper (which only surfaces a
        // generic error).
        assertThrows(GeneralSecurityException.class,
                () -> rawDecrypt.decrypt(flippedTag, contextX));
        assertThrows(GeneralSecurityException.class,
                () -> rawDecrypt.decrypt(rawCiphertext, contextY));

        // --- Tampering with a TINK ciphertext. ---
        byte[] tinkCiphertext = tinkEncrypt.encrypt(plaintext, contextX);
        assertThat(tinkDirectDecrypt.decrypt(tinkCiphertext, contextX)).isEqualTo(plaintext);
        byte[] tinkFlippedTag = Arrays.copyOf(tinkCiphertext, tinkCiphertext.length);
        tinkFlippedTag[tinkFlippedTag.length - 1] ^= 0x01;
        assertDecryptionFailsWithGenericMessage(tinkDirectDecrypt, tinkFlippedTag, contextX);
        byte[] tinkBadC1Prefix = Arrays.copyOf(tinkCiphertext, tinkCiphertext.length);
        tinkBadC1Prefix[5] = 0x05;
        assertDecryptionFailsWithGenericMessage(tinkDirectDecrypt, tinkBadC1Prefix, contextX);
        assertDecryptionFailsWithGenericMessage(tinkDirectDecrypt, new byte[0], contextX);

        // --- Cross-variant handling of prefix-stripped TINK ciphertexts. Build a RAW-variant key
        // pair which reuses the TINK key material: the variant only controls the prefix, so a
        // valid prefix-stripped body still decrypts, while the tampered bodies must fail after
        // stripping the prefix. ---
        byte[] tinkPublicKeyBytes = tinkPrivateKey.getPublicKey().getPublicKey().toByteArray();
        byte[] tinkPrivateValue =
                tinkPrivateKey.getPrivateValue().toByteArray(InsecureSecretKeyAccess.get());
        Sm2HybridPublicKey sameKeyRawPublicKey =
                Sm2HybridPublicKey.builder()
                        .setParameters(
                                Sm2HybridParameters.builder()
                                        .setVariant(Sm2HybridParameters.Variant.NO_PREFIX)
                                        .build())
                        .setPublicKey(Bytes.copyFrom(tinkPublicKeyBytes))
                        .build();
        Sm2HybridPrivateKey sameKeyRawPrivateKey =
                Sm2HybridPrivateKey.builder()
                        .setPublicKey(sameKeyRawPublicKey)
                        .setPrivateValue(secretBytes(tinkPrivateValue))
                        .build();
        HybridDecrypt sameKeyRawDecrypt =
                Sm2HybridDecrypt.create(sameKeyRawPrivateKey);
        byte[] strippedValidBody =
                Arrays.copyOfRange(tinkCiphertext, 5, tinkCiphertext.length);
        assertThat(sameKeyRawDecrypt.decrypt(strippedValidBody, contextX)).isEqualTo(plaintext);
        // Tampered bodies must also fail when re-interpreted as raw ciphertexts after stripping
        // the TINK prefix (flipped tag byte; corrupted C1 0x04 prefix).
        byte[] strippedTamperedBody =
                Arrays.copyOfRange(tinkFlippedTag, 5, tinkFlippedTag.length);
        assertDecryptionFailsWithGenericMessage(sameKeyRawDecrypt, strippedTamperedBody, contextX);
        byte[] strippedBadC1Prefix =
                Arrays.copyOfRange(tinkBadC1Prefix, 5, tinkBadC1Prefix.length);
        assertDecryptionFailsWithGenericMessage(sameKeyRawDecrypt, strippedBadC1Prefix, contextX);

        // --- Ciphertexts never leak partial plaintext. ---
        byte[] wrongKeyCiphertext = tinkEncrypt.encrypt(plaintext, contextX);
        HybridDecrypt rawOnlyDecrypt = getDecrypt(rawPrivateHandle);
        // The raw-only handle only accepts ciphertexts without a prefix.
        assertThrows(GeneralSecurityException.class,
                () -> rawOnlyDecrypt.decrypt(wrongKeyCiphertext, contextX));
    }

    @Test
    void jsonKeysetRoundTripWorks() throws Exception {
        KeysetHandle privateHandle =
                KeysetHandle.generateNew(Sm2HybridKeyManager.sm2HybridTemplate().toParameters());
        HybridDecrypt originalDecrypt = getDecrypt(privateHandle);
        KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
        HybridEncrypt originalEncrypt = getEncrypt(publicHandle);
        byte[] message = "hello sm2 hybrid encryption".getBytes(UTF_8);
        byte[] contextInfo = "json round trip".getBytes(UTF_8);
        byte[] originalCiphertext = originalEncrypt.encrypt(message, contextInfo);
        assertThat(originalDecrypt.decrypt(originalCiphertext, contextInfo)).isEqualTo(message);

        Path tempDir = Files.createTempDirectory("tink-sm2-hybrid-json-test");
        Path privateFile = tempDir.resolve("sm2_hybrid_private_keyset.json");
        Path publicFile = tempDir.resolve("sm2_hybrid_public_keyset.json");
        try {
            // Write the private keyset as JSON, read it back and check that key material is
            // preserved and encryption/decryption still works.
            try (OutputStream out = Files.newOutputStream(privateFile)) {
                CleartextKeysetHandle.write(privateHandle, JsonKeysetWriter.withOutputStream(out));
            }
            KeysetHandle parsedPrivateHandle;
            try (InputStream in = Files.newInputStream(privateFile)) {
                parsedPrivateHandle =
                        CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(in));
            }
            assertTrue(parsedPrivateHandle.getAt(0).getKey().equalsKey(
                    privateHandle.getAt(0).getKey()));
            HybridDecrypt parsedDecrypt = getDecrypt(parsedPrivateHandle);
            HybridEncrypt parsedEncrypt = getEncrypt(parsedPrivateHandle.getPublicKeysetHandle());
            byte[] parsedCiphertext = parsedEncrypt.encrypt(message, contextInfo);
            assertThat(parsedDecrypt.decrypt(parsedCiphertext, contextInfo)).isEqualTo(message);
            // The original ciphertext must decrypt with the parsed private keyset.
            assertThat(parsedDecrypt.decrypt(originalCiphertext, contextInfo)).isEqualTo(message);

            // Write only the public keyset as JSON, read it into a fresh handle and encrypt with
            // it; the original (private) handle must be able to decrypt the result.
            try (OutputStream out = Files.newOutputStream(publicFile)) {
                CleartextKeysetHandle.write(publicHandle, JsonKeysetWriter.withOutputStream(out));
            }
            KeysetHandle parsedPublicHandle;
            try (InputStream in = Files.newInputStream(publicFile)) {
                parsedPublicHandle =
                        CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(in));
            }
            HybridEncrypt publicEncrypt = getEncrypt(parsedPublicHandle);
            byte[] publicEncrypted = publicEncrypt.encrypt(message, contextInfo);
            assertThat(originalDecrypt.decrypt(publicEncrypted, contextInfo)).isEqualTo(message);
            assertThat(parsedDecrypt.decrypt(publicEncrypted, contextInfo)).isEqualTo(message);
        } finally {
            Files.deleteIfExists(privateFile);
            Files.deleteIfExists(publicFile);
            Files.deleteIfExists(tempDir);
        }
    }

    @Test
    void sm2EncryptionAndSm2HybridManagersCoexist() throws Exception {
        // The standard SM2 (F1) and the SM2 hybrid (F2) managers can be registered in the same
        // JVM and their ciphertexts do not interfere.
        Sm2EncryptionKeyManager.registerPair(true);

        // F1 round trip.
        KeysetHandle f1PrivateHandle =
                KeysetHandle.generateNew(Sm2EncryptionKeyManager.sm2EncryptionTemplate().toParameters());
        HybridDecrypt f1Decrypt = getDecrypt(f1PrivateHandle);
        HybridEncrypt f1Encrypt = getEncrypt(f1PrivateHandle.getPublicKeysetHandle());
        byte[] f1Message = "f1 message".getBytes(UTF_8);
        byte[] f1Ciphertext = f1Encrypt.encrypt(f1Message, null);
        assertThat(f1Decrypt.decrypt(f1Ciphertext, null)).isEqualTo(f1Message);

        // F2 round trip with a non-empty contextInfo (which F1 does not support).
        KeysetHandle f2PrivateHandle =
                KeysetHandle.generateNew(Sm2HybridKeyManager.sm2HybridTemplate().toParameters());
        HybridDecrypt f2Decrypt = getDecrypt(f2PrivateHandle);
        HybridEncrypt f2Encrypt = getEncrypt(f2PrivateHandle.getPublicKeysetHandle());
        byte[] f2Message = "f2 message".getBytes(UTF_8);
        byte[] f2Context = "f2 context".getBytes(UTF_8);
        byte[] f2Ciphertext = f2Encrypt.encrypt(f2Message, f2Context);
        assertThat(f2Decrypt.decrypt(f2Ciphertext, f2Context)).isEqualTo(f2Message);

        // Cross checks: F1 material (raw, prefixed with a TINK keyset id) is not accepted by the
        // F2 keyset and vice versa.
        assertThrows(GeneralSecurityException.class,
                () -> f1Decrypt.decrypt(f2Ciphertext, null));
        assertThrows(GeneralSecurityException.class,
                () -> f2Decrypt.decrypt(f1Ciphertext, null));

        // Body-level cross check with RAW keysets: an F1 raw C1C3C2 body fed to an F2 raw key
        // must fail (SM4-GCM authentication) even though the C1 part parses as a valid point.
        KeysetHandle f1RawPrivateHandle =
                KeysetHandle.generateNew(
                        Sm2EncryptionKeyManager.rawSm2EncryptionTemplate().toParameters());
        HybridEncrypt f1RawEncrypt = getEncrypt(f1RawPrivateHandle.getPublicKeysetHandle());
        HybridDecrypt f1RawDecrypt = getDecrypt(f1RawPrivateHandle);
        byte[] f1RawMessage = "cross-check body payload".getBytes(UTF_8);
        byte[] f1RawCiphertext = f1RawEncrypt.encrypt(f1RawMessage, null);
        assertThat(f1RawCiphertext.length)
                .isEqualTo(Sm2Curve.UNCOMPRESSED_POINT_SIZE + 32 + f1RawMessage.length);

        KeysetHandle f2RawPrivateHandle =
                KeysetHandle.generateNew(Sm2HybridKeyManager.rawSm2HybridTemplate().toParameters());
        HybridDecrypt f2RawDecrypt = getDecrypt(f2RawPrivateHandle);
        HybridEncrypt f2RawEncrypt = getEncrypt(f2RawPrivateHandle.getPublicKeysetHandle());
        assertThrows(GeneralSecurityException.class,
                () -> f2RawDecrypt.decrypt(f1RawCiphertext, null));
        assertThrows(GeneralSecurityException.class,
                () -> f1RawDecrypt.decrypt(f2RawEncrypt.encrypt(f1RawMessage, null), null));
    }
}
