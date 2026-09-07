package cc.ddrpa.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cc.ddrpa.crypto.tink.hybrid.internal.Sm2EncryptionHybridDecrypt;
import cc.ddrpa.crypto.tink.hybrid.internal.Sm2EncryptionHybridEncrypt;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2Curve;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.hybrid.HybridDecryptWrapper;
import com.google.crypto.tink.hybrid.HybridEncryptWrapper;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test for Sm2EncryptionKeyManager and Sm2EncryptionPublicKeyManager.
 */
class Sm2EncryptionKeyManagerTest {

    // Layout of the standard SM2 (GB/T 32918.4) ciphertext body for sm2p256v1:
    // C1 (65 bytes, 0x04 || X || Y) + C3 (32 bytes SM3 digest) + C2 (plaintext length bytes).
    private static final int C1_SIZE = Sm2Curve.UNCOMPRESSED_POINT_SIZE;
    private static final int C3_SIZE = 32;

    @BeforeEach
    void register() throws Exception {
        // Registers the HybridEncrypt / HybridDecrypt wrappers (used by KeysetHandle to obtain
        // primitives from keysets), without pulling in the whole HybridConfig.
        HybridEncryptWrapper.register();
        HybridDecryptWrapper.register();
        Sm2EncryptionKeyManager.registerPair(true);
    }

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
     * ciphertext failures (wrong prefix, wrong length, malformed C1, C3 mismatch, ...).
     */
    private static void assertDecryptionFailsWithGenericMessage(
        HybridDecrypt decrypt, byte[] ciphertext, byte[] contextInfo) {
        GeneralSecurityException e = assertThrows(GeneralSecurityException.class,
            () -> decrypt.decrypt(ciphertext, contextInfo));
        assertThat(e.getMessage()).isEqualTo("Decryption failed");
    }

    @Test
    void testKeyManagersRegistered() throws Exception {
        assertThat(KeyManagerRegistry.globalInstance()
            .getKeyManager(Sm2EncryptionKeyManager.getKeyType(), HybridDecrypt.class)).isNotNull();
        assertThat(KeyManagerRegistry.globalInstance()
            .getKeyManager(Sm2EncryptionPublicKeyManager.getKeyType(), HybridEncrypt.class))
            .isNotNull();
    }

    @Test
    void encryptDecryptRoundTripThroughKeysetHandle() throws Exception {
        KeysetHandle privateHandle =
            KeysetHandle.generateNew(Sm2EncryptionKeyManager.sm2EncryptionTemplate().toParameters());
        HybridDecrypt decrypt = getDecrypt(privateHandle);
        KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
        HybridEncrypt encrypt = getEncrypt(publicHandle);

        // null and empty contextInfo are both "no associated data" and must work. Note that an
        // empty plaintext can not be encrypted (SM2Engine rejects zero-length inputs; see
        // emptyPlaintextEncryptionFails).
        byte[][] contextInfos = {null, new byte[]{}};
        String[] messages = {"hello sm2 encryption", "some longer message to encrypt"};
        for (String message : messages) {
            byte[] plaintext = message.getBytes(UTF_8);
            for (byte[] contextInfo : contextInfos) {
                byte[] ciphertext = encrypt.encrypt(plaintext, contextInfo);
                assertThat(decrypt.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);
            }
        }
    }

    @Test
    void nonEmptyContextInfoIsRejected() throws Exception {
        KeysetHandle privateHandle =
            KeysetHandle.generateNew(Sm2EncryptionKeyManager.sm2EncryptionTemplate().toParameters());
        KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
        HybridDecrypt decrypt = getDecrypt(privateHandle);
        HybridEncrypt encrypt = getEncrypt(publicHandle);
        Sm2EncryptionPublicKey publicKey = (Sm2EncryptionPublicKey) publicHandle.getAt(0).getKey();
        Sm2EncryptionPrivateKey privateKey =
            (Sm2EncryptionPrivateKey) privateHandle.getAt(0).getKey();
        HybridEncrypt directEncrypt = Sm2EncryptionHybridEncrypt.create(publicKey);
        HybridDecrypt directDecrypt = Sm2EncryptionHybridDecrypt.create(privateKey);

        byte[] plaintext = "message".getBytes(UTF_8);
        byte[] contextInfo = "context".getBytes(UTF_8);

        // Through the keyset wrapper the descriptive encrypt error propagates...
        GeneralSecurityException encryptException = assertThrows(
            GeneralSecurityException.class, () -> encrypt.encrypt(plaintext, contextInfo));
        assertThat(encryptException.getMessage())
            .contains("contextInfo must be empty");
        // ... and decrypt must also refuse non-empty contextInfo (through the wrapper only a
        // generic error is observable, since the wrapper retries other keys).
        byte[] validCiphertext = encrypt.encrypt(plaintext, null);
        assertThrows(GeneralSecurityException.class,
            () -> decrypt.decrypt(validCiphertext, contextInfo));
        // On the direct primitive the descriptive message is observable on both sides.
        GeneralSecurityException directEncryptException = assertThrows(
            GeneralSecurityException.class, () -> directEncrypt.encrypt(plaintext, contextInfo));
        assertThat(directEncryptException.getMessage()).contains("contextInfo must be empty");
        GeneralSecurityException directDecryptException = assertThrows(
            GeneralSecurityException.class,
            () -> directDecrypt.decrypt(new byte[C1_SIZE + C3_SIZE + 1], contextInfo));
        assertThat(directDecryptException.getMessage()).contains("contextInfo must be empty");
    }

    @Test
    void rawCiphertextsHaveStandardLayout() throws Exception {
        KeysetHandle privateHandle =
            KeysetHandle.generateNew(
                Sm2EncryptionKeyManager.rawSm2EncryptionTemplate().toParameters());
        HybridDecrypt decrypt = getDecrypt(privateHandle);
        KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
        HybridEncrypt encrypt = getEncrypt(publicHandle);

        byte[] plaintext = "raw sm2 encryption".getBytes(UTF_8);
        byte[] ciphertext = encrypt.encrypt(plaintext, null);
        // A raw (NO_PREFIX) ciphertext is exactly the standard 65 + 32 + plaintext.length bytes
        // C1C3C2 body, starting with the 0x04 uncompressed point prefix.
        assertThat(ciphertext.length).isEqualTo(C1_SIZE + C3_SIZE + plaintext.length);
        assertThat(ciphertext[0]).isEqualTo((byte) 0x04);
        assertThat(decrypt.decrypt(ciphertext, null)).isEqualTo(plaintext);

        // Encrypting the same plaintext twice must produce different ciphertexts (random k).
        byte[] ciphertext2 = encrypt.encrypt(plaintext, null);
        assertThat(ciphertext).isNotEqualTo(ciphertext2);
        assertThat(decrypt.decrypt(ciphertext2, null)).isEqualTo(plaintext);
    }

    @Test
    void tinkCiphertextsArePrefixedWithKeyId() throws Exception {
        KeysetHandle privateHandle =
            KeysetHandle.generateNew(Sm2EncryptionKeyManager.sm2EncryptionTemplate().toParameters());
        int id = privateHandle.getAt(0).getId();
        Sm2EncryptionPrivateKey privateKey =
            (Sm2EncryptionPrivateKey) privateHandle.getAt(0).getKey();
        assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(id);

        HybridDecrypt decrypt = getDecrypt(privateHandle);
        HybridEncrypt encrypt = getEncrypt(privateHandle.getPublicKeysetHandle());
        byte[] plaintext = "message".getBytes(UTF_8);
        byte[] ciphertext = encrypt.encrypt(plaintext, null);

        // TINK prefix: 0x01 followed by the 4-byte big-endian key id, then the standard C1C3C2
        // body.
        assertThat(ciphertext.length).isEqualTo(5 + C1_SIZE + C3_SIZE + plaintext.length);
        assertThat(ciphertext[0]).isEqualTo((byte) 1);
        assertThat(Arrays.copyOf(ciphertext, 5))
            .isEqualTo(privateKey.getOutputPrefix().toByteArray());
        assertThat(ciphertext).isEqualTo(concat(privateKey.getOutputPrefix().toByteArray(),
            Arrays.copyOfRange(ciphertext, 5, ciphertext.length)));
        assertThat(decrypt.decrypt(ciphertext, null)).isEqualTo(plaintext);
    }

    @Test
    void encryptOutputLayoutSpotCheck() throws Exception {
        KeysetHandle privateHandle =
            KeysetHandle.generateNew(
                Sm2EncryptionKeyManager.rawSm2EncryptionTemplate().toParameters());
        HybridEncrypt encrypt = getEncrypt(privateHandle.getPublicKeysetHandle());

        byte[] plaintext = new byte[64];
        Arrays.fill(plaintext, (byte) 0x42);
        byte[] ciphertext = encrypt.encrypt(plaintext, null);
        assertThat(ciphertext.length).isEqualTo(C1_SIZE + C3_SIZE + plaintext.length);
        // C1 is the 65 byte uncompressed point starting with 0x04.
        assertThat(ciphertext[0]).isEqualTo((byte) 0x04);
        // Bytes [65, 97) hold the 32 byte C3 = SM3 digest, which for a non-empty plaintext is
        // essentially never all zero and also not a copy of the plaintext.
        byte[] c3 = Arrays.copyOfRange(ciphertext, C1_SIZE, C1_SIZE + C3_SIZE);
        assertThat(c3).isNotEqualTo(new byte[C3_SIZE]);
        assertThat(c3).isNotEqualTo(Arrays.copyOf(plaintext, C3_SIZE));
    }

    @Test
    void emptyPlaintextEncryptionFails() throws Exception {
        KeysetHandle privateHandle =
            KeysetHandle.generateNew(Sm2EncryptionKeyManager.sm2EncryptionTemplate().toParameters());
        KeysetHandle rawPrivateHandle =
            KeysetHandle.generateNew(
                Sm2EncryptionKeyManager.rawSm2EncryptionTemplate().toParameters());
        HybridEncrypt tinkEncrypt = getEncrypt(privateHandle.getPublicKeysetHandle());
        HybridEncrypt rawEncrypt = getEncrypt(rawPrivateHandle.getPublicKeysetHandle());
        Sm2EncryptionPublicKey publicKey =
            (Sm2EncryptionPublicKey) privateHandle.getPublicKeysetHandle().getAt(0).getKey();
        HybridEncrypt directEncrypt = Sm2EncryptionHybridEncrypt.create(publicKey);

        assertThrows(GeneralSecurityException.class,
            () -> tinkEncrypt.encrypt(new byte[]{}, null));
        assertThrows(GeneralSecurityException.class,
            () -> rawEncrypt.encrypt(new byte[]{}, null));
        assertThrows(GeneralSecurityException.class,
            () -> directEncrypt.encrypt(new byte[]{}, null));
    }

    @Test
    void twoKeyKeysetWorks() throws Exception {
        KeysetHandle keyAHandle =
            KeysetHandle.generateNew(Sm2EncryptionKeyManager.sm2EncryptionTemplate().toParameters());
        KeysetHandle keyBHandle =
            KeysetHandle.generateNew(Sm2EncryptionKeyManager.sm2EncryptionTemplate().toParameters());
        // Extremely unlikely, but make sure the two keys have different ids (hence different
        // prefixes).
        while (keyBHandle.getAt(0).getId() == keyAHandle.getAt(0).getId()) {
            keyBHandle =
                KeysetHandle.generateNew(
                    Sm2EncryptionKeyManager.sm2EncryptionTemplate().toParameters());
        }
        Sm2EncryptionPrivateKey keyA = (Sm2EncryptionPrivateKey) keyAHandle.getAt(0).getKey();
        Sm2EncryptionPrivateKey keyB = (Sm2EncryptionPrivateKey) keyBHandle.getAt(0).getKey();

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

        // Ciphertexts encrypted by either key decrypt with the two-key private handle (dispatched
        // via the output prefix).
        byte[] keyACiphertext = keyAEncrypt.encrypt(data, null);
        assertThat(twoKeyDecrypt.decrypt(keyACiphertext, null)).isEqualTo(data);
        byte[] keyBCiphertext = keyBEncrypt.encrypt(data, null);
        assertThat(twoKeyDecrypt.decrypt(keyBCiphertext, null)).isEqualTo(data);

        // A ciphertext encrypted by key B does not decrypt with a private handle which only
        // contains key A.
        HybridDecrypt keyADecrypt = getDecrypt(keyAHandle);
        assertThrows(GeneralSecurityException.class,
            () -> keyADecrypt.decrypt(keyBCiphertext, null));
        // A ciphertext from a foreign key (not in the keyset) does not decrypt either.
        KeysetHandle foreignHandle =
            KeysetHandle.generateNew(
                Sm2EncryptionKeyManager.sm2EncryptionTemplate().toParameters());
        HybridEncrypt foreignEncrypt = getEncrypt(foreignHandle.getPublicKeysetHandle());
        byte[] foreignCiphertext = foreignEncrypt.encrypt(data, null);
        assertThrows(GeneralSecurityException.class,
            () -> twoKeyDecrypt.decrypt(foreignCiphertext, null));
    }

    @Test
    void rawCiphertextInteroperatesWithBouncyCastle() throws Exception {
        KeysetHandle privateHandle =
            KeysetHandle.generateNew(
                Sm2EncryptionKeyManager.rawSm2EncryptionTemplate().toParameters());
        Sm2EncryptionPrivateKey privateKey =
            (Sm2EncryptionPrivateKey) privateHandle.getAt(0).getKey();
        byte[] d = privateKey.getPrivateValue().toByteArray(InsecureSecretKeyAccess.get());
        byte[] q = privateKey.getPublicKey().getPublicKey().toByteArray();
        assertThat(d.length).isEqualTo(32);
        assertThat(q.length).isEqualTo(64);

        HybridEncrypt encrypt = getEncrypt(privateHandle.getPublicKeysetHandle());
        HybridDecrypt decrypt = getDecrypt(privateHandle);
        byte[] message = "hello sm2 encryption".getBytes(UTF_8);

        // 1. A ciphertext produced by a BouncyCastle low-level SM2Engine (using the public key
        // derived from our key material) decrypts with our HybridDecrypt.
        ECPublicKeyParameters bcPublicParams = Sm2KeyUtil.toPublicKeyParameters(q);
        SM2Engine bcEncryptEngine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
        bcEncryptEngine.init(
            true, new ParametersWithRandom(bcPublicParams, Sm2KeyUtil.getSecureRandom()));
        byte[] bcCiphertext = bcEncryptEngine.processBlock(message, 0, message.length);
        assertThat(decrypt.decrypt(bcCiphertext, null)).isEqualTo(message);

        // 2. Our raw ciphertext decrypts with a BouncyCastle low-level SM2Engine using the
        // private key.
        byte[] ourCiphertext = encrypt.encrypt(message, null);
        assertThat(ourCiphertext.length).isEqualTo(C1_SIZE + C3_SIZE + message.length);
        ECPrivateKeyParameters bcPrivateParams = Sm2KeyUtil.toPrivateKeyParameters(d);
        SM2Engine bcDecryptEngine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
        bcDecryptEngine.init(false, bcPrivateParams);
        byte[] bcPlaintext =
            bcDecryptEngine.processBlock(ourCiphertext, 0, ourCiphertext.length);
        assertThat(bcPlaintext).isEqualTo(message);
    }

    @Test
    void tamperedCiphertextsFailUniformly() throws Exception {
        KeysetHandle rawPrivateHandle =
            KeysetHandle.generateNew(
                Sm2EncryptionKeyManager.rawSm2EncryptionTemplate().toParameters());
        Sm2EncryptionPrivateKey rawPrivateKey =
            (Sm2EncryptionPrivateKey) rawPrivateHandle.getAt(0).getKey();
        HybridEncrypt rawEncrypt = getEncrypt(rawPrivateHandle.getPublicKeysetHandle());
        HybridDecrypt rawDecrypt = getDecrypt(rawPrivateHandle);
        HybridDecrypt rawDirectDecrypt = Sm2EncryptionHybridDecrypt.create(rawPrivateKey);

        KeysetHandle tinkPrivateHandle =
            KeysetHandle.generateNew(Sm2EncryptionKeyManager.sm2EncryptionTemplate().toParameters());
        Sm2EncryptionPrivateKey tinkPrivateKey =
            (Sm2EncryptionPrivateKey) tinkPrivateHandle.getAt(0).getKey();
        HybridEncrypt tinkEncrypt = getEncrypt(tinkPrivateHandle.getPublicKeysetHandle());
        HybridDecrypt tinkDirectDecrypt = Sm2EncryptionHybridDecrypt.create(tinkPrivateKey);

        byte[] plaintext = "tamper me please".getBytes(UTF_8);

        // --- Tampering with a raw ciphertext, exercised on the direct primitive so that the
        // uniform generic message is observable. ---
        byte[] rawCiphertext = rawEncrypt.encrypt(plaintext, null);
        assertThat(rawDirectDecrypt.decrypt(rawCiphertext, null)).isEqualTo(plaintext);

        // Flip one byte inside C2 (the last byte).
        byte[] flippedC2 = Arrays.copyOf(rawCiphertext, rawCiphertext.length);
        flippedC2[flippedC2.length - 1] ^= 0x01;
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt, flippedC2, null);
        // Truncate the ciphertext.
        assertDecryptionFailsWithGenericMessage(
            rawDirectDecrypt,
            Arrays.copyOf(rawCiphertext, rawCiphertext.length - 1), null);
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt, new byte[10], null);
        // Replace the 0x04 prefix of C1.
        byte[] badPrefix = Arrays.copyOf(rawCiphertext, rawCiphertext.length);
        badPrefix[0] = 0x05;
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt, badPrefix, null);
        // Corrupt one byte inside C3 (bytes [65, 97) of the body).
        byte[] corruptedC3 = Arrays.copyOf(rawCiphertext, rawCiphertext.length);
        corruptedC3[C1_SIZE] ^= 0x01;
        assertDecryptionFailsWithGenericMessage(rawDirectDecrypt, corruptedC3, null);

        // The same tampered values also fail through the keyset wrapper (which only surfaces a
        // generic error).
        assertThrows(GeneralSecurityException.class,
            () -> rawDecrypt.decrypt(flippedC2, null));

        // --- Tampering with a TINK ciphertext. ---
        byte[] tinkCiphertext = tinkEncrypt.encrypt(plaintext, null);
        assertThat(tinkDirectDecrypt.decrypt(tinkCiphertext, null)).isEqualTo(plaintext);
        byte[] tinkFlippedC2 = Arrays.copyOf(tinkCiphertext, tinkCiphertext.length);
        tinkFlippedC2[tinkFlippedC2.length - 1] ^= 0x01;
        assertDecryptionFailsWithGenericMessage(tinkDirectDecrypt, tinkFlippedC2, null);
        byte[] tinkBadC1Prefix = Arrays.copyOf(tinkCiphertext, tinkCiphertext.length);
        tinkBadC1Prefix[5] = 0x05;
        assertDecryptionFailsWithGenericMessage(tinkDirectDecrypt, tinkBadC1Prefix, null);
        assertDecryptionFailsWithGenericMessage(tinkDirectDecrypt, new byte[0], null);

        // --- Cross-variant handling of prefix-stripped TINK ciphertexts. Build a RAW-variant key
        // pair which reuses the TINK key material: the variant only controls the prefix, so a
        // valid prefix-stripped body still decrypts, while the tampered bodies must fail after
        // stripping the prefix. ---
        byte[] tinkPublicKeyBytes = tinkPrivateKey.getPublicKey().getPublicKey().toByteArray();
        byte[] tinkPrivateValue =
            tinkPrivateKey.getPrivateValue().toByteArray(InsecureSecretKeyAccess.get());
        Sm2EncryptionPublicKey sameKeyRawPublicKey =
            Sm2EncryptionPublicKey.builder()
                .setParameters(
                    Sm2EncryptionParameters.builder()
                        .setVariant(Sm2EncryptionParameters.Variant.NO_PREFIX)
                        .build())
                .setPublicKey(Bytes.copyFrom(tinkPublicKeyBytes))
                .build();
        Sm2EncryptionPrivateKey sameKeyRawPrivateKey =
            Sm2EncryptionPrivateKey.builder()
                .setPublicKey(sameKeyRawPublicKey)
                .setPrivateValue(secretBytes(tinkPrivateValue))
                .build();
        HybridDecrypt sameKeyRawDecrypt =
            Sm2EncryptionHybridDecrypt.create(sameKeyRawPrivateKey);
        byte[] strippedValidBody =
            Arrays.copyOfRange(tinkCiphertext, 5, tinkCiphertext.length);
        assertThat(sameKeyRawDecrypt.decrypt(strippedValidBody, null)).isEqualTo(plaintext);
        // Tampered bodies must also fail when re-interpreted as raw ciphertexts after stripping
        // the TINK prefix (flipped C2 byte; corrupted C1 0x04 prefix).
        byte[] strippedTamperedBody =
            Arrays.copyOfRange(tinkFlippedC2, 5, tinkFlippedC2.length);
        assertDecryptionFailsWithGenericMessage(sameKeyRawDecrypt, strippedTamperedBody, null);
        byte[] strippedBadC1Prefix =
            Arrays.copyOfRange(tinkBadC1Prefix, 5, tinkBadC1Prefix.length);
        assertDecryptionFailsWithGenericMessage(sameKeyRawDecrypt, strippedBadC1Prefix, null);

        // --- Ciphertexts never leak partial plaintext: decrypting with a plaintext prefix match
        // but an invalid body returns nothing. ---
        byte[] wrongKeyCiphertext = tinkEncrypt.encrypt(plaintext, null);
        HybridDecrypt rawOnlyDecrypt = getDecrypt(rawPrivateHandle);
        // The raw-only handle only accepts ciphertexts without a prefix.
        assertThrows(GeneralSecurityException.class,
            () -> rawOnlyDecrypt.decrypt(wrongKeyCiphertext, null));
    }

    @Test
    void jsonKeysetRoundTripWorks() throws Exception {
        KeysetHandle privateHandle =
            KeysetHandle.generateNew(Sm2EncryptionKeyManager.sm2EncryptionTemplate().toParameters());
        HybridDecrypt originalDecrypt = getDecrypt(privateHandle);
        KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
        HybridEncrypt originalEncrypt = getEncrypt(publicHandle);
        byte[] message = "hello sm2 encryption".getBytes(UTF_8);
        byte[] originalCiphertext = originalEncrypt.encrypt(message, null);
        assertThat(originalDecrypt.decrypt(originalCiphertext, null)).isEqualTo(message);

        Path tempDir = Files.createTempDirectory("tink-sm2-encryption-json-test");
        Path privateFile = tempDir.resolve("sm2_encryption_private_keyset.json");
        Path publicFile = tempDir.resolve("sm2_encryption_public_keyset.json");
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
            byte[] parsedCiphertext = parsedEncrypt.encrypt(message, null);
            parsedDecrypt.decrypt(parsedCiphertext, null);
            // The original ciphertext must decrypt with the parsed private keyset.
            assertThat(parsedDecrypt.decrypt(originalCiphertext, null)).isEqualTo(message);

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
            byte[] publicEncrypted = publicEncrypt.encrypt(message, null);
            assertThat(originalDecrypt.decrypt(publicEncrypted, null)).isEqualTo(message);
            assertThat(parsedDecrypt.decrypt(publicEncrypted, null)).isEqualTo(message);
        } finally {
            Files.deleteIfExists(privateFile);
            Files.deleteIfExists(publicFile);
            Files.deleteIfExists(tempDir);
        }
    }
}
