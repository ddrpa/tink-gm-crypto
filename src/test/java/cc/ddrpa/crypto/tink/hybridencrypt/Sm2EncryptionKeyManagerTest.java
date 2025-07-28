package cc.ddrpa.crypto.tink.hybridencrypt;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cc.ddrpa.crypto.tink.proto.Sm2EncryptionPrivateKey;
import cc.ddrpa.crypto.tink.proto.Sm2EncryptionPublicKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;

/**
 * Tests for SM2 hybrid encryption key manager.
 */
public final class Sm2EncryptionKeyManagerTest {

    @Test
    public void testBasicEncryptionDecryption_sha256AesGcm_success() throws Exception {
        // Generate key pair
        Sm2EncryptionPrivateKey privateKey = Sm2EncryptionKeyManager.generateKeySha256AesGcm();
        Sm2EncryptionPublicKey publicKey = privateKey.getPublicKey();

        // Create primitives
        HybridEncrypt encryptor = Sm2EncryptionKeyManager.createHybridEncrypt(publicKey);
        HybridDecrypt decryptor = Sm2EncryptionKeyManager.createHybridDecrypt(privateKey);

        // Test data
        byte[] plaintext = "Hello, SM2 hybrid encryption test!".getBytes();
        byte[] contextInfo = "test context".getBytes();

        // Encrypt and decrypt
        byte[] ciphertext = encryptor.encrypt(plaintext, contextInfo);
        byte[] decrypted = decryptor.decrypt(ciphertext, contextInfo);

        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    public void testEncryptionWithWrongContextInfo_fails() throws Exception {
        // Generate key pair
        Sm2EncryptionPrivateKey privateKey = Sm2EncryptionKeyManager.generateKeySha256AesGcm();
        Sm2EncryptionPublicKey publicKey = privateKey.getPublicKey();

        // Create primitives
        HybridEncrypt encryptor = Sm2EncryptionKeyManager.createHybridEncrypt(publicKey);
        HybridDecrypt decryptor = Sm2EncryptionKeyManager.createHybridDecrypt(privateKey);

        // Test data
        byte[] plaintext = "Hello, SM2!".getBytes();
        byte[] contextInfo = "correct context".getBytes();
        byte[] wrongContextInfo = "wrong context".getBytes();

        // Encrypt with correct context
        byte[] ciphertext = encryptor.encrypt(plaintext, contextInfo);

        // Decrypt with wrong context should fail
        assertThrows(GeneralSecurityException.class,
            () -> decryptor.decrypt(ciphertext, wrongContextInfo));
    }

    @Test
    public void testEncryptionWithCorruptedCiphertext_fails() throws Exception {
        // Generate key pair
        Sm2EncryptionPrivateKey privateKey = Sm2EncryptionKeyManager.generateKeySha256AesGcm();
        Sm2EncryptionPublicKey publicKey = privateKey.getPublicKey();

        // Create primitives
        HybridEncrypt encryptor = Sm2EncryptionKeyManager.createHybridEncrypt(publicKey);
        HybridDecrypt decryptor = Sm2EncryptionKeyManager.createHybridDecrypt(privateKey);

        // Test data
        byte[] plaintext = "Hello, SM2!".getBytes();
        byte[] contextInfo = "test context".getBytes();

        // Encrypt
        byte[] ciphertext = encryptor.encrypt(plaintext, contextInfo);

        // Corrupt the ciphertext
        byte[] corruptedCiphertext = ciphertext.clone();
        corruptedCiphertext[corruptedCiphertext.length - 1] ^= 1;

        // Decrypt corrupted ciphertext should fail
        assertThrows(GeneralSecurityException.class,
            () -> decryptor.decrypt(corruptedCiphertext, contextInfo));
    }

    @Test
    public void testDifferentKeyPairs_fails() throws Exception {
        // Generate two different key pairs
        Sm2EncryptionPrivateKey privateKey1 = Sm2EncryptionKeyManager.generateKeySha256AesGcm();
        Sm2EncryptionPrivateKey privateKey2 = Sm2EncryptionKeyManager.generateKeySha256AesGcm();
        
        Sm2EncryptionPublicKey publicKey1 = privateKey1.getPublicKey();

        // Create primitives with different keys
        HybridEncrypt encryptor = Sm2EncryptionKeyManager.createHybridEncrypt(publicKey1);
        HybridDecrypt decryptor = Sm2EncryptionKeyManager.createHybridDecrypt(privateKey2);

        // Test data
        byte[] plaintext = "Hello, SM2!".getBytes();
        byte[] contextInfo = "test context".getBytes();

        // Encrypt with one key
        byte[] ciphertext = encryptor.encrypt(plaintext, contextInfo);

        // Decrypt with different key should fail
        assertThrows(GeneralSecurityException.class,
            () -> decryptor.decrypt(ciphertext, contextInfo));
    }

    @Test
    public void testEmptyPlaintext_success() throws Exception {
        // Generate key pair
        Sm2EncryptionPrivateKey privateKey = Sm2EncryptionKeyManager.generateKeySha256AesGcm();
        Sm2EncryptionPublicKey publicKey = privateKey.getPublicKey();

        // Create primitives
        HybridEncrypt encryptor = Sm2EncryptionKeyManager.createHybridEncrypt(publicKey);
        HybridDecrypt decryptor = Sm2EncryptionKeyManager.createHybridDecrypt(privateKey);

        // Test empty plaintext
        byte[] plaintext = new byte[0];
        byte[] contextInfo = "test context".getBytes();

        // Encrypt and decrypt
        byte[] ciphertext = encryptor.encrypt(plaintext, contextInfo);
        byte[] decrypted = decryptor.decrypt(ciphertext, contextInfo);

        assertThat(decrypted).isEqualTo(plaintext);
        assertThat(decrypted).hasLength(0);
    }

    @Test
    public void testLargePlaintext_success() throws Exception {
        // Generate key pair
        Sm2EncryptionPrivateKey privateKey = Sm2EncryptionKeyManager.generateKeySha256AesGcm();
        Sm2EncryptionPublicKey publicKey = privateKey.getPublicKey();

        // Create primitives
        HybridEncrypt encryptor = Sm2EncryptionKeyManager.createHybridEncrypt(publicKey);
        HybridDecrypt decryptor = Sm2EncryptionKeyManager.createHybridDecrypt(privateKey);

        // Test large plaintext (1MB)
        byte[] plaintext = new byte[1024 * 1024];
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) (i % 256);
        }
        byte[] contextInfo = "test context".getBytes();

        // Encrypt and decrypt
        byte[] ciphertext = encryptor.encrypt(plaintext, contextInfo);
        byte[] decrypted = decryptor.decrypt(ciphertext, contextInfo);

        assertThat(decrypted).isEqualTo(plaintext);
    }
}