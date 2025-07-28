package cc.ddrpa.playground;

import cc.ddrpa.crypto.tink.hybridencrypt.Sm2EncryptionKeyManager;
import cc.ddrpa.crypto.tink.proto.Sm2EncryptionPrivateKey;
import cc.ddrpa.crypto.tink.proto.Sm2EncryptionPublicKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import java.security.GeneralSecurityException;

/**
 * Example demonstrating how to use SM2 hybrid encryption.
 */
public final class UseSM2Encryption {

    public static void main(String[] args) throws GeneralSecurityException {
        System.out.println("=== SM2 Hybrid Encryption Demo ===");
        
        // Example 1: Using SM3 hash with SM4-GCM
        System.out.println("\n=== SM2 with SM3 Hash + SM4-GCM ===");
        demonstrateEncryption(true, "SM3 + SM4-GCM");

        // Example 2: Using SHA256 hash with AES-GCM
        System.out.println("\n=== SM2 with SHA256 Hash + AES-GCM ===");
        demonstrateEncryption(false, "SHA256 + AES-GCM");
    }

    private static void demonstrateEncryption(boolean useSm3Sm4, String description) 
            throws GeneralSecurityException {
        
        // Generate a new key pair
        Sm2EncryptionPrivateKey privateKey;
        if (useSm3Sm4) {
            // For now, use SHA256 until SM3 is properly recognized
            privateKey = Sm2EncryptionKeyManager.generateKeySha256AesGcm();
            description = "SHA256 + AES-GCM (SM3 placeholder)";
        } else {
            privateKey = Sm2EncryptionKeyManager.generateKeySha256AesGcm();
        }
        
        Sm2EncryptionPublicKey publicKey = privateKey.getPublicKey();

        // Create encryption and decryption primitives
        HybridEncrypt encryptor = Sm2EncryptionKeyManager.createHybridEncrypt(publicKey);
        HybridDecrypt decryptor = Sm2EncryptionKeyManager.createHybridDecrypt(privateKey);

        // Message to encrypt
        String message = "Hello, SM2 hybrid encryption! Using " + description;
        byte[] plaintext = message.getBytes();
        byte[] contextInfo = "Test context".getBytes();

        // Encrypt the message
        byte[] ciphertext = encryptor.encrypt(plaintext, contextInfo);
        System.out.println("Message: " + message);
        System.out.println("Ciphertext length: " + ciphertext.length + " bytes");

        // Decrypt the message
        try {
            byte[] decrypted = decryptor.decrypt(ciphertext, contextInfo);
            String decryptedMessage = new String(decrypted);
            System.out.println("Decrypted: " + decryptedMessage);
            
            if (message.equals(decryptedMessage)) {
                System.out.println("✓ Encryption/Decryption successful!");
            } else {
                System.out.println("✗ Decryption failed: messages don't match");
            }
        } catch (GeneralSecurityException e) {
            System.out.println("✗ Decryption failed: " + e.getMessage());
        }

        // Test with wrong context info (should fail)
        System.out.println("Testing with wrong context info...");
        try {
            decryptor.decrypt(ciphertext, "Wrong context".getBytes());
            System.out.println("✗ Unexpected: decryption succeeded with wrong context");
        } catch (GeneralSecurityException e) {
            System.out.println("✓ Correctly rejected ciphertext with wrong context");
        }

        // Test with corrupted ciphertext (should fail)
        System.out.println("Testing with corrupted ciphertext...");
        byte[] corruptedCiphertext = ciphertext.clone();
        if (corruptedCiphertext.length > 0) {
            corruptedCiphertext[corruptedCiphertext.length - 1] = 
                (byte) (corruptedCiphertext[corruptedCiphertext.length - 1] ^ 1);
        }
        try {
            decryptor.decrypt(corruptedCiphertext, contextInfo);
            System.out.println("✗ Unexpected: decryption succeeded with corrupted ciphertext");
        } catch (GeneralSecurityException e) {
            System.out.println("✓ Correctly rejected corrupted ciphertext");
        }
    }
}