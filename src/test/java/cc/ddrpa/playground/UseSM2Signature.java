package cc.ddrpa.playground;

import cc.ddrpa.crypto.tink.signature.Sm2SignatureKeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.SignatureConfig;
import java.security.GeneralSecurityException;

/**
 * Example demonstrating how to use SM2 digital signatures.
 */
public final class UseSM2Signature {

    public static void main(String[] args) throws GeneralSecurityException {
        // Register SM2 signature with Tink
        SignatureConfig.register();
        Sm2SignatureKeyManager.register(true);

        // Example 1: Using SM3 hash with DER encoding
        System.out.println("=== SM2 Signature with SM3 Hash ===");
        demonstrateSignature(Sm2SignatureKeyManager.sm2Sm3Template(), "SM3");

        // Example 2: Using SHA256 hash with DER encoding 
        System.out.println("\n=== SM2 Signature with SHA256 Hash ===");
        demonstrateSignature(Sm2SignatureKeyManager.sm2Sha256Template(), "SHA256");

        // Example 3: Using raw template (no prefix)
        System.out.println("\n=== SM2 Signature with Raw Template ===");
        demonstrateSignature(Sm2SignatureKeyManager.rawSm2Sm3Template(), "SM3 Raw");
    }

    private static void demonstrateSignature(KeyTemplate template, String description) 
            throws GeneralSecurityException {
        // Generate a new key pair
        KeysetHandle privateKeysetHandle = KeysetHandle.generateNew(template);
        KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();

        // Create signing and verification primitives
        PublicKeySign signer = privateKeysetHandle.getPrimitive(PublicKeySign.class);
        PublicKeyVerify verifier = publicKeysetHandle.getPrimitive(PublicKeyVerify.class);

        // Message to sign
        String message = "Hello, SM2 digital signature! Using " + description;
        byte[] messageBytes = message.getBytes();

        // Sign the message
        byte[] signature = signer.sign(messageBytes);
        System.out.println("Message: " + message);
        System.out.println("Signature length: " + signature.length + " bytes");

        // Verify the signature
        try {
            verifier.verify(signature, messageBytes);
            System.out.println("✓ Signature verification successful!");
        } catch (GeneralSecurityException e) {
            System.out.println("✗ Signature verification failed: " + e.getMessage());
        }

        // Test with wrong message (should fail)
        String wrongMessage = "This is a different message";
        try {
            verifier.verify(signature, wrongMessage.getBytes());
            System.out.println("✗ Unexpected: verification succeeded with wrong message");
        } catch (GeneralSecurityException e) {
            System.out.println("✓ Correctly rejected signature for wrong message");
        }

        // Test with corrupted signature (should fail)
        byte[] corruptedSignature = signature.clone();
        if (corruptedSignature.length > 0) {
            corruptedSignature[0] = (byte) (corruptedSignature[0] ^ 1);
        }
        try {
            verifier.verify(corruptedSignature, messageBytes);
            System.out.println("✗ Unexpected: verification succeeded with corrupted signature");
        } catch (GeneralSecurityException e) {
            System.out.println("✓ Correctly rejected corrupted signature");
        }
    }
}