package com.google.crypto.tink.subtle;

import static com.google.common.truth.Truth.assertThat;

import org.junit.jupiter.api.Test;

/** Simple test for SM2 signature implementation to debug issues */
public final class Sm2SignatureTest {

    @Test
    public void basicSignAndVerify_works() throws Exception {
        // Generate a key pair
        Sm2Signature.KeyPair keyPair = Sm2Signature.generateKeyPair();

        // Create signer and verifier
        Sm2Signature signer = new Sm2Signature(
                keyPair.getPrivateKey(),
                keyPair.getPublicKeyX(),
                keyPair.getPublicKeyY(),
                Sm2Signature.HashAlgorithm.SM3,
                Sm2Signature.SignatureEncoding.DER);

        Sm2Signature verifier = new Sm2Signature(
                keyPair.getPublicKeyX(),
                keyPair.getPublicKeyY(),
                Sm2Signature.HashAlgorithm.SM3,
                Sm2Signature.SignatureEncoding.DER);

        // Test signing and verification
        byte[] message = "Hello, SM2!".getBytes();
        byte[] signature = signer.sign(message);

        assertThat(verifier.verify(signature, message)).isTrue();
    }

    @Test
    public void basicSignAndVerify_sha256_works() throws Exception {
        // Generate a key pair
        Sm2Signature.KeyPair keyPair = Sm2Signature.generateKeyPair();

        // Create signer and verifier
        Sm2Signature signer = new Sm2Signature(
                keyPair.getPrivateKey(),
                keyPair.getPublicKeyX(),
                keyPair.getPublicKeyY(),
                Sm2Signature.HashAlgorithm.SHA256,
                Sm2Signature.SignatureEncoding.DER);

        Sm2Signature verifier = new Sm2Signature(
                keyPair.getPublicKeyX(),
                keyPair.getPublicKeyY(),
                Sm2Signature.HashAlgorithm.SHA256,
                Sm2Signature.SignatureEncoding.DER);

        // Test signing and verification
        byte[] message = "Hello, SM2 with SHA256!".getBytes();
        byte[] signature = signer.sign(message);

        assertThat(verifier.verify(signature, message)).isTrue();
    }

    @Test
    public void signatureWithWrongMessage_fails() throws Exception {
        // Generate a key pair
        Sm2Signature.KeyPair keyPair = Sm2Signature.generateKeyPair();

        // Create signer and verifier
        Sm2Signature signer = new Sm2Signature(
                keyPair.getPrivateKey(),
                keyPair.getPublicKeyX(),
                keyPair.getPublicKeyY(),
                Sm2Signature.HashAlgorithm.SM3,
                Sm2Signature.SignatureEncoding.DER);

        Sm2Signature verifier = new Sm2Signature(
                keyPair.getPublicKeyX(),
                keyPair.getPublicKeyY(),
                Sm2Signature.HashAlgorithm.SM3,
                Sm2Signature.SignatureEncoding.DER);

        // Test signing and verification with wrong message
        byte[] message = "Original message".getBytes();
        byte[] wrongMessage = "Wrong message".getBytes();
        byte[] signature = signer.sign(message);

        assertThat(verifier.verify(signature, wrongMessage)).isFalse();
    }
}