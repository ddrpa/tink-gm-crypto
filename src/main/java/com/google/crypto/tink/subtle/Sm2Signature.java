package com.google.crypto.tink.subtle;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * SM2 signature implementation using BouncyCastle.
 * 
 * This class provides SM2 digital signature functionality following the 
 * Chinese national cryptographic standard GM/T 0003.2-2012.
 */
public final class Sm2Signature {
    
    /**
     * Hash algorithms supported for SM2.
     */
    public enum HashAlgorithm {
        SM3, SHA256
    }
    
    /**
     * Signature encodings supported for SM2.
     */
    public enum SignatureEncoding {
        DER, IEEE_P1363
    }
    
    private static final String DEFAULT_USER_ID = "1234567812345678"; // 16 bytes default
    private static final X9ECParameters SM2_CURVE_PARAMS = GMNamedCurves.getByName("sm2p256v1");
    private static final ECDomainParameters SM2_DOMAIN_PARAMS = new ECDomainParameters(
        SM2_CURVE_PARAMS.getCurve(),
        SM2_CURVE_PARAMS.getG(),
        SM2_CURVE_PARAMS.getN(),
        SM2_CURVE_PARAMS.getH());
    
    private final ECPrivateKeyParameters privateKey;
    private final ECPublicKeyParameters publicKey;
    private final HashAlgorithm hashAlgorithm;
    private final SignatureEncoding signatureEncoding;
    
    /**
     * Constructs a new SM2Signature instance.
     */
    public Sm2Signature(
            byte[] privateKeyBytes,
            byte[] publicKeyX,
            byte[] publicKeyY,
            HashAlgorithm hashAlgorithm,
            SignatureEncoding signatureEncoding) throws GeneralSecurityException {
        validateInputs(privateKeyBytes, publicKeyX, publicKeyY);
        
        this.hashAlgorithm = hashAlgorithm;
        this.signatureEncoding = signatureEncoding;
        
        // Create private key
        BigInteger d = new BigInteger(1, privateKeyBytes);
        this.privateKey = new ECPrivateKeyParameters(d, SM2_DOMAIN_PARAMS);
        
        // Create public key
        BigInteger x = new BigInteger(1, publicKeyX);
        BigInteger y = new BigInteger(1, publicKeyY);
        ECPoint q = SM2_CURVE_PARAMS.getCurve().createPoint(x, y);
        this.publicKey = new ECPublicKeyParameters(q, SM2_DOMAIN_PARAMS);
        
        // Validate key pair consistency
        validateKeyPair();
    }
    
    /**
     * Constructs a new SM2Signature instance for verification only.
     */
    public Sm2Signature(
            byte[] publicKeyX,
            byte[] publicKeyY,
            HashAlgorithm hashAlgorithm,
            SignatureEncoding signatureEncoding) throws GeneralSecurityException {
        validatePublicKeyInputs(publicKeyX, publicKeyY);
        
        this.hashAlgorithm = hashAlgorithm;
        this.signatureEncoding = signatureEncoding;
        this.privateKey = null; // No private key for verification
        
        // Create public key
        BigInteger x = new BigInteger(1, publicKeyX);
        BigInteger y = new BigInteger(1, publicKeyY);
        ECPoint q = SM2_CURVE_PARAMS.getCurve().createPoint(x, y);
        this.publicKey = new ECPublicKeyParameters(q, SM2_DOMAIN_PARAMS);
    }
    
    /**
     * Signs the given message.
     */
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        if (privateKey == null) {
            throw new GeneralSecurityException("Cannot sign without private key");
        }
        
        try {
            SM2Signer signer = new SM2Signer(getDigest());
            signer.init(true, privateKey);
            signer.update(DEFAULT_USER_ID.getBytes(), 0, DEFAULT_USER_ID.getBytes().length);
            signer.update(message, 0, message.length);
            
            byte[] signature = signer.generateSignature();
            
            if (signatureEncoding == SignatureEncoding.IEEE_P1363) {
                return convertDerToIeeeP1363(signature);
            }
            return signature;
        } catch (CryptoException e) {
            throw new GeneralSecurityException("Failed to sign message", e);
        }
    }
    
    /**
     * Verifies the given signature.
     */
    public boolean verify(byte[] signature, byte[] message) throws GeneralSecurityException {
        try {
            byte[] derSignature = signature;
            if (signatureEncoding == SignatureEncoding.IEEE_P1363) {
                derSignature = convertIeeeP1363ToDer(signature);
            }
            
            SM2Signer verifier = new SM2Signer(getDigest());
            verifier.init(false, publicKey);
            verifier.update(DEFAULT_USER_ID.getBytes(), 0, DEFAULT_USER_ID.getBytes().length);
            verifier.update(message, 0, message.length);
            
            return verifier.verifySignature(derSignature);
        } catch (Exception e) {
            // Log the error but return false for verification failure
            return false;
        }
    }
    
    /**
     * Generates a new SM2 key pair.
     */
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        try {
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.init(new ECKeyGenerationParameters(SM2_DOMAIN_PARAMS, new SecureRandom()));
            
            AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
            ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
            
            // Extract key material
            byte[] privateKeyBytes = privateKey.getD().toByteArray();
            if (privateKeyBytes.length > 32) {
                // Remove leading zero byte if present
                byte[] temp = new byte[32];
                System.arraycopy(privateKeyBytes, privateKeyBytes.length - 32, temp, 0, 32);
                privateKeyBytes = temp;
            } else if (privateKeyBytes.length < 32) {
                // Pad with leading zeros
                byte[] temp = new byte[32];
                System.arraycopy(privateKeyBytes, 0, temp, 32 - privateKeyBytes.length, privateKeyBytes.length);
                privateKeyBytes = temp;
            }
            
            ECPoint q = publicKey.getQ();
            byte[] publicKeyX = q.getAffineXCoord().toBigInteger().toByteArray();
            byte[] publicKeyY = q.getAffineYCoord().toBigInteger().toByteArray();
            
            // Ensure coordinates are 32 bytes
            publicKeyX = padTo32Bytes(publicKeyX);
            publicKeyY = padTo32Bytes(publicKeyY);
            
            return new KeyPair(privateKeyBytes, publicKeyX, publicKeyY);
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to generate SM2 key pair", e);
        }
    }
    
    private org.bouncycastle.crypto.Digest getDigest() {
        switch (hashAlgorithm) {
            case SM3:
                return new SM3Digest();
            case SHA256:
                return new SHA256Digest();
            default:
                throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
        }
    }
    
    private static void validateInputs(byte[] privateKeyBytes, byte[] publicKeyX, byte[] publicKeyY) 
            throws GeneralSecurityException {
        if (privateKeyBytes == null || privateKeyBytes.length != 32) {
            throw new GeneralSecurityException("Private key must be 32 bytes");
        }
        validatePublicKeyInputs(publicKeyX, publicKeyY);
    }
    
    private static void validatePublicKeyInputs(byte[] publicKeyX, byte[] publicKeyY) 
            throws GeneralSecurityException {
        if (publicKeyX == null || publicKeyX.length != 32) {
            throw new GeneralSecurityException("Public key X coordinate must be 32 bytes");
        }
        if (publicKeyY == null || publicKeyY.length != 32) {
            throw new GeneralSecurityException("Public key Y coordinate must be 32 bytes");
        }
    }
    
    private void validateKeyPair() throws GeneralSecurityException {
        // Verify that public key corresponds to private key
        ECPoint calculatedQ = SM2_DOMAIN_PARAMS.getG().multiply(privateKey.getD());
        if (!calculatedQ.equals(publicKey.getQ())) {
            throw new GeneralSecurityException("Public key does not correspond to private key");
        }
    }
    
    private static byte[] padTo32Bytes(byte[] input) {
        if (input.length == 32) {
            return input;
        } else if (input.length > 32) {
            // Remove leading zero bytes
            byte[] result = new byte[32];
            System.arraycopy(input, input.length - 32, result, 0, 32);
            return result;
        } else {
            // Pad with leading zeros
            byte[] result = new byte[32];
            System.arraycopy(input, 0, result, 32 - input.length, input.length);
            return result;
        }
    }
    
    private byte[] convertDerToIeeeP1363(byte[] derSignature) throws GeneralSecurityException {
        // Parse DER signature to extract r and s values
        // This is a simplified implementation - in practice, you'd want proper ASN.1 parsing
        try {
            // Assuming standard DER encoding: 0x30 [length] 0x02 [r-length] [r] 0x02 [s-length] [s]
            int rLength = derSignature[3] & 0xFF;
            int sLength = derSignature[5 + rLength] & 0xFF;
            
            byte[] r = new byte[rLength];
            byte[] s = new byte[sLength];
            System.arraycopy(derSignature, 4, r, 0, rLength);
            System.arraycopy(derSignature, 6 + rLength, s, 0, sLength);
            
            // Convert to IEEE P1363 format (r || s, each padded to 32 bytes)
            byte[] result = new byte[64];
            System.arraycopy(padTo32Bytes(r), 0, result, 0, 32);
            System.arraycopy(padTo32Bytes(s), 0, result, 32, 32);
            return result;
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to convert DER to IEEE P1363", e);
        }
    }
    
    private byte[] convertIeeeP1363ToDer(byte[] ieeeSignature) throws GeneralSecurityException {
        if (ieeeSignature.length != 64) {
            throw new GeneralSecurityException("IEEE P1363 signature must be 64 bytes");
        }
        
        try {
            byte[] r = new byte[32];
            byte[] s = new byte[32];
            System.arraycopy(ieeeSignature, 0, r, 0, 32);
            System.arraycopy(ieeeSignature, 32, s, 0, 32);
            
            // Convert to DER format
            // This is a simplified implementation
            byte[] result = new byte[6 + r.length + s.length];
            result[0] = 0x30; // SEQUENCE
            result[1] = (byte) (4 + r.length + s.length); // Length
            result[2] = 0x02; // INTEGER
            result[3] = (byte) r.length;
            System.arraycopy(r, 0, result, 4, r.length);
            result[4 + r.length] = 0x02; // INTEGER
            result[5 + r.length] = (byte) s.length;
            System.arraycopy(s, 0, result, 6 + r.length, s.length);
            
            return result;
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to convert IEEE P1363 to DER", e);
        }
    }
    
    /**
     * Represents an SM2 key pair.
     */
    public static class KeyPair {
        private final byte[] privateKey;
        private final byte[] publicKeyX;
        private final byte[] publicKeyY;
        
        public KeyPair(byte[] privateKey, byte[] publicKeyX, byte[] publicKeyY) {
            this.privateKey = privateKey.clone();
            this.publicKeyX = publicKeyX.clone();
            this.publicKeyY = publicKeyY.clone();
        }
        
        public byte[] getPrivateKey() {
            return privateKey.clone();
        }
        
        public byte[] getPublicKeyX() {
            return publicKeyX.clone();
        }
        
        public byte[] getPublicKeyY() {
            return publicKeyY.clone();
        }
    }
}