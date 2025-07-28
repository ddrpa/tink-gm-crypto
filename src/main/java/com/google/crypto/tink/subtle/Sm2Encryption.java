package com.google.crypto.tink.subtle;

import cc.ddrpa.crypto.tink.aead.Sm4GcmJce;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.math.ec.ECPoint;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * SM2 encryption implementation using BouncyCastle.
 * 
 * This class provides SM2 public key encryption functionality following the 
 * Chinese national cryptographic standard GM/T 0003.4-2012.
 * 
 * The implementation follows the hybrid encryption pattern where:
 * 1. A random symmetric key is generated
 * 2. The symmetric key is encrypted using SM2 public key encryption
 * 3. The data is encrypted using the symmetric key with SM4-GCM or AES-GCM
 * 4. The result combines the encrypted symmetric key and encrypted data
 */
public final class Sm2Encryption {
    
    /**
     * Hash algorithms supported for SM2 KDF.
     */
    public enum HashAlgorithm {
        SM3, SHA256
    }
    
    /**
     * Symmetric ciphers supported for data encryption.
     */
    public enum SymmetricCipher {
        SM4_GCM, AES_GCM
    }
    
    private static final X9ECParameters SM2_CURVE_PARAMS = GMNamedCurves.getByName("sm2p256v1");
    private static final ECDomainParameters SM2_DOMAIN_PARAMS = new ECDomainParameters(
        SM2_CURVE_PARAMS.getCurve(),
        SM2_CURVE_PARAMS.getG(),
        SM2_CURVE_PARAMS.getN(),
        SM2_CURVE_PARAMS.getH());
    
    private static final int SM2_KEY_SIZE_BYTES = 32; // 256 bits
    private static final int SYMMETRIC_KEY_SIZE_BYTES = 32; // 256 bits for SM4/AES
    
    private final ECPrivateKeyParameters privateKey;
    private final ECPublicKeyParameters publicKey;
    private final HashAlgorithm hashAlgorithm;
    private final SymmetricCipher symmetricCipher;
    private final int ivSize;
    private final int tagSize;
    
    /**
     * Key pair class for SM2.
     */
    public static final class KeyPair {
        private final byte[] privateKey;
        private final byte[] publicKeyX;
        private final byte[] publicKeyY;
        
        private KeyPair(byte[] privateKey, byte[] publicKeyX, byte[] publicKeyY) {
            this.privateKey = privateKey;
            this.publicKeyX = publicKeyX;
            this.publicKeyY = publicKeyY;
        }
        
        public byte[] getPrivateKey() { return privateKey.clone(); }
        public byte[] getPublicKeyX() { return publicKeyX.clone(); }
        public byte[] getPublicKeyY() { return publicKeyY.clone(); }
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
            
            // Convert to byte arrays
            byte[] privateKeyBytes = privateKey.getD().toByteArray();
            if (privateKeyBytes.length > SM2_KEY_SIZE_BYTES) {
                // Remove leading zeros if present
                byte[] trimmed = new byte[SM2_KEY_SIZE_BYTES];
                System.arraycopy(privateKeyBytes, privateKeyBytes.length - SM2_KEY_SIZE_BYTES, 
                               trimmed, 0, SM2_KEY_SIZE_BYTES);
                privateKeyBytes = trimmed;
            } else if (privateKeyBytes.length < SM2_KEY_SIZE_BYTES) {
                // Pad with leading zeros if necessary
                byte[] padded = new byte[SM2_KEY_SIZE_BYTES];
                System.arraycopy(privateKeyBytes, 0, 
                               padded, SM2_KEY_SIZE_BYTES - privateKeyBytes.length, 
                               privateKeyBytes.length);
                privateKeyBytes = padded;
            }
            
            ECPoint q = publicKey.getQ().normalize();
            byte[] xBytes = q.getAffineXCoord().toBigInteger().toByteArray();
            byte[] yBytes = q.getAffineYCoord().toBigInteger().toByteArray();
            
            // Ensure coordinate bytes are exactly 32 bytes
            xBytes = normalizeCoordinateBytes(xBytes);
            yBytes = normalizeCoordinateBytes(yBytes);
            
            return new KeyPair(privateKeyBytes, xBytes, yBytes);
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to generate SM2 key pair", e);
        }
    }
    
    /**
     * Constructs a new SM2Encryption instance for encryption and decryption.
     */
    public Sm2Encryption(
            byte[] privateKeyBytes,
            byte[] publicKeyX,
            byte[] publicKeyY,
            HashAlgorithm hashAlgorithm,
            SymmetricCipher symmetricCipher,
            int ivSize,
            int tagSize) throws GeneralSecurityException {
        validateInputs(privateKeyBytes, publicKeyX, publicKeyY, ivSize, tagSize);
        
        this.hashAlgorithm = hashAlgorithm;
        this.symmetricCipher = symmetricCipher;
        this.ivSize = ivSize;
        this.tagSize = tagSize;
        
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
     * Constructs a new SM2Encryption instance for encryption only.
     */
    public Sm2Encryption(
            byte[] publicKeyX,
            byte[] publicKeyY,
            HashAlgorithm hashAlgorithm,
            SymmetricCipher symmetricCipher,
            int ivSize,
            int tagSize) throws GeneralSecurityException {
        validatePublicKeyInputs(publicKeyX, publicKeyY);
        validateSymmetricParams(ivSize, tagSize);
        
        this.hashAlgorithm = hashAlgorithm;
        this.symmetricCipher = symmetricCipher;
        this.ivSize = ivSize;
        this.tagSize = tagSize;
        this.privateKey = null; // No private key for encryption only
        
        // Create public key
        BigInteger x = new BigInteger(1, publicKeyX);
        BigInteger y = new BigInteger(1, publicKeyY);
        ECPoint q = SM2_CURVE_PARAMS.getCurve().createPoint(x, y);
        this.publicKey = new ECPublicKeyParameters(q, SM2_DOMAIN_PARAMS);
    }
    
    /**
     * Encrypts the given plaintext using SM2 hybrid encryption.
     */
    public byte[] encrypt(byte[] plaintext, byte[] contextInfo) throws GeneralSecurityException {
        try {
            // Generate random symmetric key
            byte[] symmetricKey = new byte[SYMMETRIC_KEY_SIZE_BYTES];
            new SecureRandom().nextBytes(symmetricKey);
            
            // Encrypt the symmetric key using SM2
            SM2Engine sm2Engine = new SM2Engine(getDigest());
            sm2Engine.init(true, publicKey);
            byte[] encryptedKey = sm2Engine.processBlock(symmetricKey, 0, symmetricKey.length);
            
            // Encrypt the data using symmetric cipher
            byte[] encryptedData;
            if (symmetricCipher == SymmetricCipher.SM4_GCM) {
                encryptedData = encryptWithSm4Gcm(plaintext, symmetricKey, contextInfo);
            } else {
                encryptedData = encryptWithAesGcm(plaintext, symmetricKey, contextInfo);
            }
            
            // Combine encrypted key and encrypted data
            byte[] result = new byte[encryptedKey.length + encryptedData.length];
            System.arraycopy(encryptedKey, 0, result, 0, encryptedKey.length);
            System.arraycopy(encryptedData, 0, result, encryptedKey.length, encryptedData.length);
            
            return result;
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to encrypt message", e);
        }
    }
    
    /**
     * Decrypts the given ciphertext using SM2 hybrid encryption.
     */
    public byte[] decrypt(byte[] ciphertext, byte[] contextInfo) throws GeneralSecurityException {
        if (privateKey == null) {
            throw new GeneralSecurityException("Cannot decrypt without private key");
        }
        
        try {
            // The SM2 encrypted key is at the beginning
            // For SM2P256V1, the encrypted key size is typically 97 bytes (1 + 32 + 32 + 32)
            // But we need to determine this dynamically based on the actual ciphertext
            
            // Try to decrypt with SM2 to find the key length
            SM2Engine sm2Engine = new SM2Engine(getDigest());
            sm2Engine.init(false, privateKey);
            
            // SM2 encrypted data format is: 0x04 + x + y + hash + encrypted_data
            // For SM2P256V1: 1 + 32 + 32 + 32 = 97 bytes minimum
            int minSm2Size = 1 + SM2_KEY_SIZE_BYTES + SM2_KEY_SIZE_BYTES + getDigest().getDigestSize();
            
            if (ciphertext.length < minSm2Size) {
                throw new GeneralSecurityException("Ciphertext too short");
            }
            
            // Find the SM2 encrypted key length by trying different lengths
            byte[] symmetricKey = null;
            int encryptedKeyLength = 0;
            
            for (int len = minSm2Size; len <= Math.min(ciphertext.length - ivSize - tagSize, minSm2Size + 32); len++) {
                try {
                    byte[] potentialEncryptedKey = new byte[len];
                    System.arraycopy(ciphertext, 0, potentialEncryptedKey, 0, len);
                    symmetricKey = sm2Engine.processBlock(potentialEncryptedKey, 0, potentialEncryptedKey.length);
                    encryptedKeyLength = len;
                    break;
                } catch (Exception ignored) {
                    // Try next length
                }
            }
            
            if (symmetricKey == null) {
                throw new GeneralSecurityException("Failed to decrypt symmetric key");
            }
            
            // Extract encrypted data
            byte[] encryptedData = new byte[ciphertext.length - encryptedKeyLength];
            System.arraycopy(ciphertext, encryptedKeyLength, encryptedData, 0, encryptedData.length);
            
            // Decrypt the data using symmetric cipher
            if (symmetricCipher == SymmetricCipher.SM4_GCM) {
                return decryptWithSm4Gcm(encryptedData, symmetricKey, contextInfo);
            } else {
                return decryptWithAesGcm(encryptedData, symmetricKey, contextInfo);
            }
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to decrypt message", e);
        }
    }
    
    private byte[] encryptWithSm4Gcm(byte[] plaintext, byte[] key, byte[] contextInfo) 
            throws GeneralSecurityException {
        // Use Tink's SM4-GCM implementation
        Sm4GcmJce sm4Gcm = new Sm4GcmJce(key);
        return sm4Gcm.encrypt(plaintext, contextInfo);
    }
    
    private byte[] decryptWithSm4Gcm(byte[] ciphertext, byte[] key, byte[] contextInfo) 
            throws GeneralSecurityException {
        // Use Tink's SM4-GCM implementation
        Sm4GcmJce sm4Gcm = new Sm4GcmJce(key);
        return sm4Gcm.decrypt(ciphertext, contextInfo);
    }
    
    private byte[] encryptWithAesGcm(byte[] plaintext, byte[] key, byte[] contextInfo) 
            throws GeneralSecurityException {
        // Use Tink's AES-GCM implementation
        AesGcmJce aesGcm = new AesGcmJce(key);
        return aesGcm.encrypt(plaintext, contextInfo);
    }
    
    private byte[] decryptWithAesGcm(byte[] ciphertext, byte[] key, byte[] contextInfo) 
            throws GeneralSecurityException {
        // Use Tink's AES-GCM implementation
        AesGcmJce aesGcm = new AesGcmJce(key);
        return aesGcm.decrypt(ciphertext, contextInfo);
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
    
    private static byte[] normalizeCoordinateBytes(byte[] bytes) {
        if (bytes.length == SM2_KEY_SIZE_BYTES) {
            return bytes;
        } else if (bytes.length > SM2_KEY_SIZE_BYTES) {
            // Remove leading zeros
            byte[] result = new byte[SM2_KEY_SIZE_BYTES];
            System.arraycopy(bytes, bytes.length - SM2_KEY_SIZE_BYTES, result, 0, SM2_KEY_SIZE_BYTES);
            return result;
        } else {
            // Pad with leading zeros
            byte[] result = new byte[SM2_KEY_SIZE_BYTES];
            System.arraycopy(bytes, 0, result, SM2_KEY_SIZE_BYTES - bytes.length, bytes.length);
            return result;
        }
    }
    
    private void validateInputs(byte[] privateKeyBytes, byte[] publicKeyX, byte[] publicKeyY, 
                               int ivSize, int tagSize) throws GeneralSecurityException {
        if (privateKeyBytes == null || privateKeyBytes.length != SM2_KEY_SIZE_BYTES) {
            throw new GeneralSecurityException("Private key must be " + SM2_KEY_SIZE_BYTES + " bytes");
        }
        validatePublicKeyInputs(publicKeyX, publicKeyY);
        validateSymmetricParams(ivSize, tagSize);
    }
    
    private void validatePublicKeyInputs(byte[] publicKeyX, byte[] publicKeyY) throws GeneralSecurityException {
        if (publicKeyX == null || publicKeyX.length != SM2_KEY_SIZE_BYTES) {
            throw new GeneralSecurityException("Public key X coordinate must be " + SM2_KEY_SIZE_BYTES + " bytes");
        }
        if (publicKeyY == null || publicKeyY.length != SM2_KEY_SIZE_BYTES) {
            throw new GeneralSecurityException("Public key Y coordinate must be " + SM2_KEY_SIZE_BYTES + " bytes");
        }
    }
    
    private void validateSymmetricParams(int ivSize, int tagSize) throws GeneralSecurityException {
        if (ivSize <= 0 || ivSize > 16) {
            throw new GeneralSecurityException("IV size must be between 1 and 16 bytes");
        }
        if (tagSize <= 0 || tagSize > 16) {
            throw new GeneralSecurityException("Tag size must be between 1 and 16 bytes");
        }
    }
    
    private void validateKeyPair() throws GeneralSecurityException {
        // Verify that private key generates the same public key
        ECPoint derivedPublicKey = SM2_DOMAIN_PARAMS.getG().multiply(privateKey.getD()).normalize();
        if (!derivedPublicKey.equals(publicKey.getQ().normalize())) {
            throw new GeneralSecurityException("Private and public keys do not form a valid key pair");
        }
    }
}