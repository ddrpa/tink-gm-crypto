package cc.ddrpa.crypto.tink.hybridencrypt;

import cc.ddrpa.crypto.tink.proto.Sm2EncryptionPrivateKey;
import cc.ddrpa.crypto.tink.proto.Sm2EncryptionPublicKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.subtle.Sm2Encryption;
import java.security.GeneralSecurityException;

/**
 * Key manager for SM2 hybrid encryption using a simplified approach.
 */
public final class Sm2EncryptionKeyManager {
    
    /**
     * Registers SM2 encryption key manager.
     */
    public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
        // Registration will be implemented later
        // For now, users can create primitives directly using static methods
    }
    
    /**
     * Creates an HybridEncrypt primitive from an SM2 public key.
     */
    public static HybridEncrypt createHybridEncrypt(Sm2EncryptionPublicKey publicKey) 
            throws GeneralSecurityException {
        return new Sm2HybridEncrypt(publicKey);
    }
    
    /**
     * Creates an HybridDecrypt primitive from an SM2 private key.
     */
    public static HybridDecrypt createHybridDecrypt(Sm2EncryptionPrivateKey privateKey) 
            throws GeneralSecurityException {
        return new Sm2HybridDecrypt(privateKey);
    }
    
    /**
     * Generates a new SM2 key pair with SM3 hash and SM4-GCM.
     */
    public static Sm2EncryptionPrivateKey generateKeySm3Sm4Gcm() throws GeneralSecurityException {
        return generateKey(HashType.SM3, true);
    }
    
    /**
     * Generates a new SM2 key pair with SHA256 hash and AES-GCM.
     */
    public static Sm2EncryptionPrivateKey generateKeySha256AesGcm() throws GeneralSecurityException {
        return generateKey(HashType.SHA256, false);
    }
    
    private static Sm2EncryptionPrivateKey generateKey(HashType hashType, boolean useSm4Gcm) 
            throws GeneralSecurityException {
        
        // Generate new key pair
        Sm2Encryption.KeyPair keyPair = Sm2Encryption.generateKeyPair();
        
        // Build KDF params
        cc.ddrpa.crypto.tink.proto.Sm2KdfParams kdfParams = 
            cc.ddrpa.crypto.tink.proto.Sm2KdfParams.newBuilder()
                .setKdfHashType(hashType)
                .build();
        
        // Build symmetric cipher params
        cc.ddrpa.crypto.tink.proto.Sm2SymmetricCipher.Builder cipherBuilder = 
            cc.ddrpa.crypto.tink.proto.Sm2SymmetricCipher.newBuilder();
        
        if (useSm4Gcm) {
            cipherBuilder.setSm4Gcm(
                cc.ddrpa.crypto.tink.proto.Sm4GcmParams.newBuilder()
                    .setIvSize(12)
                    .setTagSize(16)
                    .build());
        } else {
            cipherBuilder.setAesGcm(
                cc.ddrpa.crypto.tink.proto.AesGcmParams.newBuilder()
                    .setIvSize(12)
                    .setTagSize(16)
                    .build());
        }
        
        // Build encryption params
        cc.ddrpa.crypto.tink.proto.Sm2EncryptionParams encryptionParams = 
            cc.ddrpa.crypto.tink.proto.Sm2EncryptionParams.newBuilder()
                .setKdfParams(kdfParams)
                .setDemParams(cipherBuilder.build())
                .build();
        
        // Build public key
        Sm2EncryptionPublicKey publicKey = Sm2EncryptionPublicKey.newBuilder()
            .setVersion(0)
            .setParams(encryptionParams)
            .setX(com.google.protobuf.ByteString.copyFrom(keyPair.getPublicKeyX()))
            .setY(com.google.protobuf.ByteString.copyFrom(keyPair.getPublicKeyY()))
            .build();
        
        // Build private key
        return Sm2EncryptionPrivateKey.newBuilder()
            .setVersion(0)
            .setParams(encryptionParams)
            .setKeyValue(com.google.protobuf.ByteString.copyFrom(keyPair.getPrivateKey()))
            .setPublicKey(publicKey)
            .build();
    }
    
    /**
     * HybridEncrypt implementation using SM2.
     */
    private static final class Sm2HybridEncrypt implements HybridEncrypt {
        
        private final Sm2Encryption sm2Encryption;
        
        private Sm2HybridEncrypt(Sm2EncryptionPublicKey publicKey) throws GeneralSecurityException {
            Sm2Encryption.HashAlgorithm hashAlgorithm = getHashAlgorithm(publicKey.getParams());
            Sm2Encryption.SymmetricCipher symmetricCipher = getSymmetricCipher(publicKey.getParams());
            int ivSize = getIvSize(publicKey.getParams());
            int tagSize = getTagSize(publicKey.getParams());
            
            this.sm2Encryption = new Sm2Encryption(
                publicKey.getX().toByteArray(),
                publicKey.getY().toByteArray(),
                hashAlgorithm,
                symmetricCipher,
                ivSize,
                tagSize);
        }
        
        @Override
        public byte[] encrypt(byte[] plaintext, byte[] contextInfo) throws GeneralSecurityException {
            return sm2Encryption.encrypt(plaintext, contextInfo);
        }
    }
    
    /**
     * HybridDecrypt implementation using SM2.
     */
    private static final class Sm2HybridDecrypt implements HybridDecrypt {
        
        private final Sm2Encryption sm2Encryption;
        
        private Sm2HybridDecrypt(Sm2EncryptionPrivateKey privateKey) throws GeneralSecurityException {
            Sm2EncryptionPublicKey publicKey = privateKey.getPublicKey();
            
            Sm2Encryption.HashAlgorithm hashAlgorithm = getHashAlgorithm(privateKey.getParams());
            Sm2Encryption.SymmetricCipher symmetricCipher = getSymmetricCipher(privateKey.getParams());
            int ivSize = getIvSize(privateKey.getParams());
            int tagSize = getTagSize(privateKey.getParams());
            
            this.sm2Encryption = new Sm2Encryption(
                privateKey.getKeyValue().toByteArray(),
                publicKey.getX().toByteArray(),
                publicKey.getY().toByteArray(),
                hashAlgorithm,
                symmetricCipher,
                ivSize,
                tagSize);
        }
        
        @Override
        public byte[] decrypt(byte[] ciphertext, byte[] contextInfo) throws GeneralSecurityException {
            return sm2Encryption.decrypt(ciphertext, contextInfo);
        }
    }
    
    private static Sm2Encryption.HashAlgorithm getHashAlgorithm(
            cc.ddrpa.crypto.tink.proto.Sm2EncryptionParams params) throws GeneralSecurityException {
        
        switch (params.getKdfParams().getKdfHashType()) {
            case SM3:
                return Sm2Encryption.HashAlgorithm.SM3;
            case SHA256:
                return Sm2Encryption.HashAlgorithm.SHA256;
            default:
                throw new GeneralSecurityException("Unsupported hash type: " + 
                    params.getKdfParams().getKdfHashType());
        }
    }
    
    private static Sm2Encryption.SymmetricCipher getSymmetricCipher(
            cc.ddrpa.crypto.tink.proto.Sm2EncryptionParams params) throws GeneralSecurityException {
        
        if (params.getDemParams().hasSm4Gcm()) {
            return Sm2Encryption.SymmetricCipher.SM4_GCM;
        } else if (params.getDemParams().hasAesGcm()) {
            return Sm2Encryption.SymmetricCipher.AES_GCM;
        } else {
            throw new GeneralSecurityException("Unknown symmetric cipher");
        }
    }
    
    private static int getIvSize(cc.ddrpa.crypto.tink.proto.Sm2EncryptionParams params) 
            throws GeneralSecurityException {
        
        if (params.getDemParams().hasSm4Gcm()) {
            return params.getDemParams().getSm4Gcm().getIvSize();
        } else if (params.getDemParams().hasAesGcm()) {
            return params.getDemParams().getAesGcm().getIvSize();
        } else {
            throw new GeneralSecurityException("Unknown symmetric cipher");
        }
    }
    
    private static int getTagSize(cc.ddrpa.crypto.tink.proto.Sm2EncryptionParams params) 
            throws GeneralSecurityException {
        
        if (params.getDemParams().hasSm4Gcm()) {
            return params.getDemParams().getSm4Gcm().getTagSize();
        } else if (params.getDemParams().hasAesGcm()) {
            return params.getDemParams().getAesGcm().getTagSize();
        } else {
            throw new GeneralSecurityException("Unknown symmetric cipher");
        }
    }
    
    private Sm2EncryptionKeyManager() {}
}