package cc.ddrpa.crypto.tink.hybrid;

/**
 * This key manager produces new instances of {@code Sm2EncryptionHybridEncrypt}. It doesn't
 * support key generation.
 */
final class Sm2EncryptionPublicKeyManager {

    private Sm2EncryptionPublicKeyManager() {
    }

    static String getKeyType() {
        return "type.googleapis.com/ddrpa.crypto.tink.Sm2EncryptionPublicKey";
    }
}
