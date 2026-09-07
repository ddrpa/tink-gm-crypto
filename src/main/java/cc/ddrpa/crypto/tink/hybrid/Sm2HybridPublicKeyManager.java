package cc.ddrpa.crypto.tink.hybrid;

/**
 * This key manager produces new instances of {@code Sm2HybridEncrypt}. It doesn't support key
 * generation.
 */
final class Sm2HybridPublicKeyManager {

    private Sm2HybridPublicKeyManager() {
    }

    static String getKeyType() {
        return "type.googleapis.com/ddrpa.crypto.tink.Sm2HybridPublicKey";
    }
}
