package cc.ddrpa.crypto.tink.signature;

/**
 * This key manager produces new instances of {@code Sm2PublicKeyVerify}. It doesn't support key
 * generation.
 */
final class Sm2VerifyKeyManager {

    private Sm2VerifyKeyManager() {
    }

    static String getKeyType() {
        return "type.googleapis.com/ddrpa.crypto.tink.Sm2SignaturePublicKey";
    }
}
