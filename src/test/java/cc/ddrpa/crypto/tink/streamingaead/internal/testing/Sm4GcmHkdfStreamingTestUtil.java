package cc.ddrpa.crypto.tink.streamingaead.internal.testing;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKey;
import cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingParameters;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * Test vectors for Sm4GcmHkdf StreamingAEAD.
 */
@AccessesPartialKey
public final class Sm4GcmHkdfStreamingTestUtil {

    private Sm4GcmHkdfStreamingTestUtil() {
    }

    /**
     * From the cross language tests, test_manually_created_test_vector
     */
    private static StreamingAeadTestVector createTestVector0() throws GeneralSecurityException {
        Sm4GcmHkdfStreamingParameters parameters = Sm4GcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(64)
            .setDerivedSm4GcmKeySizeBytes(16)
            .build();
        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters,
            SecretBytes.copyFrom(Hex.decode("6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                InsecureSecretKeyAccess.get()));
        byte[] plaintext = "This is a fairly long plaintext. It is of the exact length to create three output blocks. ".getBytes(
            StandardCharsets.UTF_8);
        byte[] headerLength = Hex.decode("18");
        byte[] salt = Hex.decode("93b3af5e14ab378d065addfc8484da64");
        byte[] noncePrefix = Hex.decode("2c0862877baea8");
        byte[] header = Bytes.concat(headerLength, salt, noncePrefix);

        byte[] c0 = Hex.decode("c1055bc4308e0104cc1bb6cf23e013be594b34d42ddc261e3218b1034804c83bcd35c768fb8be7d7");
        byte[] c1 = Hex.decode("a83d4cf3e8459e00d1aed1e96e3b2e4a1caae8e80ae1c7ded496ecb4f87a5358a1cbc6216ac7a73e980dd5667660a65ed8df67745e968eb24e9bf8af2ca7e775");
        byte[] c2 = Hex.decode("cf2d29a2f28f2e3a0e7a3d0977616e141760a4434790b6af42a5dff22f9029de3211");
        byte[] ciphertext = Bytes.concat(header, c0, c1, c2);
        byte[] aad = "aad".getBytes(StandardCharsets.UTF_8);
        return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
    }

    // Empty plaintext, empty aad.
    private static StreamingAeadTestVector createTestVector1() throws GeneralSecurityException {
        Sm4GcmHkdfStreamingParameters parameters = Sm4GcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(64)
            .setDerivedSm4GcmKeySizeBytes(16)
            .build();
        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters,
            SecretBytes.copyFrom(Hex.decode("6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                InsecureSecretKeyAccess.get()));
        byte[] plaintext = new byte[0];
        byte[] aad = new byte[0];
        byte[] ciphertext = Hex.decode(
            "1893b3af5e14ab378d065addfc8484da642c0862877baea83ac8aa5752e37875e1305b4ef7f1814a");
        return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
    }

    // SHA256
    private static StreamingAeadTestVector createTestVector2() throws GeneralSecurityException {
        Sm4GcmHkdfStreamingParameters parameters = Sm4GcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(64)
            .setDerivedSm4GcmKeySizeBytes(16)
            .build();
        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters,
            SecretBytes.copyFrom(Hex.decode("6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                InsecureSecretKeyAccess.get()));
        byte[] plaintext = new byte[0];
        byte[] aad = new byte[0];
        byte[] ciphertext = Hex.decode(
            "1893b3af5e14ab378d065addfc8484da642c0862877baea82f24be445ab65c9a511b84d38b0e7cc4");
        return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
    }

    // SHA512
    private static StreamingAeadTestVector createTestVector3() throws GeneralSecurityException {
        Sm4GcmHkdfStreamingParameters parameters = Sm4GcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA512)
            .setCiphertextSegmentSizeBytes(64)
            .setDerivedSm4GcmKeySizeBytes(16)
            .build();
        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters,
            SecretBytes.copyFrom(Hex.decode("6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                InsecureSecretKeyAccess.get()));
        byte[] plaintext = new byte[0];
        byte[] aad = new byte[0];
        byte[] ciphertext = Hex.decode(
            "1893b3af5e14ab378d065addfc8484da642c0862877baea874042f46fbfbc91835e1aa5c781dfcd8");
        return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
    }

    // 32 byte key
    private static StreamingAeadTestVector createTestVector4() throws GeneralSecurityException {
        Sm4GcmHkdfStreamingParameters parameters = Sm4GcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(64)
            .setDerivedSm4GcmKeySizeBytes(16)
            .build();
        Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKey.create(parameters, SecretBytes.copyFrom(
            Hex.decode("00112233445566778899aabbccddeeff6eb56cdc726dfbe5d57f2fcdc6e9345b"),
            InsecureSecretKeyAccess.get()));
        byte[] plaintext = new byte[0];
        byte[] aad = new byte[0];
        byte[] ciphertext = Hex.decode(
            "1893b3af5e14ab378d065addfc8484da642c0862877baea8f4420a463b0bc229ccac58cef80e3c95");
        return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
    }

    public static StreamingAeadTestVector[] createSm4GcmHkdfTestVectors() {
        return exceptionIsBug(
            () -> new StreamingAeadTestVector[]{
                createTestVector0(),
                createTestVector1(), createTestVector2(), createTestVector3(), createTestVector4(),
            });
    }
}
