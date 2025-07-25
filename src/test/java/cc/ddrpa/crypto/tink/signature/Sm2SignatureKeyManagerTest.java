package cc.ddrpa.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cc.ddrpa.crypto.tink.signature.Sm2SignatureKeyManager;
import cc.ddrpa.crypto.tink.signature.Sm2SignatureParameters;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.SignatureConfig;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Test for SM2 signature key manager */
public final class Sm2SignatureKeyManagerTest {

    @BeforeAll
    public static void setUp() throws Exception {
        SignatureConfig.register();
        Sm2SignatureKeyManager.register(true);
    }

    @Test
    public void createKeyTemplate_sm3() throws Exception {
        KeyTemplate template = Sm2SignatureKeyManager.sm2Sm3Template();
        assertThat(template.getTypeUrl()).isEqualTo("type.googleapis.com/ddrpa.crypto.tink.Sm2PrivateKey");
    }

    @Test
    public void createKeyTemplate_sha256() throws Exception {
        KeyTemplate template = Sm2SignatureKeyManager.sm2Sha256Template();
        assertThat(template.getTypeUrl()).isEqualTo("type.googleapis.com/ddrpa.crypto.tink.Sm2PrivateKey");
    }

    @Test
    public void createSignVerify_sm3Der_success() throws Exception {
        KeyTemplate template = Sm2SignatureKeyManager.sm2Sm3Template();
        KeysetHandle privateHandle = KeysetHandle.generateNew(template);
        KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

        PublicKeySign signer = privateHandle.getPrimitive(PublicKeySign.class);
        PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

        byte[] message = "Hello SM2 signature!".getBytes();
        byte[] signature = signer.sign(message);

        // Verify should succeed
        verifier.verify(signature, message);
    }

    @Test
    public void createSignVerify_sha256Der_success() throws Exception {
        KeyTemplate template = Sm2SignatureKeyManager.sm2Sha256Template();
        KeysetHandle privateHandle = KeysetHandle.generateNew(template);
        KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

        PublicKeySign signer = privateHandle.getPrimitive(PublicKeySign.class);
        PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

        byte[] message = "Hello SM2 signature with SHA256!".getBytes();
        byte[] signature = signer.sign(message);

        // Verify should succeed
        verifier.verify(signature, message);
    }

    @Test
    public void createSignVerify_rawTemplate_success() throws Exception {
        KeyTemplate template = Sm2SignatureKeyManager.rawSm2Sm3Template();
        KeysetHandle privateHandle = KeysetHandle.generateNew(template);
        KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

        PublicKeySign signer = privateHandle.getPrimitive(PublicKeySign.class);
        PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

        byte[] message = "Hello raw SM2 signature!".getBytes();
        byte[] signature = signer.sign(message);

        // Verify should succeed
        verifier.verify(signature, message);
    }

    @Test
    public void verifyWithWrongMessage_fails() throws Exception {
        KeyTemplate template = Sm2SignatureKeyManager.sm2Sm3Template();
        KeysetHandle privateHandle = KeysetHandle.generateNew(template);
        KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

        PublicKeySign signer = privateHandle.getPrimitive(PublicKeySign.class);
        PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

        byte[] message = "Original message".getBytes();
        byte[] wrongMessage = "Wrong message".getBytes();
        byte[] signature = signer.sign(message);

        // Verify with wrong message should fail
        assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, wrongMessage));
    }

    @Test
    public void verifyWithWrongSignature_fails() throws Exception {
        KeyTemplate template = Sm2SignatureKeyManager.sm2Sm3Template();
        KeysetHandle privateHandle = KeysetHandle.generateNew(template);
        KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

        PublicKeySign signer = privateHandle.getPrimitive(PublicKeySign.class);
        PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

        byte[] message = "Test message".getBytes();
        byte[] signature = signer.sign(message);
        
        // Corrupt the signature
        signature[0] = (byte) (signature[0] ^ 1);

        // Verify with corrupted signature should fail
        assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, message));
    }

    @Test
    public void signatureParameters_builderPattern() throws Exception {
        Sm2SignatureParameters params = Sm2SignatureParameters.builder()
                .setHashAlgorithm(Sm2SignatureParameters.HashAlgorithm.SM3)
                .setSignatureEncoding(Sm2SignatureParameters.SignatureEncoding.DER)
                .setVariant(Sm2SignatureParameters.Variant.TINK)
                .build();

        assertThat(params.getHashAlgorithm()).isEqualTo(Sm2SignatureParameters.HashAlgorithm.SM3);
        assertThat(params.getSignatureEncoding()).isEqualTo(Sm2SignatureParameters.SignatureEncoding.DER);
        assertThat(params.getVariant()).isEqualTo(Sm2SignatureParameters.Variant.TINK);
        assertThat(params.hasIdRequirement()).isTrue();
    }

    @Test
    public void signatureParameters_noPrefix() throws Exception {
        Sm2SignatureParameters params = Sm2SignatureParameters.builder()
                .setHashAlgorithm(Sm2SignatureParameters.HashAlgorithm.SHA256)
                .setSignatureEncoding(Sm2SignatureParameters.SignatureEncoding.IEEE_P1363)
                .setVariant(Sm2SignatureParameters.Variant.NO_PREFIX)
                .build();

        assertThat(params.hasIdRequirement()).isFalse();
    }

    @Test
    public void signatureParameters_missingFields_throws() throws Exception {
        assertThrows(GeneralSecurityException.class, () -> 
                Sm2SignatureParameters.builder()
                        .setHashAlgorithm(Sm2SignatureParameters.HashAlgorithm.SM3)
                        // Missing signature encoding
                        .setVariant(Sm2SignatureParameters.Variant.TINK)
                        .build());

        assertThrows(GeneralSecurityException.class, () -> 
                Sm2SignatureParameters.builder()
                        // Missing hash algorithm
                        .setSignatureEncoding(Sm2SignatureParameters.SignatureEncoding.DER)
                        .setVariant(Sm2SignatureParameters.Variant.TINK)
                        .build());
    }

    @Test
    public void signatureParameters_equality() throws Exception {
        Sm2SignatureParameters params1 = Sm2SignatureParameters.builder()
                .setHashAlgorithm(Sm2SignatureParameters.HashAlgorithm.SM3)
                .setSignatureEncoding(Sm2SignatureParameters.SignatureEncoding.DER)
                .setVariant(Sm2SignatureParameters.Variant.TINK)
                .build();

        Sm2SignatureParameters params2 = Sm2SignatureParameters.builder()
                .setHashAlgorithm(Sm2SignatureParameters.HashAlgorithm.SM3)
                .setSignatureEncoding(Sm2SignatureParameters.SignatureEncoding.DER)
                .setVariant(Sm2SignatureParameters.Variant.TINK)
                .build();

        assertThat(params1).isEqualTo(params2);
        assertThat(params1.hashCode()).isEqualTo(params2.hashCode());
    }
}