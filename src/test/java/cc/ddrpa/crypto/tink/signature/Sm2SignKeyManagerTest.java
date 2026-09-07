package cc.ddrpa.crypto.tink.signature;

import cc.ddrpa.crypto.tink.sm2.internal.Sm2Curve;
import cc.ddrpa.crypto.tink.sm2.internal.Sm2KeyUtil;
import com.google.crypto.tink.*;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.signature.SignatureConfig;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for Sm2SignKeyManager and Sm2VerifyKeyManager.
 */
class Sm2SignKeyManagerTest {

    // The default SM2 user ID, see GB/T 32918.2.
    private static final byte[] USER_ID = "1234567812345678".getBytes(US_ASCII);

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    @BeforeEach
    void register() throws Exception {
        Sm2SignKeyManager.registerPair(true);
        // Registers the PublicKeySign / PublicKeyVerify wrappers (used by KeysetHandle to obtain
        // primitives from keysets).
        SignatureConfig.register();
    }

    @Test
    void testKeyManagersRegistered() throws Exception {
        assertThat(KeyManagerRegistry.globalInstance()
                .getKeyManager(Sm2SignKeyManager.getKeyType(), PublicKeySign.class)).isNotNull();
        assertThat(KeyManagerRegistry.globalInstance()
                .getKeyManager(Sm2VerifyKeyManager.getKeyType(), PublicKeyVerify.class)).isNotNull();
    }

    @Test
    void signVerifyRoundTripThroughKeysetHandle() throws Exception {
        KeysetHandle privateHandle =
                KeysetHandle.generateNew(Sm2SignKeyManager.sm2SignTemplate().toParameters());
        PublicKeySign signer =
                privateHandle.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
        KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
        PublicKeyVerify verifier =
                publicHandle.getPrimitive(RegistryConfiguration.get(), PublicKeyVerify.class);

        String[] messages = {"hello sm2", "some longer message to be signed", ""};
        for (String message : messages) {
            byte[] data = message.getBytes(UTF_8);
            byte[] signature = signer.sign(data);
            // The signature must verify with the corresponding public keyset handle.
            verifier.verify(signature, data);
        }
    }

    @Test
    void tamperedSignatureAndWrongDataDoNotVerify() throws Exception {
        KeysetHandle privateHandle =
                KeysetHandle.generateNew(Sm2SignKeyManager.sm2SignTemplate().toParameters());
        PublicKeySign signer =
                privateHandle.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
        PublicKeyVerify verifier =
                privateHandle.getPublicKeysetHandle().getPrimitive(
                        RegistryConfiguration.get(), PublicKeyVerify.class);

        byte[] data = "message".getBytes(UTF_8);
        byte[] signature = signer.sign(data);

        byte[] tampered = Arrays.copyOf(signature, signature.length);
        tampered[tampered.length - 1] ^= 0x01;
        assertThrows(GeneralSecurityException.class, () -> verifier.verify(tampered, data));

        byte[] otherData = "other message".getBytes(UTF_8);
        assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, otherData));
    }

    @Test
    void tinkSignaturesArePrefixedWithKeyId() throws Exception {
        KeysetHandle privateHandle =
                KeysetHandle.generateNew(Sm2SignKeyManager.sm2SignTemplate().toParameters());
        int id = privateHandle.getAt(0).getId();
        Sm2SignaturePrivateKey privateKey =
                (Sm2SignaturePrivateKey) privateHandle.getAt(0).getKey();
        assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(id);

        PublicKeySign signer =
                privateHandle.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
        byte[] signature = signer.sign("message".getBytes(UTF_8));

        // TINK prefix: 0x01 followed by the 4-byte big-endian key id, then a raw 64-byte
        // signature.
        assertThat(signature.length).isEqualTo(5 + 64);
        assertThat(signature[0]).isEqualTo((byte) 1);
        assertThat(Arrays.copyOf(signature, 5)).isEqualTo(privateKey.getOutputPrefix().toByteArray());
        assertThat(signature).isEqualTo(
                concat(privateKey.getOutputPrefix().toByteArray(),
                        Arrays.copyOfRange(signature, 5, signature.length)));
    }

    @Test
    void rawSignaturesHaveNoPrefix() throws Exception {
        KeysetHandle privateHandle =
                KeysetHandle.generateNew(Sm2SignKeyManager.rawSm2SignTemplate().toParameters());
        PublicKeySign signer =
                privateHandle.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
        PublicKeyVerify verifier =
                privateHandle.getPublicKeysetHandle().getPrimitive(
                        RegistryConfiguration.get(), PublicKeyVerify.class);

        byte[] data = "hello sm2".getBytes(UTF_8);
        byte[] signature = signer.sign(data);
        // A raw (NO_PREFIX) signature is exactly the raw 64-byte r || s encoding.
        assertThat(signature.length).isEqualTo(64);
        verifier.verify(signature, data);
    }

    @Test
    void rawVerifyRejectsMalformedSignatures() throws Exception {
        KeysetHandle privateHandle =
                KeysetHandle.generateNew(Sm2SignKeyManager.rawSm2SignTemplate().toParameters());
        PublicKeyVerify verifier =
                privateHandle.getPublicKeysetHandle().getPrimitive(
                        RegistryConfiguration.get(), PublicKeyVerify.class);

        byte[] data = "hello sm2".getBytes(UTF_8);
        // All-zero signature.
        assertThrows(GeneralSecurityException.class,
                () -> verifier.verify(new byte[64], data));
        // Signature of wrong length.
        assertThrows(GeneralSecurityException.class,
                () -> verifier.verify(new byte[32], data));
        assertThrows(GeneralSecurityException.class,
                () -> verifier.verify(new byte[65], data));
    }

    @Test
    void rawSignaturesInteroperateWithBouncyCastle() throws Exception {
        KeysetHandle privateHandle =
                KeysetHandle.generateNew(Sm2SignKeyManager.rawSm2SignTemplate().toParameters());
        Sm2SignaturePrivateKey privateKey =
                (Sm2SignaturePrivateKey) privateHandle.getAt(0).getKey();
        byte[] d = privateKey.getPrivateValue().toByteArray(InsecureSecretKeyAccess.get());
        byte[] q = privateKey.getPublicKey().getPublicKey().toByteArray();
        assertThat(d.length).isEqualTo(32);
        assertThat(q.length).isEqualTo(64);

        PublicKeySign signer =
                privateHandle.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
        PublicKeyVerify verifier =
                privateHandle.getPublicKeysetHandle().getPrimitive(
                        RegistryConfiguration.get(), PublicKeyVerify.class);

        byte[] message = "hello sm2".getBytes(UTF_8);

        // 1. Our raw signature is accepted by a BouncyCastle SM2Signer which derives the public
        // key from our private key material (d * G).
        byte[] ourSignature = signer.sign(message);
        assertThat(ourSignature.length).isEqualTo(64);
        ECPoint derivedPoint =
                Sm2Curve.validatePublicPoint(
                        Sm2Curve.getDomainParameters().getG().multiply(new BigInteger(1, d)).normalize());
        assertThat(Sm2Curve.encodePointWithoutPrefix(derivedPoint)).isEqualTo(q);
        ECPublicKeyParameters derivedPublicParams =
                new ECPublicKeyParameters(derivedPoint, Sm2Curve.getDomainParameters());
        SM2Signer bcVerifier = new SM2Signer(new PlainDSAEncoding(), new SM3Digest());
        bcVerifier.init(false, new ParametersWithID(derivedPublicParams, USER_ID));
        bcVerifier.update(message, 0, message.length);
        assertTrue(bcVerifier.verifySignature(ourSignature));

        // 2. A BouncyCastle-generated raw signature over the same message is accepted by our
        // verifier.
        ECPrivateKeyParameters privateKeyParams = Sm2KeyUtil.toPrivateKeyParameters(d);
        SM2Signer bcSigner = new SM2Signer(new PlainDSAEncoding(), new SM3Digest());
        bcSigner.init(
                true,
                new ParametersWithID(
                        new ParametersWithRandom(privateKeyParams, Sm2KeyUtil.getSecureRandom()),
                        USER_ID));
        bcSigner.update(message, 0, message.length);
        byte[] bcSignature = bcSigner.generateSignature();
        assertThat(bcSignature.length).isEqualTo(64);
        verifier.verify(bcSignature, message);
    }

    @Test
    void twoKeyKeysetWorks() throws Exception {
        KeysetHandle keyAHandle =
                KeysetHandle.generateNew(Sm2SignKeyManager.sm2SignTemplate().toParameters());
        KeysetHandle keyBHandle =
                KeysetHandle.generateNew(Sm2SignKeyManager.sm2SignTemplate().toParameters());
        // Extremely unlikely, but make sure the two keys have different ids (hence different
        // prefixes).
        while (keyBHandle.getAt(0).getId() == keyAHandle.getAt(0).getId()) {
            keyBHandle =
                    KeysetHandle.generateNew(Sm2SignKeyManager.sm2SignTemplate().toParameters());
        }
        Sm2SignaturePrivateKey keyA = (Sm2SignaturePrivateKey) keyAHandle.getAt(0).getKey();
        Sm2SignaturePrivateKey keyB = (Sm2SignaturePrivateKey) keyBHandle.getAt(0).getKey();

        KeysetHandle twoKeyHandle =
                KeysetHandle.newBuilder()
                        .addEntry(KeysetHandle.importKey(keyA).makePrimary())
                        .addEntry(KeysetHandle.importKey(keyB))
                        .build();
        assertThat(twoKeyHandle.size()).isEqualTo(2);

        PublicKeySign signer =
                twoKeyHandle.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
        PublicKeyVerify verifier =
                twoKeyHandle.getPublicKeysetHandle().getPrimitive(
                        RegistryConfiguration.get(), PublicKeyVerify.class);

        // Signing always uses the primary key (keyA).
        String[] messages = {"first message", "second message", ""};
        for (String message : messages) {
            byte[] data = message.getBytes(UTF_8);
            byte[] signature = signer.sign(data);
            assertThat(signature.length).isEqualTo(5 + 64);
            assertThat(Arrays.copyOf(signature, 5))
                    .isEqualTo(keyA.getOutputPrefix().toByteArray());
            verifier.verify(signature, data);
        }

        // Signatures produced by the backup key alone also verify with the two-key public handle
        // (dispatched via the key prefix)...
        byte[] data = "prefix dispatch sanity".getBytes(UTF_8);
        PublicKeySign keyBSigner =
                keyBHandle.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
        byte[] keyBSignature = keyBSigner.sign(data);
        verifier.verify(keyBSignature, data);
        // ... but do not verify with a public handle which only contains keyA.
        PublicKeyVerify keyAVerifier =
                keyAHandle.getPublicKeysetHandle().getPrimitive(
                        RegistryConfiguration.get(), PublicKeyVerify.class);
        assertThrows(GeneralSecurityException.class,
                () -> keyAVerifier.verify(keyBSignature, data));
    }

    @Test
    void jsonKeysetRoundTripWorks() throws Exception {
        KeysetHandle privateHandle =
                KeysetHandle.generateNew(Sm2SignKeyManager.sm2SignTemplate().toParameters());
        PublicKeySign originalSigner =
                privateHandle.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
        byte[] message = "hello sm2".getBytes(UTF_8);
        byte[] originalSignature = originalSigner.sign(message);

        Path tempDir = Files.createTempDirectory("tink-sm2-json-test");
        Path privateFile = tempDir.resolve("sm2_private_keyset.json");
        Path publicFile = tempDir.resolve("sm2_public_keyset.json");
        try {
            // Write the private keyset as JSON, read it back and check that key material is
            // preserved and signing/verification still works.
            try (OutputStream out = Files.newOutputStream(privateFile)) {
                CleartextKeysetHandle.write(privateHandle, JsonKeysetWriter.withOutputStream(out));
            }
            KeysetHandle parsedPrivateHandle;
            try (InputStream in = Files.newInputStream(privateFile)) {
                parsedPrivateHandle =
                        CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(in));
            }
            assertTrue(parsedPrivateHandle.getAt(0).getKey().equalsKey(
                    privateHandle.getAt(0).getKey()));
            PublicKeySign parsedSigner = parsedPrivateHandle.getPrimitive(
                    RegistryConfiguration.get(), PublicKeySign.class);
            PublicKeyVerify parsedPrivateVerifier =
                    parsedPrivateHandle.getPublicKeysetHandle().getPrimitive(
                            RegistryConfiguration.get(), PublicKeyVerify.class);
            byte[] parsedSignature = parsedSigner.sign(message);
            parsedPrivateVerifier.verify(parsedSignature, message);

            // The original signature must verify with the public handle of the parsed private
            // keyset.
            parsedPrivateVerifier.verify(originalSignature, message);

            // Write only the public keyset as JSON, read it into a fresh handle and verify the
            // signatures produced by the original (private) handle.
            KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
            try (OutputStream out = Files.newOutputStream(publicFile)) {
                CleartextKeysetHandle.write(publicHandle, JsonKeysetWriter.withOutputStream(out));
            }
            KeysetHandle parsedPublicHandle;
            try (InputStream in = Files.newInputStream(publicFile)) {
                parsedPublicHandle =
                        CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(in));
            }
            PublicKeyVerify publicVerifier = parsedPublicHandle.getPrimitive(
                    RegistryConfiguration.get(), PublicKeyVerify.class);
            publicVerifier.verify(originalSignature, message);
            publicVerifier.verify(parsedSignature, message);
        } finally {
            Files.deleteIfExists(privateFile);
            Files.deleteIfExists(publicFile);
            Files.deleteIfExists(tempDir);
        }
    }
}
