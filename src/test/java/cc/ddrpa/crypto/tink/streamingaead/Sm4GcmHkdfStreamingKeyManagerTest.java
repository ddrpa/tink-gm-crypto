package cc.ddrpa.crypto.tink.streamingaead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cc.ddrpa.crypto.tink.streamingaead.internal.testing.Sm4GcmHkdfStreamingTestUtil;
import cc.ddrpa.crypto.tink.streamingaead.internal.testing.StreamingAeadTestVector;
import com.google.common.truth.Truth;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.SlowInputStream;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Sm4GcmHkdfStreaming;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.testing.StreamingTestUtil.ByteBufferChannel;
import com.google.crypto.tink.testing.StreamingTestUtil.SeekableByteBufferChannel;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import javax.annotation.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import java.util.stream.Stream;

/**
 * Test for Sm4GcmHkdfStreamingKeyManager.
 */
class Sm4GcmHkdfStreamingKeyManagerTest {

    private static final String[] KEY_TEMPLATES = new String[]{"SM4_GCM_HKDF_4KB",
        "SM4_GCM_HKDF_1MB",};
    private static final StreamingAeadTestVector[] streamingTestVector = Sm4GcmHkdfStreamingTestUtil.createSm4GcmHkdfTestVectors();

    @BeforeEach
    void register() throws Exception {
        Sm4GcmHkdfStreamingKeyManager.register(true);
        StreamingAeadConfig.register();
        KeyDerivationConfig.register();
    }

    @Test
    void testKeyManagerRegistered() throws Exception {
        assertThat(KeyManagerRegistry.globalInstance()
            .getKeyManager("type.googleapis.com/ddrpa.crypto.tink.Sm4GcmHkdfStreamingKey",
                StreamingAead.class)).isNotNull();
    }

    @Test
    void getPrimitive_works() throws Exception {
        Parameters parameters = Sm4GcmHkdfStreamingKeyManager.sm4GcmHkdf4KBTemplate()
            .toParameters();
        KeysetHandle handle = KeysetHandle.generateNew(parameters);
        StreamingAead streamingAead = handle.getPrimitive(RegistryConfiguration.get(),
            StreamingAead.class);
        StreamingAead directAead = Sm4GcmHkdfStreaming.create(
            (cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKey) handle.getAt(0).getKey());

        StreamingTestUtil.testEncryptDecryptDifferentInstances(streamingAead, directAead, 0, 2049,
            1000);
    }

    @Test
    void testSkip() throws Exception {
        KeysetHandle handle = KeysetHandle.generateNew(
            Sm4GcmHkdfStreamingKeyManager.sm4GcmHkdf4KBTemplate().toParameters());
        StreamingAead streamingAead = handle.getPrimitive(RegistryConfiguration.get(),
            StreamingAead.class);
        int offset = 0;
        int plaintextSize = 1 << 16;
        // Runs the test with different sizes for the chunks to skip.
        StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 1);
        StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 64);
        StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 300);
    }

    @Test
    void testNewKeyMultipleTimes() throws Exception {
        Parameters parameters = Sm4GcmHkdfStreamingKeyManager.sm4GcmHkdf4KBTemplate()
            .toParameters();
        Set<String> keys = new TreeSet<>();
        // Calls newKey multiple times and make sure that they generate different keys.
        int numTests = 100;
        for (int i = 0; i < numTests; i++) {
            KeysetHandle handle = KeysetHandle.generateNew(parameters);
            cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKey key = (cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKey) handle.getAt(
                0).getKey();
            keys.add(
                Hex.encode(key.getInitialKeyMaterial().toByteArray(InsecureSecretKeyAccess.get())));
        }
        assertThat(keys).hasSize(numTests);
    }

    @Test
    void testSm4GcmHkdf4KBTemplate() throws Exception {
        KeyTemplate template = Sm4GcmHkdfStreamingKeyManager.sm4GcmHkdf4KBTemplate();
        assertThat(template.toParameters()).isEqualTo(
            Sm4GcmHkdfStreamingParameters.builder().setKeySizeBytes(16)
                .setDerivedSm4GcmKeySizeBytes(16).setCiphertextSegmentSizeBytes(4 * 1024)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256).build());
    }

    @Test
    void testSm4GcmHkdf1MBTemplate() throws Exception {
        KeyTemplate template = Sm4GcmHkdfStreamingKeyManager.sm4GcmHkdf1MBTemplate();
        assertThat(template.toParameters()).isEqualTo(
            Sm4GcmHkdfStreamingParameters.builder().setKeySizeBytes(16)
                .setDerivedSm4GcmKeySizeBytes(16).setCiphertextSegmentSizeBytes(1024 * 1024)
                .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256).build());
    }

    @ParameterizedTest
    @MethodSource("provideTemplateNames")
    void testTemplates(String templateName) throws Exception {
        KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
        assertThat(h.size()).isEqualTo(1);
        assertThat(h.getAt(0).getKey().getParameters()).isEqualTo(
            KeyTemplates.get(templateName).toParameters());
    }

    private static Stream<Arguments> provideTemplateNames() {
        return Stream.of(KEY_TEMPLATES).map(Arguments::of);
    }

    @ParameterizedTest
    @MethodSource("provideTemplateNames")
    void testCreateKeyFromRandomness(String templateName) throws Exception {
        byte[] keyMaterial = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
            39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
            61, 62, 63, 64, 65, 66, 67, 68,};
        Sm4GcmHkdfStreamingParameters parameters = (Sm4GcmHkdfStreamingParameters) KeyTemplates.get(
            templateName).toParameters();
        cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKeyManager.createSm4GcmHkdfStreamingKeyFromRandomness(
            parameters, new ByteArrayInputStream(keyMaterial), null, InsecureSecretKeyAccess.get());
        byte[] expectedKeyBytes = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
        Key expectedKey = cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKey.create(
            parameters, SecretBytes.copyFrom(expectedKeyBytes, InsecureSecretKeyAccess.get()));
        assertTrue(key.equalsKey(expectedKey));
    }

    @Test
    void testCreateKeyFromRandomness_slowInputStream_works() throws Exception {
        Sm4GcmHkdfStreamingParameters parameters = Sm4GcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(16).setDerivedSm4GcmKeySizeBytes(16)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .setHkdfHashType(Sm4GcmHkdfStreamingParameters.HashType.SHA256).build();

        byte[] keyMaterial = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
            39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
            61, 62, 63, 64, 65, 66, 67, 68,};
        cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKey key = Sm4GcmHkdfStreamingKeyManager.createSm4GcmHkdfStreamingKeyFromRandomness(
            parameters, SlowInputStream.copyFrom(keyMaterial), null, InsecureSecretKeyAccess.get());
        byte[] expectedKeyBytes = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
        Key expectedKey = cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKey.create(
            parameters, SecretBytes.copyFrom(expectedKeyBytes, InsecureSecretKeyAccess.get()));
        assertTrue(key.equalsKey(expectedKey));
    }

    @Test
    void serializeAndParse_works() throws Exception {
        Parameters parameters = Sm4GcmHkdfStreamingKeyManager.sm4GcmHkdf4KBTemplate()
            .toParameters();
        KeysetHandle handle = KeysetHandle.generateNew(parameters);
        byte[] serializedHandle = TinkProtoKeysetFormat.serializeKeyset(handle,
            InsecureSecretKeyAccess.get());
        KeysetHandle parsedHandle = TinkProtoKeysetFormat.parseKeyset(serializedHandle,
            InsecureSecretKeyAccess.get());
        assertThat(parsedHandle.equalsKeyset(handle)).isTrue();
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    void decryptCiphertextInputStream_works(StreamingAeadTestVector v) throws Exception {
        KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getKey()).makePrimary();
        @Nullable Integer id = v.getKey().getIdRequirementOrNull();
        if (id == null) {
            entry.withRandomId();
        } else {
            entry.withFixedId(id);
        }
        KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
        StreamingAead streamingAead = handle.getPrimitive(RegistryConfiguration.get(),
            StreamingAead.class);
        InputStream plaintextStream = streamingAead.newDecryptingStream(
            new ByteArrayInputStream(v.getCiphertext()), v.getAssociatedData());
        byte[] decryption = new byte[v.getPlaintext().length];
        assertThat(plaintextStream.read(decryption)).isEqualTo(v.getPlaintext().length);
        assertThat(decryption).isEqualTo(v.getPlaintext());
        // There must be no more data available.
        assertThat(plaintextStream.read()).isEqualTo(-1);
    }

    private static Stream<Arguments> provideTestVectors() {
        return Stream.of(streamingTestVector).map(Arguments::of);
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    void encryptCiphertextInputStream_forCreation(StreamingAeadTestVector v) throws Exception {
        KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getKey()).makePrimary();
        @Nullable Integer id = v.getKey().getIdRequirementOrNull();
        if (id == null) {
            entry.withRandomId();
        } else {
            entry.withFixedId(id);
        }
        KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
        StreamingAead streamingAead = handle.getPrimitive(RegistryConfiguration.get(),
            StreamingAead.class);
        ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();
        OutputStream plaintextStream = streamingAead.newEncryptingStream(ciphertextStream,
            v.getAssociatedData());
        plaintextStream.write(v.getPlaintext());
        plaintextStream.close();

        Truth.assertWithMessage(
                "A possible ciphertext would be " + Hex.encode(ciphertextStream.toByteArray()))
            .that(v.getCiphertext()).isNotEmpty();
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    void decryptCiphertextChannel_works(StreamingAeadTestVector v) throws Exception {
        KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getKey()).makePrimary();
        @Nullable Integer id = v.getKey().getIdRequirementOrNull();
        if (id == null) {
            entry.withRandomId();
        } else {
            entry.withFixedId(id);
        }
        KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
        StreamingAead streamingAead = handle.getPrimitive(RegistryConfiguration.get(),
            StreamingAead.class);
        ReadableByteChannel plaintextChannel = streamingAead.newDecryptingChannel(
            new ByteBufferChannel(v.getCiphertext()), v.getAssociatedData());
        ByteBuffer decryption = ByteBuffer.allocate(v.getPlaintext().length);
        assertThat(plaintextChannel.read(decryption)).isEqualTo(v.getPlaintext().length);
        assertThat(decryption.array()).isEqualTo(v.getPlaintext());
        // There must be no more data available.
        ByteBuffer endOfStreamChecker = ByteBuffer.allocate(1);
        assertThat(plaintextChannel.read(endOfStreamChecker)).isEqualTo(-1);
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    void decryptSeekableByteChannel_works(StreamingAeadTestVector v) throws Exception {
        KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getKey()).makePrimary();
        @Nullable Integer id = v.getKey().getIdRequirementOrNull();
        if (id == null) {
            entry.withRandomId();
        } else {
            entry.withFixedId(id);
        }
        KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
        StreamingAead streamingAead = handle.getPrimitive(RegistryConfiguration.get(),
            StreamingAead.class);
        SeekableByteChannel plaintextChannel = streamingAead.newSeekableDecryptingChannel(
            new SeekableByteBufferChannel(v.getCiphertext()), v.getAssociatedData());
        // We move to some arbitrary place in the buffer and read the rest of the stream.
        int start = (v.getPlaintext().length + 1) / 2;
        int len = v.getPlaintext().length - start;
        plaintextChannel.position(start);
        ByteBuffer decryption = ByteBuffer.allocate(len);
        assertThat(plaintextChannel.read(decryption)).isEqualTo(len);
        assertThat(decryption.array()).isEqualTo(
            Arrays.copyOfRange(v.getPlaintext(), start, start + len));
        // There must be no more data available.
        ByteBuffer endOfStreamChecker = ByteBuffer.allocate(1);
        if (v.getPlaintext().length != 0) {
            assertThat(plaintextChannel.read(endOfStreamChecker)).isEqualTo(-1);
        } else {
            // TODO: b/390077226 - This should return -1.
            assertThat(plaintextChannel.read(endOfStreamChecker)).isEqualTo(0);
        }
    }
}
