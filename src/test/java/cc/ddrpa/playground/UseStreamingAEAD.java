package cc.ddrpa.playground;

import cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKeyManager;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import org.junit.BeforeClass;
import org.junit.Test;

public class UseStreamingAEAD {

    private static final int BLOCK_SIZE_IN_BYTES = 8 * 1024;

    private static StreamingAead streamingAead;

    @BeforeClass
    public static void setUp() throws IOException, GeneralSecurityException {
        // 创建大文件
        // mkfile -n 4g mock.blob
        // 注册 AEAD 基元和 SM4-GCM-HKDF 实现
        StreamingAeadConfig.register();
        Sm4GcmHkdfStreamingKeyManager.register(false);
        // 加载密钥集
        try (InputStream ins = new FileInputStream("streaming_aead_keyset.json")) {
            KeysetHandle keysetHandle = CleartextKeysetHandle.read(
                JsonKeysetReader.withInputStream(ins));
            streamingAead = keysetHandle.getPrimitive(RegistryConfiguration.get(),
                StreamingAead.class);
        }
    }

    @Test
    public void encryptAndDecryptTextWithAEAD() throws IOException, GeneralSecurityException {
        byte[] associatedData = LocalDateTime.now().toString().getBytes();
        // 加密
        try (WritableByteChannel encryptingChannel = streamingAead.newEncryptingChannel(
            FileChannel.open(Paths.get("encrypted.blob"), StandardOpenOption.WRITE,
                StandardOpenOption.CREATE), associatedData);
            FileChannel inputChannel = FileChannel.open(Paths.get("mock.blob"),
                StandardOpenOption.READ)
        ) {
            ByteBuffer byteBuffer = ByteBuffer.allocate(BLOCK_SIZE_IN_BYTES);
            while (true) {
                int read = inputChannel.read(byteBuffer);
                if (read <= 0) {
                    break;
                }
                byteBuffer.flip();
                while (byteBuffer.hasRemaining()) {
                    encryptingChannel.write(byteBuffer);
                }
                byteBuffer.clear();
            }
        }
        // 解密
        try (ReadableByteChannel decryptingChannel = streamingAead.newDecryptingChannel(
            FileChannel.open(Paths.get("encrypted.blob"), StandardOpenOption.READ), associatedData);
            FileChannel outputChannel =
                FileChannel.open(Paths.get("decrypted.blob"), StandardOpenOption.WRITE,
                    StandardOpenOption.CREATE)
        ) {
            ByteBuffer byteBuffer = ByteBuffer.allocate(BLOCK_SIZE_IN_BYTES);
            while (true) {
                int read = decryptingChannel.read(byteBuffer);
                if (read <= 0) {
                    break;
                }
                byteBuffer.flip();
                while (byteBuffer.hasRemaining()) {
                    outputChannel.write(byteBuffer);
                }
                byteBuffer.clear();
            }
        }
        // 计算两个文件的 sha-1 应当相同
    }
}