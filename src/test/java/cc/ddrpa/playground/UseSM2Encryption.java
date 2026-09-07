package cc.ddrpa.playground;

import cc.ddrpa.crypto.tink.hybrid.Sm2EncryptionKeyManager;
import cc.ddrpa.crypto.tink.hybrid.Sm2HybridKeyManager;
import com.google.crypto.tink.*;
import com.google.crypto.tink.hybrid.HybridDecryptWrapper;
import com.google.crypto.tink.hybrid.HybridEncryptWrapper;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * SM2 公钥加密使用示例：先用 {@link CreateSM2Keysets} 生成密钥集文件，再运行本类。
 *
 * <p>演示两种加密实现（均为 Tink {@link HybridEncrypt}/{@link HybridDecrypt} 原语）：
 * <ul>
 *   <li>标准 SM2 加密（{@code sm2_encryption_*.json}）：密文为 GB/T 32918.4 的 C1C3C2 格式，
 *       RAW 变体可与其他国密实现互操作；不支持 contextInfo（非空即报错）。</li>
 *   <li>SM2-KEM + SM4-GCM 混合（{@code sm2_hybrid_*.json}）：contextInfo 作为 SM4-GCM 关联数据
 *       被完整认证，解密时必须使用相同的 contextInfo。</li>
 * </ul>
 */
public class UseSM2Encryption {

    private static final byte[] PLAIN_TEXT =
            "SM2 椭圆曲线公钥密码算法中公钥加密算法见 GB/T 32918.4-2016，密钥协商见 GB/T 32918.3。"
                    .getBytes(StandardCharsets.UTF_8);
    private static final byte[] CONTEXT_INFO = "recipient@example.org".getBytes(StandardCharsets.UTF_8);

    private static HybridEncrypt standardEncryptor;
    private static HybridDecrypt standardDecryptor;
    private static HybridEncrypt hybridEncryptor;
    private static HybridDecrypt hybridDecryptor;

    @BeforeClass
    public static void setUp() throws IOException, GeneralSecurityException {
        HybridEncryptWrapper.register();
        HybridDecryptWrapper.register();
        Sm2EncryptionKeyManager.registerPair(false);
        Sm2HybridKeyManager.registerPair(false);

        try (InputStream ins = new FileInputStream("sm2_encryption_public_keyset.json")) {
            KeysetHandle publicHandle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(ins));
            standardEncryptor = publicHandle.getPrimitive(RegistryConfiguration.get(), HybridEncrypt.class);
        }
        try (InputStream ins = new FileInputStream("sm2_encryption_keyset.json")) {
            KeysetHandle privateHandle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(ins));
            standardDecryptor = privateHandle.getPrimitive(RegistryConfiguration.get(), HybridDecrypt.class);
        }
        try (InputStream ins = new FileInputStream("sm2_hybrid_public_keyset.json")) {
            KeysetHandle publicHandle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(ins));
            hybridEncryptor = publicHandle.getPrimitive(RegistryConfiguration.get(), HybridEncrypt.class);
        }
        try (InputStream ins = new FileInputStream("sm2_hybrid_keyset.json")) {
            KeysetHandle privateHandle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(ins));
            hybridDecryptor = privateHandle.getPrimitive(RegistryConfiguration.get(), HybridDecrypt.class);
        }
    }

    @Test
    public void standardSm2RoundTrip() throws GeneralSecurityException {
        // 标准 SM2 密文不支持关联数据，contextInfo 必须为空
        byte[] ciphertext = standardEncryptor.encrypt(PLAIN_TEXT, null);
        assertArrayEquals(PLAIN_TEXT, standardDecryptor.decrypt(ciphertext, null));
        // 每次加密的密文应当不同（随机临时密钥）
        assertFalse(Arrays.equals(ciphertext, standardEncryptor.encrypt(PLAIN_TEXT, null)));
    }

    @Test
    public void hybridRoundTripWithContextInfo() throws GeneralSecurityException {
        byte[] ciphertext = hybridEncryptor.encrypt(PLAIN_TEXT, CONTEXT_INFO);
        assertArrayEquals(PLAIN_TEXT, hybridDecryptor.decrypt(ciphertext, CONTEXT_INFO));
        // contextInfo 被认证：换一个 context 解密必须失败
        try {
            hybridDecryptor.decrypt(ciphertext, "someone-else".getBytes(StandardCharsets.UTF_8));
            throw new AssertionError("decryption with a different contextInfo must fail");
        } catch (GeneralSecurityException expected) {
            // 预期行为。
        }
    }
}
