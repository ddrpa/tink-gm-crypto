package cc.ddrpa.playground;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import cc.ddrpa.crypto.tink.aead.Sm4GcmKey;
import cc.ddrpa.crypto.tink.aead.Sm4GcmKeyManager;
import cc.ddrpa.crypto.tink.aead.Sm4GcmParameters;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;

public class HowToUseClearTextKeysetTests {

    @BeforeClass
    public static void setUp() throws Exception {
        // 注册 SM4-GCM 密钥管理器
        Sm4GcmKeyManager.register(true);
        // 注册 AEAD 配置
        AeadConfig.register();
    }

    @Test
    void testEncryptDecrypt() throws Exception {
        // 1. 创建密钥参数
        Sm4GcmParameters parameters = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.NO_PREFIX)
            .build();

        // 2. 创建密钥
        Sm4GcmKey key = Sm4GcmKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();

        // 3. 创建 KeysetHandle
        KeysetHandle handle = KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).makePrimary().withRandomId())
            .build();

        // 4. 获取 AEAD 实例
        Aead aead = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);

        // 5. 测试加密和解密
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] associatedData = "metadata".getBytes();

        // 加密
        byte[] ciphertext = aead.encrypt(plaintext, associatedData);

        // 解密
        byte[] decrypted = aead.decrypt(ciphertext, associatedData);

        // 验证
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void testWithTinkPrefix() throws Exception {
        // 1. 创建带 TINK 前缀的参数
        Sm4GcmParameters parameters = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.TINK)
            .build();

        // 2. 创建密钥
        Sm4GcmKey key = Sm4GcmKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(128)
            .build();

        // 3. 创建 KeysetHandle
        KeysetHandle handle = KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).makePrimary().withFixedId(128))
            .build();

        // 4. 获取 AEAD 实例
        Aead aead = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);

        // 5. 测试加密和解密
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] associatedData = "metadata".getBytes();

        // 加密
        byte[] ciphertext = aead.encrypt(plaintext, associatedData);

        // 解密
        byte[] decrypted = aead.decrypt(ciphertext, associatedData);

        // 验证
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void testInvalidDecrypt() throws Exception {
        // 1. 创建密钥参数
        Sm4GcmParameters parameters = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.NO_PREFIX)
            .build();

        // 2. 创建密钥
        Sm4GcmKey key = Sm4GcmKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();

        // 3. 创建 KeysetHandle
        KeysetHandle handle = KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).makePrimary().withRandomId())
            .build();

        // 4. 获取 AEAD 实例
        Aead aead = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);

        // 5. 测试无效解密
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] associatedData = "metadata".getBytes();

        // 加密
        byte[] ciphertext = aead.encrypt(plaintext, associatedData);

        // 修改密文
        ciphertext[0] ^= 1;

        // 验证解密失败
        assertThrows(GeneralSecurityException.class, () -> {
            aead.decrypt(ciphertext, associatedData);
        });
    }
}
