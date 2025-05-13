package cc.ddrpa.playground;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import cc.ddrpa.crypto.tink.aead.Sm4GcmKey;
import cc.ddrpa.crypto.tink.aead.Sm4GcmKeyManager;
import cc.ddrpa.crypto.tink.aead.Sm4GcmParameters;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.util.SecretBytes;
import org.junit.BeforeClass;
import org.junit.Test;

public class Sm4GcmKeyTrackingTest {

    @BeforeClass
    public static void setUp() throws Exception {
        // 注册 SM4-GCM 密钥管理器
        Sm4GcmKeyManager.register(true);
        // 注册 AEAD 配置
        AeadConfig.register();
    }

    @Test
    void testKeyTracking() throws Exception {
        // 1. 创建两个密钥，使用不同的密钥ID
        // 密钥1
        Sm4GcmParameters key1Params = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.TINK)
            .build();
        Sm4GcmKey key1 = Sm4GcmKey.builder()
            .setParameters(key1Params)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(1001)  // 密钥ID: 1001
            .build();

        // 密钥2
        Sm4GcmParameters key2Params = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.TINK)
            .build();
        Sm4GcmKey key2 = Sm4GcmKey.builder()
            .setParameters(key2Params)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(1002)  // 密钥ID: 1002
            .build();

        // 2. 创建 KeysetHandle，设置密钥1为主密钥
        KeysetHandle handle = KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key1).makePrimary().withFixedId(1001))
            .addEntry(KeysetHandle.importKey(key2).withFixedId(1002))
            .build();

        // 3. 获取 AEAD 实例
        Aead aead = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);

        // 4. 加密数据
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] associatedData = "metadata".getBytes();
        byte[] ciphertext = aead.encrypt(plaintext, associatedData);

        // 5. 从密文中提取密钥ID
        int keyId = extractKeyIdFromCiphertext(ciphertext);
        System.out.println("使用的密钥ID: " + keyId);

        // 6. 验证使用的密钥
        assertEquals(1001, keyId);  // 应该使用主密钥(1001)

        // 7. 解密数据
        byte[] decrypted = aead.decrypt(ciphertext, associatedData);
        assertNotNull(decrypted);
    }

    @Test
    void testKeyRotation() throws Exception {
        // 1. 创建两个密钥
        // 旧密钥
        Sm4GcmParameters oldKeyParams = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.TINK)
            .build();
        Sm4GcmKey oldKey = Sm4GcmKey.builder()
            .setParameters(oldKeyParams)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(2001)
            .build();

        // 新密钥
        Sm4GcmParameters newKeyParams = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.TINK)
            .build();
        Sm4GcmKey newKey = Sm4GcmKey.builder()
            .setParameters(newKeyParams)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(2002)
            .build();

        // 2. 创建 KeysetHandle，设置旧密钥为主密钥
        KeysetHandle handle = KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(oldKey).makePrimary().withFixedId(2001))
            .addEntry(KeysetHandle.importKey(newKey).withFixedId(2002))
            .build();

        // 3. 获取 AEAD 实例并加密数据
        Aead aead = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] associatedData = "metadata".getBytes();
        byte[] ciphertext = aead.encrypt(plaintext, associatedData);

        // 4. 验证使用旧密钥加密
        int keyId = extractKeyIdFromCiphertext(ciphertext);
        assertEquals(2001, keyId);

        // 5. 轮换密钥（将新密钥设为主密钥）
        handle = KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(newKey).makePrimary().withFixedId(2002))
            .addEntry(KeysetHandle.importKey(oldKey).withFixedId(2001))
            .build();

        // 6. 获取新的 AEAD 实例并加密新数据
        aead = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
        byte[] newCiphertext = aead.encrypt(plaintext, associatedData);

        // 7. 验证使用新密钥加密
        keyId = extractKeyIdFromCiphertext(newCiphertext);
        assertEquals(2002, keyId);

        // 8. 验证两个密文都可以解密
        byte[] decrypted1 = aead.decrypt(ciphertext, associatedData);
        byte[] decrypted2 = aead.decrypt(newCiphertext, associatedData);
        assertNotNull(decrypted1);
        assertNotNull(decrypted2);
    }

    // 从 TINK 格式的密文中提取密钥ID
    private int extractKeyIdFromCiphertext(byte[] ciphertext) {
        // TINK 格式: 0x01 + 4字节密钥ID
        if (ciphertext.length < 5 || ciphertext[0] != 0x01) {
            throw new IllegalArgumentException("Invalid TINK format ciphertext");
        }
        return ((ciphertext[1] & 0xFF) << 24) |
            ((ciphertext[2] & 0xFF) << 16) |
            ((ciphertext[3] & 0xFF) << 8) |
            (ciphertext[4] & 0xFF);
    }
}
