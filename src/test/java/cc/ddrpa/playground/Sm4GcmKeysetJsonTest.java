package cc.ddrpa.playground;

import static org.junit.Assert.assertArrayEquals;

import cc.ddrpa.crypto.tink.aead.Sm4GcmKey;
import cc.ddrpa.crypto.tink.aead.Sm4GcmKeyManager;
import cc.ddrpa.crypto.tink.aead.Sm4GcmParameters;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.junit.BeforeClass;
import org.junit.Test;

public class Sm4GcmKeysetJsonTest {

    @BeforeClass
    public static void setUp() throws Exception {
        // 注册 SM4-GCM 密钥管理器
        Sm4GcmKeyManager.register(true);
        // 注册 AEAD 配置
        AeadConfig.register();
    }

    @Test
    public void testMultipleKeysJson() throws Exception {
        // 1. 创建多个密钥
        // 主密钥
        Sm4GcmParameters primaryParams = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.TINK)
            .build();
        Sm4GcmKey primaryKey = Sm4GcmKey.builder()
            .setParameters(primaryParams)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(123)
            .build();

        // 备用密钥 1
        Sm4GcmParameters backup1Params = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.TINK)
            .build();
        Sm4GcmKey backup1Key = Sm4GcmKey.builder()
            .setParameters(backup1Params)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(456)
            .build();

        // 备用密钥 2
        Sm4GcmParameters backup2Params = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.TINK)
            .build();
        Sm4GcmKey backup2Key = Sm4GcmKey.builder()
            .setParameters(backup2Params)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(789)
            .build();

        // 2. 创建 KeysetHandle 并添加所有密钥
        KeysetHandle handle = KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(primaryKey).makePrimary().withFixedId(123))
            .addEntry(KeysetHandle.importKey(backup1Key).withFixedId(456))
            .addEntry(KeysetHandle.importKey(backup2Key).withFixedId(789))
            .build();

        // 3. 将密钥集序列化为 JSON
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CleartextKeysetHandle.write(handle, JsonKeysetWriter.withOutputStream(outputStream));
        String jsonKeyset = outputStream.toString();
        System.out.println("JSON Keyset:");
        System.out.println(jsonKeyset);

        // 4. 从 JSON 反序列化密钥集
        ByteArrayInputStream inputStream = new ByteArrayInputStream(jsonKeyset.getBytes());
        KeysetHandle restoredHandle = CleartextKeysetHandle.read(
            JsonKeysetReader.withInputStream(inputStream));

        // 5. 验证密钥集
        Aead aead = restoredHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
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
    public void testKeysetWithDifferentVariants() throws Exception {
        // 1. 创建不同变体的密钥
        // TINK 变体
        Sm4GcmParameters tinkParams = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.TINK)
            .build();
        Sm4GcmKey tinkKey = Sm4GcmKey.builder()
            .setParameters(tinkParams)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(111)
            .build();

        // NO_PREFIX 变体
        Sm4GcmParameters noPrefixParams = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.NO_PREFIX)
            .build();
        Sm4GcmKey noPrefixKey = Sm4GcmKey.builder()
            .setParameters(noPrefixParams)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();

        // 2. 创建 KeysetHandle
        KeysetHandle handle = KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkKey).makePrimary().withFixedId(111))
            .addEntry(KeysetHandle.importKey(noPrefixKey))
            .build();

        // 3. 序列化为 JSON
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CleartextKeysetHandle.write(handle, JsonKeysetWriter.withOutputStream(outputStream));
        String jsonKeyset = outputStream.toString();
        System.out.println("JSON Keyset with different variants:");
        System.out.println(jsonKeyset);

        // 4. 验证密钥集
        Aead aead = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] associatedData = "metadata".getBytes();

        // 加密
        byte[] ciphertext = aead.encrypt(plaintext, associatedData);

        // 解密
        byte[] decrypted = aead.decrypt(ciphertext, associatedData);

        // 验证
        assertArrayEquals(plaintext, decrypted);
    }
}
