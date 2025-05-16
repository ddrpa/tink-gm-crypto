package cc.ddrpa.playground;

import cc.ddrpa.crypto.tink.aead.Sm4GcmKey;
import cc.ddrpa.crypto.tink.aead.Sm4GcmKeyManager;
import cc.ddrpa.crypto.tink.aead.Sm4GcmParameters;
import cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKeyManager;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import com.google.crypto.tink.util.SecretBytes;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * 本程序演示如何创建 JSON 格式的 AEAD 和 Streaming AEAD 密钥集
 * <p>
 * 通常来说你应当通过 KMS 管理密钥而不是使用明文密钥集
 */
public class CreateClearTextKeyset {

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        aead();
        streamAead();
    }

    public static void aead() throws GeneralSecurityException, IOException {
        // 0. 随机数生成器，用于在创建密钥时分配 key ID，也可以使用其他方法，如序列递增
        // NO_PREFIX 变体因为没有前缀，在生成时不需要指定 ID
        SecureRandom random = new SecureRandom();

        // 1. 注册 AEAD 基元和 SM4-GCM 实现
        AeadConfig.register();
        Sm4GcmKeyManager.register(true);

        // 2. 创建多个密钥
        // 主密钥
        Sm4GcmParameters primaryParams = Sm4GcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(Sm4GcmParameters.Variant.TINK)
            .build();
        Sm4GcmKey primaryKey = Sm4GcmKey.builder()
            .setParameters(primaryParams)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(random.nextInt())
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
            .setIdRequirement(random.nextInt())
            .build();

        // 备用密钥 2
        // 你也可以使用具名参数创建密钥，不过注意在写入密钥集时分配 ID
        KeysetHandle.Builder.Entry entryBackup2 = KeysetHandle.generateEntryFromParametersName(
            "SM4_GCM");

        // 3. 创建 KeysetHandle 并添加所有密钥
        KeysetHandle handle = KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(primaryKey).makePrimary())
            .addEntry(KeysetHandle.importKey(backup1Key))
            .addEntry(entryBackup2.withRandomId())
            .build();

        // 4. 将密钥集序列化为 JSON 并输出
        try (OutputStream os = new FileOutputStream("aead_keyset.json")) {
            CleartextKeysetHandle.write(handle, JsonKeysetWriter.withOutputStream(os));
        }
    }

    private static void streamAead() throws GeneralSecurityException, IOException {
        // 1. 注册 Streaming AEAD 基元和 SM4-GCM-HKDF 实现
        StreamingAeadConfig.register();
        Sm4GcmHkdfStreamingKeyManager.register(true);

        // 2. 使用具名参数创建密钥
        KeysetHandle.Builder.Entry entry1 = KeysetHandle.generateEntryFromParametersName(
            "SM4_GCM_HKDF_1MB");
        KeysetHandle.Builder.Entry entry2 = KeysetHandle.generateEntryFromParametersName(
            "SM4_GCM_HKDF_4KB");

        // 3. 保存到密钥集
        KeysetHandle handle = KeysetHandle.newBuilder()
            .addEntry(entry1.makePrimary().withRandomId())
            .addEntry(entry2.withRandomId())
            .build();

        // 4. 序列化为 JSON 输出
        try (OutputStream os = new FileOutputStream("streaming_aead_keyset.json")) {
            CleartextKeysetHandle.write(handle, JsonKeysetWriter.withOutputStream(os));
        }
    }
}