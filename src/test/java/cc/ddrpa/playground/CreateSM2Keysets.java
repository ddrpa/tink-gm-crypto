package cc.ddrpa.playground;

import cc.ddrpa.crypto.tink.hybrid.Sm2EncryptionKeyManager;
import cc.ddrpa.crypto.tink.hybrid.Sm2HybridKeyManager;
import cc.ddrpa.crypto.tink.signature.Sm2SignKeyManager;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;

/**
 * 本程序演示如何创建 SM2 相关密钥集（JSON 格式）。
 *
 * <p>创建三种密钥集，每种都写出私钥密钥集与可分发他人的公钥密钥集：
 * <ul>
 *   <li>SM2 数字签名（{@code SM2_SIGN}，TINK 前缀）</li>
 *   <li>标准 SM2 公钥加密（{@code SM2_ENCRYPTION}，密文为国标 C1C3C2 格式）</li>
 *   <li>SM2-KEM + SM4-GCM 混合加密（{@code SM2_HYBRID}，contextInfo 作为关联数据）</li>
 * </ul>
 *
 * <p>通常来说你应当通过 KMS 管理密钥而不是使用明文密钥集。
 */
public class CreateSM2Keysets {

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        // 注册 SM2 各实现（用于按具名参数生成密钥）
        Sm2SignKeyManager.registerPair(true);
        Sm2EncryptionKeyManager.registerPair(true);
        Sm2HybridKeyManager.registerPair(true);

        signatureKeysets();
        encryptionKeysets();
        hybridKeysets();
    }

    private static void signatureKeysets() throws GeneralSecurityException, IOException {
        KeysetHandle privateHandle =
            KeysetHandle.newBuilder()
                .addEntry(
                    KeysetHandle.generateEntryFromParametersName("SM2_SIGN")
                        .makePrimary()
                        .withRandomId())
                .build();
        write(privateHandle, "sm2_signature_keyset.json");
        write(privateHandle.getPublicKeysetHandle(), "sm2_signature_public_keyset.json");
    }

    private static void encryptionKeysets() throws GeneralSecurityException, IOException {
        KeysetHandle privateHandle =
            KeysetHandle.newBuilder()
                .addEntry(
                    KeysetHandle.generateEntryFromParametersName("SM2_ENCRYPTION")
                        .makePrimary()
                        .withRandomId())
                .build();
        write(privateHandle, "sm2_encryption_keyset.json");
        write(privateHandle.getPublicKeysetHandle(), "sm2_encryption_public_keyset.json");
    }

    private static void hybridKeysets() throws GeneralSecurityException, IOException {
        KeysetHandle privateHandle =
            KeysetHandle.newBuilder()
                .addEntry(
                    KeysetHandle.generateEntryFromParametersName("SM2_HYBRID")
                        .makePrimary()
                        .withRandomId())
                .build();
        write(privateHandle, "sm2_hybrid_keyset.json");
        write(privateHandle.getPublicKeysetHandle(), "sm2_hybrid_public_keyset.json");
    }

    private static void write(KeysetHandle handle, String fileName)
        throws GeneralSecurityException, IOException {
        try (OutputStream os = Files.newOutputStream(Paths.get(fileName))) {
            CleartextKeysetHandle.write(handle, JsonKeysetWriter.withOutputStream(os));
        }
    }
}
