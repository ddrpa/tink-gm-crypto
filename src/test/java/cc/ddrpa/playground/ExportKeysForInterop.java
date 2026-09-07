package cc.ddrpa.playground;

import cc.ddrpa.crypto.tink.aead.Sm4GcmKey;
import cc.ddrpa.crypto.tink.hybrid.Sm2EncryptionPrivateKey;
import cc.ddrpa.crypto.tink.hybrid.Sm2EncryptionPublicKey;
import cc.ddrpa.crypto.tink.hybrid.Sm2HybridPrivateKey;
import cc.ddrpa.crypto.tink.hybrid.Sm2HybridPublicKey;
import cc.ddrpa.crypto.tink.signature.Sm2SignaturePrivateKey;
import cc.ddrpa.crypto.tink.signature.Sm2SignaturePublicKey;
import cc.ddrpa.crypto.tink.streamingaead.Sm4GcmHkdfStreamingKey;
import com.google.crypto.tink.*;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * 演示如何把本库的明文 JSON keyset 转换成<strong>对方系统（不使用 Google Tink）</strong>可用的
 * 裸密钥（hex），用于跨系统互操作。
 *
 * <p>用法：{@code java ... ExportKeysForInterop <keyset.json>}
 *
 * <p>说明：
 * <ul>
 *   <li>跨系统一律建议使用 RAW（NO_PREFIX）变体密钥；若 keyset 中是 TINK 前缀变体，对方收到数据时
 *       需剥离 {@code 0x01 ‖ keyId(4B 大端)} 前缀（打印中会给出每个 key 的 keyId 与前缀 hex）；</li>
 *   <li>SM2 公钥密钥集可直接导出 64 字节 {@code X‖Y} 公钥给对方用于加密/验签；私钥密钥集导出
 *       32 字节 {@code d} 用于解密/签名——请通过安全通道分发，切勿直接发送明文 keyset 文件；</li>
 *   <li>密钥材质各字节均为定长大端无符号整数（坐标/私钥 32 字节，SM4 密钥 16 字节）。</li>
 * </ul>
 */
public class ExportKeysForInterop {

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: ExportKeysForInterop <keyset.json>");
            System.exit(1);
        }
        KeysetHandle handle;
        try (InputStream ins = new FileInputStream(args[0])) {
            handle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(ins));
        }
        System.out.println("# keyset: " + args[0] + " (" + handle.size() + " key(s))");
        for (int i = 0; i < handle.size(); i++) {
            KeysetHandle.Entry entry = handle.getAt(i);
            Key key = entry.getKey();
            System.out.println();
            System.out.println("## key index " + i + ", keyId=0x" + hexInt(entry.getId()));
            System.out.println("   parameters: " + key.getParameters());
            dump(key);
        }
    }

    private static void dump(Key key) throws GeneralSecurityException {
        if (key instanceof Sm4GcmKey) {
            Sm4GcmKey sm4 = (Sm4GcmKey) key;
            System.out.println("   type=SM4-GCM-AEAD");
            System.out.println("   outputPrefix: " + hex(sm4.getOutputPrefix().toByteArray()));
            System.out.println("   sm4Key(16B): " + hex(
                    sm4.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
        } else if (key instanceof Sm4GcmHkdfStreamingKey) {
            Sm4GcmHkdfStreamingKey stream = (Sm4GcmHkdfStreamingKey) key;
            System.out.println("   type=SM4-GCM-HKDF-STREAMING (无前缀)");
            System.out.println("   ikm: " + hex(
                    stream.getInitialKeyMaterial().toByteArray(InsecureSecretKeyAccess.get())));
            System.out.println("   ciphertextSegmentSize: "
                    + stream.getParameters().getCiphertextSegmentSizeBytes());
        } else if (key instanceof Sm2SignaturePrivateKey) {
            Sm2SignaturePrivateKey priv = (Sm2SignaturePrivateKey) key;
            System.out.println("   type=SM2-SIGNATURE (private keyset)");
            System.out.println("   outputPrefix: " + hex(
                    priv.getPublicKey().getOutputPrefix().toByteArray()));
            System.out.println("   d(32B): " + hex(
                    priv.getPrivateValue().toByteArray(InsecureSecretKeyAccess.get())));
            System.out.println("   Q(64B): " + hex(
                    priv.getPublicKey().getPublicKey().toByteArray()));
        } else if (key instanceof Sm2SignaturePublicKey) {
            Sm2SignaturePublicKey pub = (Sm2SignaturePublicKey) key;
            System.out.println("   type=SM2-SIGNATURE (public keyset)");
            System.out.println("   outputPrefix: " + hex(pub.getOutputPrefix().toByteArray()));
            System.out.println("   Q(64B): " + hex(pub.getPublicKey().toByteArray()));
        } else if (key instanceof Sm2EncryptionPrivateKey) {
            Sm2EncryptionPrivateKey priv = (Sm2EncryptionPrivateKey) key;
            System.out.println("   type=SM2-STANDARD-ENCRYPTION (private keyset)");
            System.out.println("   outputPrefix: " + hex(
                    priv.getPublicKey().getOutputPrefix().toByteArray()));
            System.out.println("   d(32B): " + hex(
                    priv.getPrivateValue().toByteArray(InsecureSecretKeyAccess.get())));
            System.out.println("   Q(64B): " + hex(
                    priv.getPublicKey().getPublicKey().toByteArray()));
        } else if (key instanceof Sm2EncryptionPublicKey) {
            Sm2EncryptionPublicKey pub = (Sm2EncryptionPublicKey) key;
            System.out.println("   type=SM2-STANDARD-ENCRYPTION (public keyset)");
            System.out.println("   outputPrefix: " + hex(pub.getOutputPrefix().toByteArray()));
            System.out.println("   Q(64B): " + hex(pub.getPublicKey().toByteArray()));
        } else if (key instanceof Sm2HybridPrivateKey) {
            Sm2HybridPrivateKey priv = (Sm2HybridPrivateKey) key;
            System.out.println("   type=SM2-KEM-SM4-GCM-HYBRID (private keyset)");
            System.out.println("   outputPrefix: " + hex(
                    priv.getPublicKey().getOutputPrefix().toByteArray()));
            System.out.println("   d(32B): " + hex(
                    priv.getPrivateValue().toByteArray(InsecureSecretKeyAccess.get())));
            System.out.println("   Q(64B): " + hex(
                    priv.getPublicKey().getPublicKey().toByteArray()));
        } else if (key instanceof Sm2HybridPublicKey) {
            Sm2HybridPublicKey pub = (Sm2HybridPublicKey) key;
            System.out.println("   type=SM2-KEM-SM4-GCM-HYBRID (public keyset)");
            System.out.println("   outputPrefix: " + hex(pub.getOutputPrefix().toByteArray()));
            System.out.println("   Q(64B): " + hex(pub.getPublicKey().toByteArray()));
        } else {
            System.out.println("   type=" + key.getClass().getSimpleName() + " (未识别的密钥类型)");
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16));
            sb.append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }

    private static String hexInt(int value) {
        return String.format("%08x", value);
    }
}
