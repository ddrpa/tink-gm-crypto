package cc.ddrpa.playground;

import cc.ddrpa.crypto.tink.signature.Sm2SignKeyManager;
import com.google.crypto.tink.*;
import com.google.crypto.tink.signature.SignatureConfig;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import static org.junit.Assert.assertTrue;

/**
 * SM2 数字签名使用示例：先用 {@link CreateSM2Keysets} 生成密钥集文件，再运行本类。
 *
 * <p>私钥持有方加载 {@code sm2_signature_keyset.json} 进行签名；验证方只需公钥密钥集
 * {@code sm2_signature_public_keyset.json}。
 */
public class UseSM2Signature {

    private static final byte[] MESSAGE =
            "SM2 椭圆曲线公钥密码算法基于 256 位椭圆曲线，数字签名算法见 GB/T 32918.2-2016。"
                    .getBytes(StandardCharsets.UTF_8);

    private static PublicKeySign signer;
    private static PublicKeyVerify verifier;

    @BeforeClass
    public static void setUp() throws IOException, GeneralSecurityException {
        // SignatureConfig.register() 会注册 Tink 自带的签名 wrapper 与算法；
        // 若只想使用 SM2，也可改用 PublicKeySignWrapper.register() 后注册 Sm2SignKeyManager。
        SignatureConfig.register();
        Sm2SignKeyManager.registerPair(false);
        try (InputStream ins = new FileInputStream("sm2_signature_keyset.json")) {
            KeysetHandle privateHandle = CleartextKeysetHandle.read(
                    JsonKeysetReader.withInputStream(ins));
            signer = privateHandle.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
        }
        try (InputStream ins = new FileInputStream("sm2_signature_public_keyset.json")) {
            KeysetHandle publicHandle = CleartextKeysetHandle.read(
                    JsonKeysetReader.withInputStream(ins));
            verifier = publicHandle.getPrimitive(RegistryConfiguration.get(), PublicKeyVerify.class);
        }
    }

    @Test
    public void signAndVerify() throws GeneralSecurityException {
        byte[] signature = signer.sign(MESSAGE);
        // TINK 前缀的密钥生成的签名以 0x01 || keyId 开头
        assertTrue(signature.length > 64);
        verifier.verify(signature, MESSAGE);
    }

    @Test
    public void verifyRejectsTamperedData() throws GeneralSecurityException {
        byte[] signature = signer.sign(MESSAGE);
        byte[] tampered = MESSAGE.clone();
        tampered[0] ^= 1;
        try {
            verifier.verify(signature, tampered);
            throw new AssertionError("tampered message must not verify");
        } catch (GeneralSecurityException expected) {
            // 验签失败按 Tink PublicKeyVerify 约定抛出 GeneralSecurityException。
        }
    }
}
