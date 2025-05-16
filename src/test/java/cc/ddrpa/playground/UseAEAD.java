package cc.ddrpa.playground;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

import cc.ddrpa.crypto.tink.aead.Sm4GcmKeyManager;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;

public class UseAEAD {

    private static final byte[] PLAIN_TEXT = "SM4 密码算法是一个分组算法。该算法的分组长度为 128 比特,密钥长度为 128 比特。加密算法与密钥扩展算法均采用非线性迭代结构，运算轮数均为 32 轮。数据解密和数据加密的算法结构相同，只是轮密钥的使用顺序相反,解密轮密钥是加密轮密钥的逆序。".getBytes(
        StandardCharsets.UTF_8);
    private static Aead aead;

    @BeforeClass
    public static void setUp() throws IOException, GeneralSecurityException {
        // 注册 AEAD 基元和 SM4-GCM 实现
        AeadConfig.register();
        Sm4GcmKeyManager.register(false);
        // 加载密钥集
        try (InputStream ins = new FileInputStream("aead_keyset.json")) {
            KeysetHandle keysetHandle = CleartextKeysetHandle.read(
                JsonKeysetReader.withInputStream(ins));
            aead = keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
        }
    }

    @Test
    public void encryptAndDecryptTextWithAEAD() throws Exception {
        byte[] associatedData = LocalDateTime.now().toString().getBytes();
        byte[] ciphertext1 = aead.encrypt(PLAIN_TEXT, associatedData);
        byte[] ciphertext2 = aead.encrypt(PLAIN_TEXT, associatedData);

        // 每次加密产生的密文应当不同
        assertFalse(Arrays.equals(ciphertext1, ciphertext2));

        // 解密
        byte[] decrypted = aead.decrypt(ciphertext1, associatedData);
        assertArrayEquals(PLAIN_TEXT, decrypted);
    }
}
