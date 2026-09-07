package cc.ddrpa.interop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cc.ddrpa.crypto.tink.signature.Sm2SignKeyManager;
import cc.ddrpa.interop.bc.Sm2Signature;
import cc.ddrpa.interop.testing.InteropFixtures;
import cc.ddrpa.interop.testing.InteropTink;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.SignatureConfig;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * SM2 数字签名的跨系统互操作自检：Tink 侧 ⇄ 对方侧（纯 BouncyCastle，{@code cc.ddrpa.interop.bc.Sm2Signature}）。
 *
 * <p>RAW 输出：64 字节 {@code r ‖ s}（非 DER）；曲线 sm2p256v1；用户标识为默认值
 * {@code 1234567812345678}；对原始消息内部完成 ZA + SM3。
 */
class Sm2SignatureInteropTest {

    private static final byte[] D = InteropTink.fixtureD();
    private static final byte[] Q = InteropTink.fixtureQ();
    private static final byte[] MESSAGE = InteropFixtures.SAMPLE_MESSAGE;
    private static final int FIXED_KEY_ID = 0x0badf00d;

    @BeforeAll
    static void setUp() throws Exception {
        SignatureConfig.register();
        Sm2SignKeyManager.registerPair(true);
    }

    // 方向一：Tink 签名 → 对方 BC 验签。
    @Test
    void tinkSignsBcVerifies() throws Exception {
        PublicKeySign signer = InteropTink.newRawSm2Signer();
        byte[] signature = signer.sign(MESSAGE);
        assertEquals(64, signature.length); // RAW：无前缀，纯 64 字节 r‖s
        assertTrue(Sm2Signature.verify(Q, signature, MESSAGE));
        assertFalse(Sm2Signature.verify(Q, signature, "篡改消息".getBytes()));
    }

    // 方向二：对方 BC 签名 → Tink 验签。
    @Test
    void bcSignsTinkVerifies() throws Exception {
        PublicKeyVerify verifier = InteropTink.newRawSm2Verifier();
        byte[] bcSignature = Sm2Signature.sign(D, MESSAGE);
        assertEquals(64, bcSignature.length);
        verifier.verify(bcSignature, MESSAGE);
        // Tink 对错误签名同样拒绝。
        byte[] tampered = Arrays.copyOf(bcSignature, bcSignature.length);
        tampered[0] ^= 1;
        byte[] finalTampered = tampered;
        assertThrows(Exception.class, () -> verifier.verify(finalTampered, MESSAGE));
    }

    @Test
    void emptyMessageCanBeSignedAndVerified() throws Exception {
        PublicKeySign signer = InteropTink.newRawSm2Signer();
        byte[] signature = signer.sign(new byte[0]);
        assertTrue(Sm2Signature.verify(Q, signature, new byte[0]));
    }

    // TINK 前缀签名：对方需要剥离 0x01 ‖ keyId 再验签。
    @Test
    void tinkPrefixedSignatureStrippedBeforeBcVerify() throws Exception {
        PublicKeySign signer = InteropTink.newTinkSm2Signer(FIXED_KEY_ID);
        byte[] signature = signer.sign(MESSAGE);
        assertEquals(64 + 5, signature.length);

        assertEquals(0x01, signature[0] & 0xff);
        int keyId = readKeyId(signature);
        assertEquals(FIXED_KEY_ID, keyId);
        byte[] rawSignature = Arrays.copyOfRange(signature, 5, signature.length);
        assertTrue(Sm2Signature.verify(Q, rawSignature, MESSAGE));
    }

    private static int readKeyId(byte[] prefixed) {
        return ((prefixed[1] & 0xff) << 24)
            | ((prefixed[2] & 0xff) << 16)
            | ((prefixed[3] & 0xff) << 8)
            | (prefixed[4] & 0xff);
    }
}
