package cc.ddrpa.interop.bc;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * 对方侧参考实现的独立演示：仅依赖 BouncyCastle + JDK，可在仓库外单独运行，用于验证拷贝到对方
 * 工程后各算法可正常工作。内置固定测试密钥（与 {@code InteropFixtures} 一致），输出各算法密文/
 * 签名的 hex 与自检结果。
 *
 * <p>运行：{@code java -cp .:bcprov-jdk18on-<version>.jar cc.ddrpa.interop.bc.BcInteropDemo}
 *
 * <p>注意：密文与签名每次运行都不同（随机 nonce/k），所以只需确认输出均为 PASS 且能自行往返。
 */
public final class BcInteropDemo {

    private static int failures = 0;

    private BcInteropDemo() {
    }

    private static final byte[] SM4_KEY =
        HexUtil.decode("000102030405060708090a0b0c0d0e0f");
    private static final byte[] D =
        HexUtil.decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    private static final byte[] Q = HexUtil.decode(
        "46d1086f6e5c938447f05280db707c279a7b459c38f19e4d9a30ad2dadf9f28a"
            + "f45fc1dc5b377736b57e97e7e0563ccca24c97f440e1d137e5941d84d2eb43c9");

    public static void main(String[] args) throws Exception {
        byte[] aad = "recipient@example.org".getBytes(StandardCharsets.US_ASCII);
        byte[] message =
            "跨系统互操作演示消息 0123456789".getBytes(StandardCharsets.UTF_8);

        // 1. SM4-GCM（线格式：IV(12) ‖ 密文 ‖ tag(16)）
        byte[] sm4Ciphertext = Sm4GcmAead.encrypt(SM4_KEY, message, aad);
        check("SM4-GCM 往返", Arrays.equals(
            message, Sm4GcmAead.decrypt(SM4_KEY, sm4Ciphertext, aad)));
        System.out.println("SM4-GCM 密文(hex): " + HexUtil.encode(sm4Ciphertext));

        // 2. SM2 签名（64 字节 r‖s）
        byte[] signature = Sm2Signature.sign(D, message);
        check("SM2 签名/验签", Sm2Signature.verify(Q, signature, message));
        System.out.println("SM2 签名(hex): " + HexUtil.encode(signature));

        // 3. 标准 SM2 加密（C1C3C2）
        byte[] sm2Ciphertext = Sm2StandardEncryption.encrypt(Q, message);
        check("标准 SM2 往返", Arrays.equals(
            message, Sm2StandardEncryption.decrypt(D, sm2Ciphertext)));
        System.out.println("标准 SM2 密文(hex): " + HexUtil.encode(sm2Ciphertext));

        // 4. SM2-KEM + SM4-GCM 混合（本库自定义格式）
        byte[] context = "request-2026-0001".getBytes(StandardCharsets.US_ASCII);
        byte[] hybridCiphertext = Sm2KemSm4GcmHybrid.encrypt(Q, message, context);
        check("SM2 混合往返", Arrays.equals(
            message, Sm2KemSm4GcmHybrid.decrypt(D, hybridCiphertext, context)));
        System.out.println("SM2 混合密文(hex): " + HexUtil.encode(hybridCiphertext));

        // 5. SM4-GCM-HKDF 流式（4KB 密文段；本库自定义线格式）
        byte[] bigData = new byte[10000];
        new java.util.Random(1).nextBytes(bigData);
        byte[] streamCiphertext =
            Sm4GcmHkdfStreamingAead.encryptBytes(SM4_KEY, 4096, aad, bigData);
        byte[] streamPlaintext =
            Sm4GcmHkdfStreamingAead.decryptBytes(SM4_KEY, 4096, aad, streamCiphertext);
        check("流式 4KB 段往返（10000 字节）",
            Arrays.equals(bigData, streamPlaintext)
                && streamCiphertext.length == Sm4GcmHkdfStreamingAead.ciphertextSize(
                    bigData.length, 4096));

        System.out.println();
        if (failures == 0) {
            System.out.println("ALL OK：对方侧参考实现自检通过。");
        } else {
            System.out.println("FAILURES=" + failures);
            System.exit(1);
        }
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "PASS  " : "FAIL  ") + what);
        if (!ok) {
            failures++;
        }
    }
}
