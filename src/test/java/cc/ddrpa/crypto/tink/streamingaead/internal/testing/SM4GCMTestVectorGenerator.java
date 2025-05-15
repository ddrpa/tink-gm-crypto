package cc.ddrpa.crypto.tink.streamingaead.internal.testing;

import com.google.crypto.tink.subtle.Hex;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SM4GCMTestVectorGenerator {

    public static void main(String[] args) throws Exception {
        // 添加 BouncyCastle 提供者
        Security.addProvider(new BouncyCastleProvider());

        // 密钥
        byte[] key = Hex.decode("6eb56cdc726dfbe5d57f2fcdc6e9345b");
        // 盐值
        byte[] salt = Hex.decode("93b3af5e14ab378d065addfc8484da64");
        // 随机数前缀
        byte[] noncePrefix = Hex.decode("2c0862877baea8");
        // 明文
        byte[] plaintext = "This is a fairly long plaintext. It is of the exact length to create three output blocks. ".getBytes(
            StandardCharsets.UTF_8);
        // 关联数据
        byte[] aad = "aad".getBytes(StandardCharsets.UTF_8);

        int ciphertextSegmentSize = 64;  // 总段大小
        int headerLength = 24;

        // 使用 HKDF 派生密钥
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA1Digest());
        HKDFParameters hkdfParameters = new HKDFParameters(key, salt, aad);
        hkdf.init(hkdfParameters);
        byte[] derivedKey = new byte[16];
        hkdf.generateBytes(derivedKey, 0, 16);

        byte[] header = new byte[headerLength];
        header[0] = (byte) headerLength;  // 头部长度
        System.arraycopy(salt, 0, header, 1, 16);  // 盐值
        System.arraycopy(noncePrefix, 0, header, 17, 7);  // 随机数前缀

        System.out.println("Header: " + Hex.encode(header));

        if (plaintext.length == 0) {
            // 如果明文为空，添加一个空的段
            byte[] emptySegment = encryptSegment(derivedKey, noncePrefix, aad, plaintext, 0, 0, 0,
                true);
            System.out.println(Hex.encode(emptySegment));
        } else {
            int segmentNr = 0;
            int offset = 0;
            int plaintextSegmentSize;
            List<byte[]> segments = new ArrayList<>();

            while (offset < plaintext.length) {
                if (segmentNr == 0) {
                    // 第一个段的大小
                    plaintextSegmentSize = ciphertextSegmentSize - headerLength - 16;
                } else {
                    // 其他段的大小
                    plaintextSegmentSize = ciphertextSegmentSize - 16;
                }
                int len = Math.min(plaintextSegmentSize, plaintext.length - offset);
                boolean isLast = (offset + len == plaintext.length);
                byte[] segment = encryptSegment(derivedKey, noncePrefix, aad, plaintext, offset,
                    len,
                    segmentNr, isLast);
                segments.add(segment);
                offset += len;
                segmentNr++;
                System.out.println(Hex.encode(segment));
            }
        }
    }

    private static byte[] encryptSegment(byte[] key, byte[] noncePrefix, byte[] aad,
        byte[] plaintext, int offset, int length, int segmentNr, boolean isLastSegment)
        throws Exception {
        // 创建段特定的 nonce
        byte[] segmentNonce = new byte[12];  // 固定为12字节
        System.arraycopy(noncePrefix, 0, segmentNonce, 0, noncePrefix.length);  // 7字节

        // 添加段号(4字节)
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putInt(segmentNr);
        System.arraycopy(buffer.array(), 0, segmentNonce, noncePrefix.length, 4);

        // 添加last_block标志(1字节)
        segmentNonce[11] = (byte) (isLastSegment ? 1 : 0);

        // 创建 SM4-GCM 加密器
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", "BC");
        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");
        GCMParameterSpec spec = new GCMParameterSpec(128, segmentNonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);

        byte[] segmentPlaintext = new byte[length];
        System.arraycopy(plaintext, offset, segmentPlaintext, 0, length);

        return cipher.doFinal(segmentPlaintext);
    }
}
