package cc.ddrpa.interop.bc;

/**
 * 对方侧（不使用 Google Tink）参考实现共用的十六进制编解码工具。
 *
 * <p>本包（{@code cc.ddrpa.interop.bc}）内的所有类只依赖 JDK 与
 * {@code org.bouncycastle:bcprov-jdk18on}，不依赖 Google Tink，可整体拷贝到对方工程使用。
 * 本类仅提供大端无符号十六进制与字节数组的互转，无其他依赖。
 */
public final class HexUtil {

    private HexUtil() {
    }

    /**
     * @return {@code hex} 对应的字节数组；每两个十六进制字符一组按大端解析
     * @throws IllegalArgumentException 长度为奇数或包含非十六进制字符时抛出
     */
    public static byte[] decode(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex must not be null");
        }
        String h = hex.trim();
        if ((h.length() & 1) != 0) {
            throw new IllegalArgumentException("hex length must be even: " + hex);
        }
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(h.charAt(2 * i), 16);
            int lo = Character.digit(h.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("invalid hex character in: " + hex);
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /**
     * @return {@code bytes} 的小写十六进制表示
     */
    public static String encode(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16));
            sb.append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }
}
