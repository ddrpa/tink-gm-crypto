package cc.ddrpa.interop.testing;

import java.nio.charset.StandardCharsets;

/**
 * 跨系统互操作自检共用的<strong>固定</strong>密钥材料与样本数据。
 *
 * <p>这些常量同时被两处使用：
 * <ul>
 *   <li>Tink 侧测试：用固定密钥构造 RAW 变体 keyset（避免每次随机生成，使双向交叉可复现）；</li>
 *   <li>对方侧（纯 BouncyCastle）测试：直接用固定密钥解密/验签本文件中的历史向量。</li>
 * </ul>
 *
 * <p>历史向量（……_VECTOR……）是固定密钥下由本库 Tink 原语生成的密文/签名快照：对方角色
 * （纯 BouncyCastle，不使用 Tink）的测试独立解密/验签这些值，避免“加密侧与解密侧共享同一处
 * 错误”的对称性缺陷。若算法线格式演进，按 {@code interop/README.md} 的“维护说明”重新生成并
 * 同步替换。
 */
public final class InteropFixtures {

    private InteropFixtures() {
    }

    /** SM4 密钥（16 字节 = 128 位）：0x00 … 0x0f。 */
    public static final String SM4_KEY_HEX = "000102030405060708090a0b0c0d0e0f";

    /** SM2 私钥标量 d（32 字节，位于 [1, n-1]）：0x01 … 0x20。 */
    public static final String SM2_PRIVATE_D_HEX =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    /** SM2 公钥（64 字节 X ‖ Y）= d·G，由上述 d 在 sm2p256v1 上导出。 */
    public static final String SM2_PUBLIC_Q_HEX =
        "46d1086f6e5c938447f05280db707c279a7b459c38f19e4d9a30ad2dadf9f28a"
            + "f45fc1dc5b377736b57e97e7e0563ccca24c97f440e1d137e5941d84d2eb43c9";

    /** SM4-GCM 的关联数据（ASCII）。 */
    public static final byte[] SAMPLE_AAD =
        "recipient@example.org".getBytes(StandardCharsets.US_ASCII);

    /** SM2 混合加密的 contextInfo（ASCII）。 */
    public static final byte[] SAMPLE_CONTEXT_INFO =
        "request-2026-0001".getBytes(StandardCharsets.US_ASCII);

    /** SM2 签名消息（UTF-8）。 */
    public static final byte[] SAMPLE_MESSAGE =
        "SM2 椭圆曲线公钥密码算法（GB/T 32918.2）——跨系统互操作自检消息 0123456789"
            .getBytes(StandardCharsets.UTF_8);

    /** 标准 SM2 加密的较长明文（UTF-8）。 */
    public static final byte[] SAMPLE_PLAINTEXT =
        "跨系统加密互操作消息：SM4-GCM 提供对称加密，SM2 提供公钥加密与数字签名。"
            .getBytes(StandardCharsets.UTF_8);

    // ---------------------------------------------------------------------
    // 历史向量：固定密钥下的输出快照（本库加密原语每次输出不同，故固化为常量，而非在测试运行
    // 时重新生成）。线格式演进时的重新生成方法见 interop/README.md 的“维护说明”。
    // ---------------------------------------------------------------------

    /** SM4-GCM（RAW，密文 = IV ‖ 密文 ‖ tag，130 字节）：Tink 以 {@link #SAMPLE_AAD} 加密 {@link #SAMPLE_PLAINTEXT}。 */
    public static final String SM4_GCM_VECTOR_CIPHERTEXT_HEX =
        "bc62f0274336fd65ff0ea970fdedf5ade54aa43143f478b884f034da3eec5b05"
            + "6a839dc94cb96be5b75f2321c57adaa2f7b32774f433de75ec971dd17657eb9e"
            + "aacdde8c1554d51ad85bfcc7139dc53391073d8f236119db064d8948a8198b4ba"
            + "bbb9f4ed3a58fed52a3a59452e5a69adf9e99b4767575fd1ffac7a63c4e9d48ecfe";

    /** SM2 签名（RAW，64 字节 r‖s）：Tink 用固定 d 对 {@link #SAMPLE_MESSAGE} 的输出。 */
    public static final String SM2_SIGNATURE_VECTOR_HEX =
        "9958bd8bc6ec63c68e7414ffbec49a7806eaa6e48060dc4a72e45077f0948814"
            + "ab2687b93cc73d6067f869e847cd46f386aee2f065ac62b7be964fe5d7983097";

    /** 标准 SM2 加密（RAW，C1C3C2，199 字节）：Tink 用固定公钥加密 {@link #SAMPLE_PLAINTEXT}。 */
    public static final String SM2_STANDARD_ENCRYPTION_VECTOR_CIPHERTEXT_HEX =
        "046dfe4547cff14262aa9bbfa51aeb92e14e6f8eb921986c2b9ddcbeb7634447d5"
            + "eb899b7b59fecfa15c8512eaa9766d077b5f2610c24977263756455ecbc8bc795"
            + "fb879f9922c03f8ca240eb00de2cd20f27f5161d5472f03e90098b928d9c155b8"
            + "bbd3e53d912d9bbd19198d596a7b67b97dc7dca3abe280e52e573d82a274864c2"
            + "1dc1e6a6d0a7f225375caa2c1c0c9c2af18079a9c33092f33f5071f7f93a33bd4"
            + "f12731c6a8eabb80cbecbd31180cb1cfe7c1df2cbdfda6d4fac9ba88a93362ffe68be542";

    /** SM2 混合加密（RAW，C1‖nonce‖SM4-GCM，195 字节）：Tink 以 {@link #SAMPLE_CONTEXT_INFO} 加密 {@link #SAMPLE_PLAINTEXT}。 */
    public static final String SM2_HYBRID_VECTOR_CIPHERTEXT_HEX =
        "0440bf26c3cdd8e613a219a7412571ccbf637cb5c7b6e5966847d0efca447ad5"
            + "243422f9830df937b8d5a4bb78af858aff4807349fbf8b98604c89d244cb4940"
            + "1108496863f3206d0236fc519a751f3765419564debe11154c9d7e9ec28acf46"
            + "fe1dfabe5ba0eed039ee8e18ae3fb4dd179b4032abda82db2c7b630758fe158d"
            + "7972c09cbccfd0fe8f594633e7194ecf999952dc975d1518844e19a89851a713"
            + "130b163fb50ef46beea54b85fef2be1d92587e4fc10be975b6918cfbea5750e001a690";

    /** 流式 SM4-GCM-HKDF（4KB 密文段）的固定明文（100 字节，确定性内容）。 */
    public static final String SM4_GCM_HKDF_STREAMING_VECTOR_PLAINTEXT_HEX =
        "a86886a5d2978142da2d8cf378ebc83cf5ea8adb327f305122c74e759388ba8c"
            + "13fa0056fb80b717412331343d0fdf03feecce587c98b474a34b089e78245b1a"
            + "956365f2d90e3565020512043eaefc3d7dca12681e7bf37ae7cfdc11b5a329d545b9b00c";

    /** 流式 SM4-GCM-HKDF（4KB 密文段，AAD = {@link #SAMPLE_AAD}）：Tink 对上述明文的输出（140 字节）。 */
    public static final String SM4_GCM_HKDF_STREAMING_VECTOR_CIPHERTEXT_HEX =
        "18ab8456785d6fc8d186a4f2940574272ce7108a3d63b03f47b92147c189fbb2"
            + "8eff2c743c36ca48af1731170a0e4b9db00be1f1c66096227db9a6dc3f333707"
            + "e273b87575fcadbb730659efba10a28b906edc851ef022be0dacc22e0bb06bc4"
            + "2bfc461f8c12e429b5145433096c4df4f80114fb3dae27c71154b099e5eba414"
            + "414aa0c0c3603201c04d25a7";
}
