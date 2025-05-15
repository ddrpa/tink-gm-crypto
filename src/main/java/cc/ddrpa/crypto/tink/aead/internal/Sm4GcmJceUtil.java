package cc.ddrpa.crypto.tink.aead.internal;

import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.subtle.EngineFactory;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Helper functions for SM4-GCM using JCE.
 */
public final class Sm4GcmJceUtil {

    // All instances of this class use a 12-byte IV and a 16-byte tag.
    public static final int IV_SIZE_IN_BYTES = 12;
    public static final int TAG_SIZE_IN_BYTES = 16;

    private static final ThreadLocal<Cipher> localCipher =
        ThreadLocal.withInitial(() -> {
            try {
                return EngineFactory.CIPHER.getInstance("SM4/GCM/NoPadding");
            } catch (GeneralSecurityException ex) {
                throw new IllegalStateException(ex);
            }
        });

    private Sm4GcmJceUtil() {
    }

    /**
     * Returns a thread-local instance of the SM4-GCM cipher.
     */
    public static Cipher getThreadLocalCipher() {
        return localCipher.get();
    }

    public static SecretKey getSecretKey(final byte[] key) throws GeneralSecurityException {
        if (key.length != 16) {
            throw new InvalidAlgorithmParameterException(
                String.format("invalid key size %d; only 128-bit SM4 keys are supported",
                    key.length * 8));
        }
        return new SecretKeySpec(key, "SM4");
    }

    public static AlgorithmParameterSpec getParams(final byte[] iv) {
        return getParams(iv, 0, iv.length);
    }

    public static AlgorithmParameterSpec getParams(final byte[] buf, int offset, int len) {
        @Nullable Integer apiLevel = Util.getAndroidApiLevel();
        if (apiLevel != null && apiLevel <= 19) {
            // GCMParameterSpec should always be present in Java 7 or newer, but it's unsupported on
            // Android devices with API level <= 19. Fortunately, if a modern copy of Conscrypt is present
            // (either through GMS Core or bundled with the app) we can initialize the cipher with just an
            // IvParameterSpec. It will use a tag size of 128 bits.
            //
            // Note that API level 19 is not supported anymore by Tink, and we don't run tests on it
            // anymore.
            return new IvParameterSpec(buf, offset, len);
        }
        return new GCMParameterSpec(8 * TAG_SIZE_IN_BYTES, buf, offset, len);
    }
}
