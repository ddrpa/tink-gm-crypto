package cc.ddrpa.crypto.tink.streamingaead.internal.testing;

import com.google.crypto.tink.streamingaead.StreamingAeadKey;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;

/**
 * Test vector for StreamingAEAD encryption.
 */
@Immutable
public final class StreamingAeadTestVector {

    private final StreamingAeadKey key;
    private final Bytes plaintext;
    private final Bytes associatedData;
    private final Bytes ciphertext;

    public StreamingAeadTestVector(
        StreamingAeadKey key, byte[] plaintext, byte[] associatedData, byte[] ciphertext) {
        this.key = key;
        this.plaintext = Bytes.copyFrom(plaintext);
        this.associatedData = Bytes.copyFrom(associatedData);
        this.ciphertext = Bytes.copyFrom(ciphertext);
    }

    public StreamingAeadKey getKey() {
        return key;
    }

    public byte[] getPlaintext() {
        return plaintext.toByteArray();
    }

    public byte[] getAssociatedData() {
        return associatedData.toByteArray();
    }

    public byte[] getCiphertext() {
        return ciphertext.toByteArray();
    }
}
