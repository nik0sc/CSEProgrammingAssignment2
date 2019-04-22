import javax.crypto.Cipher;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class Protocol {
    public static final int NONCE_LENGTH = 64;
    static final int FILE_BLOCK_SIZE = 245;
    public static final String CIPHER_SPEC = "RSA/ECB/PKCS1Padding";
    public static final String CERT_TYPE = "X.509";
    public static final String DIGEST_ALGORITHM = "SHA-256";

    public static final byte FILE_BLOB_NONTERMINAL = 0;
    public static final byte FILE_BLOB_TERMINAL = 1;

    public static final byte[] CLIENT_HELLO = "HELLO NONCE=".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] CERT_REQUEST = "CERT?\n".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] CLIENT_AUTH_OK = "OK!\n".getBytes(StandardCharsets.US_ASCII);

    public static final byte[] BYE = "BYE!\n".getBytes(StandardCharsets.US_ASCII);

    public static byte[] readBlob(DataInputStream from) throws IOException {
        // get length of blob
        int blobLength = from.readInt();
        if (blobLength < 0) {
            blobLength = 0;
        }
        return from.readNBytes(blobLength);
    }

    public static void writeBlob(DataOutputStream to, byte[] byteArray) throws IOException {
        to.writeInt(byteArray.length);
        to.write(byteArray);
    }

    public static void writeEncryptedBlob(
            DataOutputStream to,
            Cipher cipher,
            byte[] byteArray,
            int offset,
            int length
    ) throws IOException, GeneralSecurityException {
        writeBlob(to, cipher.doFinal(byteArray, offset, length));
    }

    public static void writeEncryptedBlob(DataOutputStream to, Cipher cipher, byte[] byteArray)
            throws IOException, GeneralSecurityException {
        writeEncryptedBlob(to, cipher, byteArray, 0, byteArray.length);
    }

    public static byte[] readEncryptedBlob(DataInputStream from, Cipher cipher)
            throws IOException, GeneralSecurityException {
        byte[] encryptedBlob = readBlob(from);
        return cipher.doFinal(encryptedBlob);
    }

}
