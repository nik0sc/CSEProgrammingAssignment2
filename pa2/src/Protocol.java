import javax.crypto.Cipher;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class Protocol {
    private static final boolean DEBUG = true;

    public static final String CLIENT_HI_STR = "HELLO V1 NONCE=";
    public static final byte[] CLIENT_HI = CLIENT_HI_STR.getBytes(StandardCharsets.US_ASCII);
    public static final String CLIENT_CERT_REQUEST_STR = "CERT?\n";
    public static final byte[] CLIENT_CERT_REQUEST = CLIENT_CERT_REQUEST_STR.getBytes(StandardCharsets.US_ASCII);
    public static final int NONCE_LENGTH = 64;
    public static final String CIPHER_SPEC = "RSA/ECB/PKCS1Padding";
    public static final String CLIENT_AUTH_OK_STR = "OK!\n";
    public static final byte[] CLIENT_AUTH_OK = CLIENT_AUTH_OK_STR.getBytes(StandardCharsets.US_ASCII);

    public static final String CLIENT_NUM_BLOCKS_STR = "BLOCKS=";
    public static final byte[] CLIENT_NUM_BLOCKS = CLIENT_NUM_BLOCKS_STR.getBytes(StandardCharsets.US_ASCII);

    public static final String CLIENT_FILE_NAME_STR = "FILE_NAME=";
    public static final byte[] CLIENT_FILE_NAME = CLIENT_FILE_NAME_STR.getBytes(StandardCharsets.US_ASCII);
    public static final String CLIENT_FILE_DIGEST_STR = "FILE_DIGEST=";
    public static final byte[] CLIENT_FILE_DIGEST = CLIENT_FILE_DIGEST_STR.getBytes(StandardCharsets.US_ASCII);

    public static final String CLIENT_BYE_STR = "BYE!\n";
    public static final byte[] CLIENT_BYE = CLIENT_BYE_STR.getBytes(StandardCharsets.US_ASCII);

    /**
     * Read blob from socket. The blob is prefixed with an unsigned short (16 bits) indicating the length of the
     * data to follow. Beware of buffer under/overflow
     *
     * @param fromServer
     * @return byte array containing the blob
     * @throws IOException
     */
    public static byte[] readBlob(DataInputStream fromServer) throws IOException {
        // First read 32 bits worth of unsigned data - that is the length
        // Then allocate a buffer from it
        int blobLength = fromServer.readInt();
        assert blobLength > 0;
        ByteBuffer buffer = ByteBuffer.allocate(blobLength);

        // Now read all the data that will fit
        for (int i = 0; i < blobLength; i++) {
            buffer.put(fromServer.readByte());
        }

        return buffer.array();
    }

    public static void writeBlob(DataOutputStream to, byte[] byteArray) throws IOException {
        to.writeInt(byteArray.length);
        to.write(byteArray);
        to.flush();
    }

    public static void writeEncryptedBlob(
            DataOutputStream to,
            byte[] byteArray,
            int offset,
            int length,
            Cipher cipher
    ) throws IOException, GeneralSecurityException {
        // byte[] len 2, offset 1, length 1 is valid
        assert (offset + length) <= byteArray.length;

        writeBlob(to, cipher.doFinal(byteArray, offset, length));
    }

    public static void writeEncryptedBlob(DataOutputStream to, byte[] byteArray, Cipher cipher)
            throws IOException, GeneralSecurityException {
        writeEncryptedBlob(to, byteArray, 0, byteArray.length, cipher);
    }

    public static byte[] readEncryptedBlob(DataInputStream from, Cipher decipher)
            throws IOException, GeneralSecurityException {
        byte[] encryptedBlob = readBlob(from);
        return decipher.doFinal(encryptedBlob);
    }

//    public static byte[] doCipherFInal(Cipher cipher, )
}
