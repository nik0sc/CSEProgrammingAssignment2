import javax.crypto.Cipher;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class Protocol {
    private static final boolean DEBUG = true;

    public static final String CLIENT_HI_CP1_STR = "HELLO CP1 V1 NONCE=";
    public static final byte[] CLIENT_HI_CP1 = CLIENT_HI_CP1_STR.getBytes(StandardCharsets.US_ASCII);
    public static final String CLIENT_CERT_REQUEST_STR = "CERT?\n";
    public static final byte[] CLIENT_CERT_REQUEST = CLIENT_CERT_REQUEST_STR.getBytes(StandardCharsets.US_ASCII);
    public static final int NONCE_LENGTH = 64;
    public static final String CIPHER_1_SPEC = "RSA/ECB/PKCS1Padding";
    public static final String CIPHER_2_SPEC = "RSA/ECB/PKCS1Padding";
    public static final String DIGEST_SPEC = "SHA-256";

    public static final String OK_STR = "OK!\n";
    public static final byte[] OK = OK_STR.getBytes(StandardCharsets.US_ASCII);

    public static final String CLIENT_METADATA_BLOCK_STR = "METADATA V1=";
    public static final byte[] CLIENT_METADATA_BLOCK = CLIENT_METADATA_BLOCK_STR.getBytes(StandardCharsets.US_ASCII);

    public static final String CLIENT_FILE_DIGEST_STR = "DIGEST V1=";
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
        // Then allocate a byte array from it
        int blobLength = fromServer.readInt();
        assert blobLength > 0;
        byte[] buf = new byte[blobLength];

        // Now read all the data that will fit
        fromServer.readFully(buf);

        return buf;
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

    public static void readForBytes(DataInputStream from, byte[] expectedBytes) throws IOException {
        byte[] msg = new byte[expectedBytes.length];
        from.readFully(msg);

        if (!Arrays.equals(msg, expectedBytes)) {
            throw new RuntimeException("Didn't get OK");
        }
    }

    public static void readOK(DataInputStream from) throws IOException {
        readForBytes(from, OK);
    }

//    public static byte[] doCipherFInal(Cipher cipher, )
}
