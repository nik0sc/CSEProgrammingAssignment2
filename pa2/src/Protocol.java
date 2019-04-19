import jdk.jshell.spi.ExecutionControl;

import javax.crypto.Cipher;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;

public class Protocol {
    public static final String CLIENT_HI_STR = "HELLO V1 NONCE=";
    public static final byte[] CLIENT_HI = CLIENT_HI_STR.getBytes(StandardCharsets.US_ASCII);
    public static final String CLIENT_CERT_REQUEST_STR = "CERT?\n";
    public static final byte[] CLIENT_CERT_REQUEST = CLIENT_CERT_REQUEST_STR.getBytes(StandardCharsets.US_ASCII);
    public static final int NONCE_LENGTH = 64;
    public static final String NONCE_CIPHER = "RSA/ECB/PKCS1Padding";
    public static final String CLIENT_AUTH_OK_STR = "OK!\n";
    public static final byte[] CLIENT_AUTH_OK = CLIENT_AUTH_OK_STR.getBytes(StandardCharsets.US_ASCII);

    public static final String CLIENT_FILE_NAME_STR = "FILE NAME=";
    public static final byte[] CLIENT_FILE_NAME = CLIENT_FILE_NAME_STR.getBytes(StandardCharsets.US_ASCII);
    public static final String CLIENT_FILE_DIGEST_STR = "FILE DIGEST=";
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
        // First read 16 bits worth of unsigned data - that is the length
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
        to.write(cipher.doFinal(byteArray, offset, length));
        to.flush();
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
}
