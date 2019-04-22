import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class ServerCP2 {

    private static final String PRIVATE_KEY_FILE_NAME = "private_key.der";
    private static PrivateKey privateKey = null;

    private static final String CERT_FILE_NAME = "example.org.crt";

    public static Cipher sharedCipherEnc;
    public static Cipher sharedCipherDec;

    private static void loadPrivateKey() throws IOException {
        // get key as byte array from file
        byte[] key = new FileInputStream(PRIVATE_KEY_FILE_NAME).readAllBytes();

        // convert to keyspec
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            // some hardcoded literal is prolly wrong, crash away~
            assert false;
        }
    }

    private static void receiveFile(DataInputStream fromClient, Cipher cipher)
            throws IOException, GeneralSecurityException {
        int blockSize = cipher.getBlockSize();
        // read file name
        byte[] filenameByteArray = cipher.doFinal(fromClient.readNBytes(blockSize));
        String filename = "recv_" + new String(filenameByteArray, StandardCharsets.US_ASCII);
        // create file
        FileOutputStream fileOutputStream = new FileOutputStream(filename);
        BufferedOutputStream bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

        // initialize main file transfer
        boolean isLastBlock = false;
        MessageDigest md = MessageDigest.getInstance(Protocol.DIGEST_ALGORITHM);
        // read one block every time until last block is reached
        while(!isLastBlock) {
            byte[] readBuffer = cipher.doFinal(fromClient.readNBytes(blockSize));
            isLastBlock = (readBuffer[0] == Protocol.FILE_BLOB_TERMINAL);
            bufferedFileOutputStream.write(readBuffer, 1, readBuffer.length - 1);
            md.update(readBuffer, 1, readBuffer.length - 1);
        }
        // close file
        bufferedFileOutputStream.close();
        fileOutputStream.close();
        // make sure digests match, if not then delete file
        byte[] clientDigest = cipher.doFinal(fromClient.readAllBytes());
        byte[] serverDigest = md.digest();
        if (!Arrays.equals(clientDigest, serverDigest)) {
            System.out.println("File checksums do not match, deleting...");
            new File(filename).delete();
        }
    }

    private static void doCPHandshake(DataOutputStream toClient, DataInputStream fromClient, Cipher rsaCipherDec)
            throws IOException, GeneralSecurityException {
        // get shared key from client
        byte[] secretKeyByteArray = Protocol.readEncryptedBlob(fromClient, rsaCipherDec);
        SecretKey secretKey = new SecretKeySpec(secretKeyByteArray, Protocol.SYMMETRIC_CIPHER_TYPE);
        // initialize ciphers
        sharedCipherEnc = Cipher.getInstance(Protocol.SYMMETRIC_CIPHER_SPEC);
        sharedCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
        sharedCipherDec = Cipher.getInstance(Protocol.SYMMETRIC_CIPHER_SPEC);
        sharedCipherDec.init(Cipher.DECRYPT_MODE, secretKey);
        // send agreement message
        toClient.write(sharedCipherEnc.doFinal(Protocol.AGREE_KEY));
    }

    private static void doAuthenticationHandshake(DataOutputStream toClient, DataInputStream fromClient, Cipher encCipher)
            throws IOException, GeneralSecurityException {
        // skip to nonce
        fromClient.skipNBytes(Protocol.CLIENT_HELLO.length);
        // read nonce
        byte[] nonce = fromClient.readNBytes(Protocol.NONCE_LENGTH);
        // skip newline
        fromClient.skipNBytes(1);
        // send signed / encrypted nonce
        Protocol.writeEncryptedBlob(toClient, encCipher, nonce);
        toClient.flush();

        // wait for cert request
        fromClient.skipNBytes(Protocol.CERT_REQUEST.length);
        // send cert
        FileInputStream certStream = new FileInputStream(CERT_FILE_NAME);
        byte[] certByteArray = certStream.readAllBytes();
        Protocol.writeBlob(toClient, certByteArray);
        toClient.flush();
        // wait for client to send okay
        fromClient.skipNBytes(Protocol.CLIENT_AUTH_OK.length);
    }

    public static void main(String[] args) {

        int port = 4321;
        if (args.length > 0) port = Integer.parseInt(args[0]);

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        try {
            loadPrivateKey();

            Cipher rsaCipherEnc = Cipher.getInstance(Protocol.CIPHER_SPEC);
            rsaCipherEnc.init(Cipher.ENCRYPT_MODE, privateKey);

            Cipher rsaCipherDec = Cipher.getInstance(Protocol.CIPHER_SPEC);
            rsaCipherDec.init(Cipher.DECRYPT_MODE, privateKey);

            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            doAuthenticationHandshake(toClient, fromClient, rsaCipherEnc);

            doCPHandshake(toClient, fromClient, rsaCipherDec);

            receiveFile(fromClient, sharedCipherDec);

            toClient.close();
            fromClient.close();
            connectionSocket.close();
            welcomeSocket.close();
        } catch (Exception e) {e.printStackTrace();}

    }

}
