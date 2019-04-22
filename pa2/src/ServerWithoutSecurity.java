import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class ServerWithoutSecurity {

	private static final String PRIVATE_KEY_FILE_NAME = "private_key.der";
	private static PrivateKey privateKey = null;

	private static final String CERT_FILE_NAME = "example.org.crt";

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
	    // read file name
        byte[] filenameByteArray = Protocol.readEncryptedBlob(fromClient, cipher);
        String filename = "recv_" + new String(filenameByteArray, StandardCharsets.US_ASCII);
        // create file
        FileOutputStream fileOutputStream = new FileOutputStream(filename);
        BufferedOutputStream bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

	    // initialize main file transfer
        boolean isLastBlock = false;
        MessageDigest md = MessageDigest.getInstance(Protocol.DIGEST_ALGORITHM);
        // read one block every time until last block is reached
        while(!isLastBlock) {
            byte[] readBuffer = Protocol.readEncryptedBlob(fromClient, cipher);
            isLastBlock = (readBuffer[0] == Protocol.FILE_BLOB_TERMINAL);
            System.out.print(new String(Arrays.copyOfRange(readBuffer, 1, readBuffer.length - 1), StandardCharsets.US_ASCII));
            bufferedFileOutputStream.write(readBuffer, 1, readBuffer.length - 1);
            md.update(readBuffer, 1, readBuffer.length - 1);
        }
        // flush and close file
        bufferedFileOutputStream.flush();
        bufferedFileOutputStream.close();
        fileOutputStream.close();
        // make sure digests match, if not then delete file
        byte[] clientDigest = Protocol.readEncryptedBlob(fromClient, cipher);
        byte[] serverDigest = md.digest();
        if (!Arrays.equals(clientDigest, serverDigest)) {
            System.out.println("File checksums do not match, deleting...");
            new File(filename).delete();
        }
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

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

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

			receiveFile(fromClient, rsaCipherDec);

		} catch (Exception e) {e.printStackTrace();}

	}

}
