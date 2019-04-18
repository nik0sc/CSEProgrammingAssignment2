import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class ServerWithoutSecurity {

	private static final String PRIVATE_KEY_FILE_NAME = "private_key.der";
	private static PrivateKey privateKey = null;

	private static final String CERT_FILE_NAME = "example.org.crt";

	private static PrivateKey getPrivateKey() {
		if (privateKey == null) {
			// load key if not loaded yet
			byte[] privateKey = null;
			try {
				// read key file
				FileInputStream fileInputStream = new FileInputStream(PRIVATE_KEY_FILE_NAME);
				privateKey = fileInputStream.readAllBytes();
			} catch (IOException e) {
				assert false;
			}

			// get key from file content
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);

			KeyFactory keyFactory = null;
			try {
				keyFactory = KeyFactory.getInstance("RSA");
			} catch (NoSuchAlgorithmException e) {
				assert false;
			}
			try {
				ServerWithoutSecurity.privateKey = keyFactory.generatePrivate(keySpec);
			} catch (InvalidKeySpecException e) {
				assert false;
			}
		}

		return ServerWithoutSecurity.privateKey;
	}

	private static void doAuthenticationHandshake(DataOutputStream toClient, DataInputStream fromClient)
			throws IOException, GeneralSecurityException {
		// accept nonce
		byte[] helloMessage = new byte[Protocol.CLIENT_HI.length + Protocol.NONCE_LENGTH + 1];
		fromClient.read(helloMessage);
		assert Arrays.equals(
				helloMessage, 0, Protocol.CLIENT_HI.length - 1,
				Protocol.CLIENT_HI, 0, Protocol.CLIENT_HI.length - 1
		);
		byte[] nonce = Arrays.copyOfRange(
				helloMessage,
				Protocol.CLIENT_HI.length,
				Protocol.CLIENT_HI.length + Protocol.NONCE_LENGTH
		);

		//  encrypt nonce
		PrivateKey privateKey = getPrivateKey();
		Cipher rsaCipherEnc = Cipher.getInstance(Protocol.NONCE_CIPHER);
		rsaCipherEnc.init(Cipher.ENCRYPT_MODE, privateKey);
		byte[] encryptedNonce = rsaCipherEnc.doFinal(nonce);

		// send encrypted nonce, prepended with length
		toClient.writeShort(encryptedNonce.length);
		toClient.write(encryptedNonce);
		toClient.flush();

		// wait for cert request
		byte[] certRequest = new byte[Protocol.CLIENT_CERT_REQUEST.length];
		fromClient.read(certRequest);
		assert Arrays.equals(certRequest, Protocol.CLIENT_CERT_REQUEST);

		// send cert, prepeded with size
		FileInputStream certStream = new FileInputStream(CERT_FILE_NAME);
		byte[] certByteArray = certStream.readAllBytes();
		toClient.writeShort(certByteArray.length);
		toClient.write(certByteArray);
		toClient.flush();

		// wait for okay, and... done!
		byte[] okayMessage = new byte[Protocol.CLIENT_AUTH_OK.length];
		fromClient.read(okayMessage);
		assert Arrays.equals(okayMessage, Protocol.CLIENT_AUTH_OK);
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
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			doAuthenticationHandshake(toClient, fromClient);

			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.readFully(block, 0, numBytes);

					if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

					if (numBytes < 117) {
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}

}
