import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class ServerWithSecurityCP1 {

	private static final String PRIVATE_KEY_FILE_NAME = "private_key.der";
	private static PrivateKey privateKey = null;

	private static final String CERT_FILE_NAME = "server_cert.crt";

	private static PrivateKey getPrivateKey() {
		if (privateKey == null) {
			// load key if not loaded yet
			byte[] privateKey = null;
			try {
				// read key file
				FileInputStream fileInputStream = new FileInputStream(PRIVATE_KEY_FILE_NAME);
				privateKey = fileInputStream.readAllBytes();
			} catch (IOException e) {
				e.printStackTrace();
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
				ServerWithSecurityCP1.privateKey = keyFactory.generatePrivate(keySpec);
			} catch (InvalidKeySpecException e) {
				assert false;
			}
		}

		return ServerWithSecurityCP1.privateKey;
	}

	private static void doAuthenticationHandshake(DataOutputStream toClient, DataInputStream fromClient, Cipher cipher)
			throws IOException, GeneralSecurityException {
		// accept nonce
		byte[] helloMessage = new byte[Protocol.CLIENT_HI_CP1.length + Protocol.NONCE_LENGTH + 1];
		fromClient.readFully(helloMessage);
		assert Arrays.equals(
				helloMessage, 0, Protocol.CLIENT_HI_CP1.length - 1,
				Protocol.CLIENT_HI_CP1, 0, Protocol.CLIENT_HI_CP1.length - 1
		);
		byte[] nonce = Arrays.copyOfRange(
				helloMessage,
				Protocol.CLIENT_HI_CP1.length,
				Protocol.CLIENT_HI_CP1.length + Protocol.NONCE_LENGTH
		);

		//  encrypt nonce
		Protocol.writeEncryptedBlob(toClient, nonce, cipher);

		// wait for cert request
		byte[] certRequest = new byte[Protocol.CLIENT_CERT_REQUEST.length];
		fromClient.readFully(certRequest);
		assert Arrays.equals(certRequest, Protocol.CLIENT_CERT_REQUEST);

		// send cert, prepended with size
		FileInputStream certStream = new FileInputStream(CERT_FILE_NAME);
		byte[] certByteArray = certStream.readAllBytes();
		Protocol.writeBlob(toClient, certByteArray);

		Protocol.readOK(fromClient);
	}

	public static void receiveFile(DataOutputStream toClient, DataInputStream fromClient, Cipher cipherDec)
			throws IOException, GeneralSecurityException {
		// Receive metadata block
		byte[] metadataBlock = Protocol.readEncryptedBlob(fromClient, cipherDec);
		ByteBuffer metadataBuf = ByteBuffer.wrap(metadataBlock);

		// Read block header V1
		byte[] metadataHeader = new byte[Protocol.CLIENT_METADATA_BLOCK.length];
		metadataBuf.get(metadataHeader);
		assert Arrays.equals(metadataHeader, Protocol.CLIENT_METADATA_BLOCK);

		int fileLength = metadataBuf.getInt();
		int numBlocks = metadataBuf.getInt();

		// Read filename
		ByteArrayOutputStream filenameBaos = new ByteArrayOutputStream();
		byte cur;
		while ((cur = metadataBuf.get()) != 0) {
			filenameBaos.write(cur);
		}

		String filename = "recv_" + filenameBaos.toString(StandardCharsets.US_ASCII);

		assert metadataBuf.position() == metadataBuf.limit();

		// Metadata ok, continue
		toClient.write(Protocol.OK);
		toClient.flush();

		// Message digest (need it for later)
		MessageDigest md = MessageDigest.getInstance(Protocol.DIGEST_SPEC);

		// Continue reading...
		ByteArrayOutputStream fileBaos = new ByteArrayOutputStream();
		FileOutputStream fileOutputStream = new FileOutputStream(filename);
		int bytesWritten = 0;
		for (int i = 0; i < numBlocks; i++) {
			byte[] fileBlock = Protocol.readEncryptedBlob(fromClient, cipherDec);
			fileOutputStream.write(fileBlock);
			md.update(fileBlock);
			bytesWritten += fileBlock.length;
		}

		// Length?
		assert fileLength == bytesWritten;

		// File data ok, continue
		toClient.write(Protocol.OK);
		toClient.flush();

		// Get digest
		byte[] digestBlock = Protocol.readEncryptedBlob(fromClient, cipherDec);
		assert Arrays.equals(digestBlock, 0, Protocol.CLIENT_FILE_DIGEST.length,
				Protocol.CLIENT_FILE_DIGEST, 0, Protocol.CLIENT_FILE_DIGEST.length);

		byte[] digest = Arrays.copyOfRange(digestBlock, Protocol.CLIENT_FILE_DIGEST.length, digestBlock.length);

		// Compute digest
		byte[] computedDigest = md.digest();
		assert Arrays.equals(digest, computedDigest);

		// OK
		toClient.write(Protocol.OK);
		toClient.flush();

		// Flush and close
		fileOutputStream.flush();
		fileOutputStream.close();
	}

	public static void main(String[] args) {

    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			PrivateKey privateKey = getPrivateKey();
			Cipher rsaCipherEnc = Cipher.getInstance(Protocol.CIPHER_1_SPEC);
			rsaCipherEnc.init(Cipher.ENCRYPT_MODE, privateKey);
			Cipher rsaCipherDec = Cipher.getInstance(Protocol.CIPHER_1_SPEC);
			rsaCipherDec.init(Cipher.DECRYPT_MODE, privateKey);

			doAuthenticationHandshake(toClient, fromClient, rsaCipherEnc);

			receiveFile(toClient, fromClient, rsaCipherDec);

			toClient.close();
			fromClient.close();
			connectionSocket.close();
			welcomeSocket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
