import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class ServerCommon {
    private static final String PRIVATE_KEY_FILE_NAME = "private_key.der";
    private static final String CERT_FILE_NAME = "server_cert.crt";
    static PrivateKey privateKey = null;

    static PrivateKey getPrivateKey() {
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
                ServerCommon.privateKey = keyFactory.generatePrivate(keySpec);
            } catch (InvalidKeySpecException e) {
                assert false;
            }
        }

        return privateKey;
    }

    static void doAuthenticationHandshake(DataOutputStream toClient, DataInputStream fromClient, Cipher cipher,
                                          byte[] versionHeader)
            throws IOException, GeneralSecurityException {
        // accept nonce
        byte[] helloMessage = new byte[versionHeader.length + Protocol.NONCE_LENGTH + 1];
        fromClient.readFully(helloMessage);
        assert Arrays.equals(
                helloMessage, 0, versionHeader.length - 1,
                versionHeader, 0, versionHeader.length - 1
        );
        byte[] nonce = Arrays.copyOfRange(
                helloMessage,
                versionHeader.length,
                versionHeader.length + Protocol.NONCE_LENGTH
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

    static Protocol.SessionCipher doKeyExchange(DataOutputStream toClient, DataInputStream fromClient,
                                                Cipher rsaCipherDec)
            throws IOException, GeneralSecurityException {
        // Read and decrypt the session key blob
        byte[] sessionKeyBytes = Protocol.readEncryptedBlob(fromClient, rsaCipherDec);

        SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, 0, sessionKeyBytes.length, "AES");

        // Create encryption cipher and send ok message
        Cipher aesCipherEnc = Cipher.getInstance(Protocol.CIPHER_2_SPEC);
        aesCipherEnc.init(Cipher.ENCRYPT_MODE, sessionKey);

        Protocol.writeEncryptedBlob(toClient, Protocol.OK, aesCipherEnc);

        Cipher aesCipherDec = Cipher.getInstance(Protocol.CIPHER_2_SPEC);
        aesCipherDec.init(Cipher.DECRYPT_MODE, sessionKey);

        return new Protocol.SessionCipher(aesCipherEnc, aesCipherDec);
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

		System.out.println(String.format("Wrote %d bytes in %d blocks to file \"%s\"",
                bytesWritten, numBlocks, filename));
	}
}
