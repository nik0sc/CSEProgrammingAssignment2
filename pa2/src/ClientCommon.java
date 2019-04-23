import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class ClientCommon {

    /**
     * Verify server certificate and return its public key
     *
     * @param serverCert
     * @return
     * @throws FileNotFoundException
     * @throws GeneralSecurityException
     */
    public static PublicKey getAndVerifyPubKey(X509Certificate serverCert)
            throws FileNotFoundException, GeneralSecurityException {
        // Load CA pubkey
        InputStream caCertInputStream = new FileInputStream(ClientWithSecurityCP1.CA_CERT_FILENAME);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate) certificateFactory.generateCertificate(caCertInputStream);
        PublicKey caPubKey = caCert.getPublicKey();

        // throws exceptions CertificateExpiredException, CertificateNotYetValidException
        caCert.checkValidity();
        serverCert.checkValidity();

        // Extract signature from cert
        serverCert.verify(caPubKey);

        return serverCert.getPublicKey();
    }

    /**
     * Perform the authentication handshake (get cert, verify with CA, challenge with nonce)
     * This does not perform key exchange for CP2!
     *
     * @param toServer
     * @param fromServer
     * @param secureRandom
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static PublicKey doAuthenticationHandshake(DataOutputStream toServer, DataInputStream fromServer,
                                                      SecureRandom secureRandom, byte[] versionHeader)
            throws IOException, GeneralSecurityException {
        // Generate nonce
        byte[] nonce = new byte[Protocol.NONCE_LENGTH];
        secureRandom.nextBytes(nonce);

// Say hi to the remote server, send a nonce
        // Length of hello string + nonce + newline
        ByteBuffer outputHiBuffer = ByteBuffer.allocate(versionHeader.length + Protocol.NONCE_LENGTH + 1);
        outputHiBuffer.put(versionHeader);
        outputHiBuffer.put(nonce);
        outputHiBuffer.put((byte)'\n');

        toServer.write(outputHiBuffer.array());
        toServer.flush();

        // Read the encrypted nonce and remember it
        byte[] encryptedNonce = Protocol.readBlob(fromServer);

// Ask for the cert
        toServer.write(Protocol.CLIENT_CERT_REQUEST);
        toServer.flush();

// Read and remember the cert
        byte[] serverCertBytes = Protocol.readBlob(fromServer);

        // Load and verify the server cert
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate serverCert = (X509Certificate) certificateFactory.generateCertificate(
                new ByteArrayInputStream(serverCertBytes));

        // Grab the public key
        PublicKey serverPubKey = getAndVerifyPubKey(serverCert);

        // And verify the nonce
        Cipher rsaCipherDec = Cipher.getInstance(Protocol.CIPHER_1_SPEC);
        rsaCipherDec.init(Cipher.DECRYPT_MODE, serverPubKey);
        byte[] nonceDec = rsaCipherDec.doFinal(encryptedNonce);

        if (Arrays.equals(nonce, nonceDec)) {
            // tell the server all is well
            toServer.write(Protocol.OK);
            toServer.flush();

            return serverPubKey;
        } else {
            // Die a horrible death
            throw new GeneralSecurityException("OMG");
        }
}

    /**
     * Generate and exchange a session key for CP2.
     *
     * @param toServer
     * @param fromServer
     * @param secureRandom
     * @param rsaCipherEnc
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static Protocol.SessionCipher doKeyExchange(DataOutputStream toServer, DataInputStream fromServer,
                                                       SecureRandom secureRandom, Cipher rsaCipherEnc)
            throws IOException, GeneralSecurityException {
        // Generate a session key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(secureRandom);
        SecretKey sessionKey = keyGen.generateKey();

        // Encrypt with server public key and send it over
        Protocol.writeEncryptedBlob(toServer, sessionKey.getEncoded(), rsaCipherEnc);

        // Expect server to send back "OK" encrypted with session key
        Cipher aesCipherDec = Cipher.getInstance(Protocol.CIPHER_2_SPEC);
        aesCipherDec.init(Cipher.DECRYPT_MODE, sessionKey);
        byte[] result = Protocol.readEncryptedBlob(fromServer, aesCipherDec);

        assert Arrays.equals(result, Protocol.OK);

        // Return the symmetric decryption cipher
        Cipher aesCipherEnc = Cipher.getInstance(Protocol.CIPHER_2_SPEC);
        aesCipherEnc.init(Cipher.ENCRYPT_MODE, sessionKey);

        return new Protocol.SessionCipher(aesCipherEnc, aesCipherDec);
    }

    /**
	 * Send the file
	 *
	 * @param toServer
	 * @param fromServer
	 * @param cipherEnc
	 * @param filename
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static void sendFile(DataOutputStream toServer, DataInputStream fromServer,
								Cipher cipherEnc, String filename, int blockSize)
			throws GeneralSecurityException, IOException {
		// make file digest
		MessageDigest md = MessageDigest.getInstance(Protocol.DIGEST_SPEC);
		long fileLength = new File(filename).length();
		assert fileLength <= Integer.MAX_VALUE;
		int numBlocks = (int) Math.ceil((double)fileLength/ blockSize);

		// Send the encrypted filename, file size, and number of blocks
		byte[] filenameBytes = filename.getBytes();

        int metadataBlockLength = Protocol.CLIENT_METADATA_BLOCK.length
                + 8 // file size + num blocks
                + filenameBytes.length
                + 1; // \0

		// Must fit into one block
		assert metadataBlockLength <= blockSize;

		ByteBuffer metadataBuf = ByteBuffer.allocate(metadataBlockLength);
		metadataBuf.put(Protocol.CLIENT_METADATA_BLOCK);
		metadataBuf.putInt((int)fileLength);
		metadataBuf.putInt(numBlocks);
        metadataBuf.put(filenameBytes);
        metadataBuf.put((byte)'\0');

		Protocol.writeEncryptedBlob(toServer, metadataBuf.array(), cipherEnc);

		Protocol.readOK(fromServer);

		// Open the file
		FileInputStream fileInputStream = new FileInputStream(filename);
		BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

		System.out.println(String.format("Sending %d blocks of %d ciphertext bytes each",
				numBlocks, cipherEnc.getBlockSize()));

		byte[] fromFileBuffer = new byte[blockSize];
		int i = 0;
		// Send the file
		while (true) {
			int numBytes = bufferedFileInputStream.read(fromFileBuffer);

			if (numBytes == -1) {
				break;
			}

			Protocol.writeEncryptedBlob(toServer, fromFileBuffer, 0, numBytes, cipherEnc);
			md.update(fromFileBuffer, 0, numBytes);
			i++;
		}

		System.out.println(String.format("Sent %d blocks", i));

		assert i == numBlocks;

		// Send digest
		byte[] digest = md.digest();
		ByteBuffer digestMessageBuf = ByteBuffer.allocate(
				Protocol.CLIENT_FILE_DIGEST.length + digest.length);
		digestMessageBuf.put(Protocol.CLIENT_FILE_DIGEST);
		digestMessageBuf.put(digest);

		Protocol.writeEncryptedBlob(toServer, digestMessageBuf.array(), cipherEnc);
		Protocol.readOK(fromServer);

		bufferedFileInputStream.close();
		fileInputStream.close();
	}
}
