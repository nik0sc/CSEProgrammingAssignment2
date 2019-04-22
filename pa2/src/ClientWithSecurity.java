import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class ClientWithSecurity {
	public static final String CA_CERT_FILENAME = "cacse.crt";

    public static PublicKey verifyAndGetPublicKey(X509Certificate serverCert)
			throws FileNotFoundException, GeneralSecurityException {
		// load CA's public key
		InputStream caCertInputStream = new FileInputStream(CA_CERT_FILENAME);
		CertificateFactory certificateFactory = CertificateFactory.getInstance(Protocol.CERT_TYPE);
		X509Certificate caCert = (X509Certificate) certificateFactory.generateCertificate(caCertInputStream);
		PublicKey caPublicKey = caCert.getPublicKey();
		// check cert validity
		caCert.checkValidity();
		serverCert.checkValidity();
		// verify cert
		serverCert.verify(caPublicKey);
		// get public key from cert
		return serverCert.getPublicKey();
	}

	public static PublicKey doAuthenticationHandshake(
			DataOutputStream toServer,
			DataInputStream fromServer
	) throws IOException, GeneralSecurityException {
		// generate nonce
		byte[] nonce = new byte[Protocol.NONCE_LENGTH];
		new SecureRandom().nextBytes(nonce);

        // send client hello
		ByteBuffer helloBuffer = ByteBuffer.allocate(Protocol.CLIENT_HELLO.length + Protocol.NONCE_LENGTH + 1);
		helloBuffer.put(Protocol.CLIENT_HELLO);
		helloBuffer.put(nonce);
		helloBuffer.put("\n".getBytes(StandardCharsets.US_ASCII));
		toServer.write(helloBuffer.array());
		toServer.flush();

		// get the encrypted nonce
		byte[] encryptedNonce = Protocol.readBlob(fromServer);

        // request for cert
		toServer.write(Protocol.CERT_REQUEST);
		toServer.flush();

        // get the cert
		byte[] serverCertByteArray = Protocol.readBlob(fromServer);
		CertificateFactory certificateFactory = CertificateFactory.getInstance(Protocol.CERT_TYPE);
		X509Certificate serverCert = (X509Certificate) certificateFactory.generateCertificate(
				new ByteArrayInputStream(serverCertByteArray));

		// verify cert and get the public key
		PublicKey serverPubKey = verifyAndGetPublicKey(serverCert);

		// authenticate by checking the nonce
		Cipher rsaCipherDec = Cipher.getInstance(Protocol.CIPHER_SPEC);
		rsaCipherDec.init(Cipher.DECRYPT_MODE, serverPubKey);
		byte[] nonceDec = rsaCipherDec.doFinal(encryptedNonce);

		if (Arrays.equals(nonce, nonceDec)) {
			// send auth ok message to server
			toServer.write(Protocol.CLIENT_AUTH_OK);
			toServer.flush();
			// and return
			return serverPubKey;
		} else {
			throw new GeneralSecurityException("something's not right :-(");
		}
    }

    public static void doFileHandshake() {

	}

	public static void sendFile(
			DataOutputStream toServer,
			Cipher cipherEnc,
			String filename
	) throws GeneralSecurityException, IOException {
		// initialize
		MessageDigest md = MessageDigest.getInstance(Protocol.DIGEST_ALGORITHM);
		FileInputStream fileInputStream = new FileInputStream(filename);
		BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

		// send encrypted file name
		Protocol.writeEncryptedBlob(toServer, cipherEnc, filename.getBytes(StandardCharsets.US_ASCII));
		toServer.flush();

		// read, update digest, and send file block by block
		byte[] fromFileBuffer = new byte[Protocol.FILE_BLOCK_SIZE];		// first byte indicates whether this is the last block
		boolean isLastBlock = false;
		while(!isLastBlock) {
			int numBytes = bufferedFileInputStream.readNBytes(fromFileBuffer, 1, Protocol.FILE_BLOCK_SIZE - 1);
			isLastBlock = (numBytes < Protocol.FILE_BLOCK_SIZE - 1);
			fromFileBuffer[0] = isLastBlock? Protocol.FILE_BLOB_TERMINAL : Protocol.FILE_BLOB_NONTERMINAL;
			Protocol.writeEncryptedBlob(toServer, cipherEnc, fromFileBuffer, 0, numBytes + 1);
			md.update(fromFileBuffer, 1, numBytes);
		}
		// only need to flush after all writes are done
        toServer.flush();

		// send digest
		Protocol.writeEncryptedBlob(toServer, cipherEnc, md.digest());
		toServer.flush();

		bufferedFileInputStream.close();
		fileInputStream.close();
	}

	public static void main(String[] args) {

    	String filename = "rr.txt";
    	if (args.length > 0) filename = args[0];

    	String serverAddress = "localhost";
    	if (args.length > 1) filename = args[1];

    	int port = 4321;
    	if (args.length > 2) port = Integer.parseInt(args[2]);

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

		long timeStarted = System.nanoTime();

		PublicKey serverPublicKey;

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			// do authentication and get public key
			serverPublicKey = doAuthenticationHandshake(toServer, fromServer);

			System.out.println("Sending file...");

			// initialize cipher
            Cipher rsaCipherEnc = Cipher.getInstance(Protocol.CIPHER_SPEC);
            rsaCipherEnc.init(Cipher.ENCRYPT_MODE, serverPublicKey);

            // send file
            sendFile(toServer, rsaCipherEnc, filename);

			// finalize
			System.out.println("Closing connection...");
			toServer.write(rsaCipherEnc.doFinal(Protocol.BYE));
			toServer.flush();
			toServer.close();
			fromServer.close();

		} catch (GeneralSecurityException e) {
			System.out.println("Security exception!!");
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
}
