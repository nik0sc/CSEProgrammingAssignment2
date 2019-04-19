import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class ClientWithSecurity {
	public static final String CA_CERT_FILENAME = "cacse.crt";

	private static final int READ_FILE_BLOCK_SIZE = 1024;

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
		InputStream caCertInputStream = new FileInputStream(CA_CERT_FILENAME);
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
	 *
	 * @param toServer
	 * @param fromServer
	 * @param secureRandom
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public static PublicKey doAuthenticationHandshake(DataOutputStream toServer, DataInputStream fromServer,
													  SecureRandom secureRandom)
			throws IOException, GeneralSecurityException {
		// Generate nonce
		byte[] nonce = new byte[Protocol.NONCE_LENGTH];
		secureRandom.nextBytes(nonce);

        // Say hi to the remote server, send a nonce
		// Length of CLIENT_HI string + nonce + newline
		ByteBuffer outputHiBuffer = ByteBuffer.allocate(Protocol.CLIENT_HI.length + Protocol.NONCE_LENGTH + 1);
		outputHiBuffer.put(Protocol.CLIENT_HI);
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
		Cipher rsaCipherDec = Cipher.getInstance(Protocol.NONCE_CIPHER);
		rsaCipherDec.init(Cipher.DECRYPT_MODE, serverPubKey);
		byte[] nonceDec = rsaCipherDec.doFinal(encryptedNonce);

		if (Arrays.equals(nonce, nonceDec)) {
			// tell the server all is well
			toServer.write(Protocol.CLIENT_AUTH_OK);
			toServer.flush();

			return serverPubKey;
		} else {
			// Die a horrible death
			throw new GeneralSecurityException("OMG");
		}
    }


    public static void doFileHandshake() {

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

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		SecureRandom secureRandom = new SecureRandom();
		PublicKey serverPubKey;

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			// Do the authentication!
			serverPubKey = doAuthenticationHandshake(toServer, fromServer, secureRandom);

			System.out.println("Sending file...");

			// set up cipher
            Cipher rsaCipherEnc = Cipher.getInstance(Protocol.NONCE_CIPHER);
            rsaCipherEnc.init(Cipher.ENCRYPT_MODE, serverPubKey);

            // make file digest
            MessageDigest md = MessageDigest.getInstance("SHA-256");

			// Send the encrypted filename
            toServer.write(rsaCipherEnc.doFinal(Protocol.CLIENT_FILE_NAME));
            Protocol.writeEncryptedBlob(toServer, filename.getBytes(), rsaCipherEnc);

			// Open the file
			fileInputStream = new FileInputStream(filename);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);

	        byte[] fromFileBuffer = new byte[READ_FILE_BLOCK_SIZE];

	        // Send the file
	        while (true) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer);

                if (numBytes == -1) {
                    break;
                }

                Protocol.writeEncryptedBlob(toServer, fromFileBuffer, 0, numBytes, rsaCipherEnc);
                md.update(fromFileBuffer);
            }

	        // Send digest
            toServer.write(rsaCipherEnc.doFinal(Protocol.CLIENT_FILE_DIGEST));
            Protocol.writeEncryptedBlob(toServer, md.digest(), rsaCipherEnc);

	        bufferedFileInputStream.close();
	        fileInputStream.close();

			System.out.println("Closing connection...");
			toServer.write(rsaCipherEnc.doFinal(Protocol.CLIENT_BYE));
			toServer.close();
			fromServer.close();

		} catch (GeneralSecurityException e) {
			System.out.println("Security exception!!");
		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
}
