import java.io.*;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ClientWithoutSecurity {
	public static final String CA_CERT_FILENAME = "";

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

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			System.out.println("Sending file...");

			// Send the filename
			toServer.writeInt(0);
			toServer.writeInt(filename.getBytes().length);
			toServer.write(filename.getBytes());
			//toServer.flush();

			// Open the file
			fileInputStream = new FileInputStream(filename);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);

	        byte [] fromFileBuffer = new byte[117];

	        // Send the file
	        for (boolean fileEnded = false; !fileEnded;) {
				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				fileEnded = numBytes < 117;

				toServer.writeInt(1);
				toServer.writeInt(numBytes);
				toServer.write(fromFileBuffer);
				toServer.flush();
			}

	        bufferedFileInputStream.close();
	        fileInputStream.close();

			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
}
