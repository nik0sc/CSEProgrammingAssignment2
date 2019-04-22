import javax.crypto.Cipher;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;

public class ClientWithSecurityCP2 {
	public static final String CA_CERT_FILENAME = "cacse.crt";

	private static final int READ_FILE_BLOCK_SIZE = 100;


	public static void main(String[] args) {

    	String filename = "interject.txt";
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

		SecureRandom secureRandom = new SecureRandom();
		PublicKey serverPubKey;

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			// Do the authentication!
			serverPubKey = ClientCommon.doAuthenticationHandshake(toServer, fromServer, secureRandom, Protocol.CLIENT_HI_CP2);
			// set up cipher
			Cipher rsaCipherEnc = Cipher.getInstance(Protocol.CIPHER_1_SPEC);
			rsaCipherEnc.init(Cipher.ENCRYPT_MODE, serverPubKey);

			Protocol.SessionCipher sessionCipher = ClientCommon.doKeyExchange(toServer, fromServer, secureRandom, rsaCipherEnc);

			System.out.println("Sending file...");

            ClientCommon.sendFile(toServer, fromServer, sessionCipher.getEnc(), filename, READ_FILE_BLOCK_SIZE);

			System.out.println("Closing connection...");
			toServer.write(Protocol.CLIENT_BYE);
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
