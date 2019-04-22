import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.Arrays;

public class ServerWithSecurityCP2 {

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

			PrivateKey privateKey = ServerCommon.getPrivateKey();
			Cipher rsaCipherEnc = Cipher.getInstance(Protocol.CIPHER_1_SPEC);
			rsaCipherEnc.init(Cipher.ENCRYPT_MODE, privateKey);
			Cipher rsaCipherDec = Cipher.getInstance(Protocol.CIPHER_1_SPEC);
			rsaCipherDec.init(Cipher.DECRYPT_MODE, privateKey);

			ServerCommon.doAuthenticationHandshake(toClient, fromClient, rsaCipherEnc, Protocol.CLIENT_HI_CP2);

			Protocol.SessionCipher sessionCipher = ServerCommon.doKeyExchange(toClient, fromClient, rsaCipherDec);

			ServerCommon.receiveFile(toClient, fromClient, sessionCipher.getDec());

			toClient.close();
			fromClient.close();
			connectionSocket.close();
			welcomeSocket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
