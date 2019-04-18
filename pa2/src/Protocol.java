import java.nio.charset.StandardCharsets;

public class Protocol {
    public static final String CLIENT_HI_STR = "HELLO V1 NONCE=";
    public static final byte[] CLIENT_HI = CLIENT_HI_STR.getBytes(StandardCharsets.US_ASCII);
    public static final String CLIENT_CERT_REQUEST_STR = "CERT?\n";
    public static final byte[] CLIENT_CERT_REQUEST = CLIENT_CERT_REQUEST_STR.getBytes(StandardCharsets.US_ASCII);
    public static final int NONCE_LENGTH = 64;
    public static final String NONCE_CIPHER = "RSA/ECB/PKCS1Padding";
    public static final String CLIENT_AUTH_OK_STR = "OK!\n";
    public static final byte[] CLIENT_AUTH_OK = CLIENT_AUTH_OK_STR.getBytes(StandardCharsets.US_ASCII);
}
