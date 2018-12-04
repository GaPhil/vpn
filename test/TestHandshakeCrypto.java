import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by GaPhil on 2018-12-04.
 * <p>
 * Test the Handshake Crypto; extract key pair, encrypt, decrypt, compare.
 */
public class TestHandshakeCrypto {
    private static String PRIVATEKEYFILE = "private_key_user.pem";
    private static String CERTFILE = "cert_user.pem";
    private static String PLAINTEXT = "Time flies like an arrow. Fruit flies like a banana.";
    private static String ENCODING = "UTF-8";

    static public void main(String[] args) throws Exception {
        PublicKey publickey = HandshakeCrypto.getPublicKeyFromCertFile(CERTFILE);
        PrivateKey privatekey = HandshakeCrypto.getPrivateKeyFromKeyFile(PRIVATEKEYFILE);

        byte[] plainInputBytes = PLAINTEXT.getBytes(ENCODING);
        byte[] cipher = HandshakeCrypto.encrypt(plainInputBytes, publickey);
        byte[] plainOutputBytes = HandshakeCrypto.decrypt(cipher, privatekey);
        String plainOutput = new String(plainOutputBytes, ENCODING);
        if (plainOutput.equals(PLAINTEXT)) {
            System.out.println("Pass. Input and output strings are the same: \"" + PLAINTEXT + "\"");
        } else {
            System.out.println("Fail. Expected \"" + PLAINTEXT + "\", but got \"" + plainOutput + "\'");
        }
    }
}
