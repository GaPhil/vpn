import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by GaPhil on 2018-12-04.
 */
public class TestHandshakeCrypto {
    static String PRIVATEKEYFILE = "private_key_user.pem";
    static String CERTFILE = "cert_user.pem";
    static String PLAINTEXT = "Time flies like an arrow. Fruit flies like a banana.";
    static String ENCODING = "UTF-8"; /* For converting between strings and byte arrays */

    static public void main(String[] args) throws Exception {
        /* Extract key pair */
        PublicKey publickey = HandshakeCrypto.getPublicKeyFromCertFile(CERTFILE);
        PrivateKey privatekey = HandshakeCrypto.getPrivateKeyFromKeyFile(PRIVATEKEYFILE);

        /* Encode string as bytes */
        byte[] plaininputbytes = PLAINTEXT.getBytes(ENCODING);
        /* Encrypt it */
        byte[] cipher = HandshakeCrypto.encrypt(plaininputbytes, publickey);
        /* Then decrypt back */
        byte[] plainoutputbytes = HandshakeCrypto.decrypt(cipher, privatekey);
        /* Decode bytes into string */
        String plainoutput = new String(plainoutputbytes, ENCODING);
        if (plainoutput.equals(PLAINTEXT)) {
            System.out.println("Pass. Input and output strings are the same: \"" + PLAINTEXT + "\"");
        } else {
            System.out.println("Fail. Expected \"" + PLAINTEXT + "\", but got \"" + plainoutput + "\'");
        }
    }
}
