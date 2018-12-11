import crypto_utils.VerifyCertificate;

/**
 * Created by GaPhil on 2018-12-03.
 * <p>
 * Test Certificate Verification with ca.pem and server.pem files.
 * Ensure both certificates exist by running:
 * $ sh create_user "Bob Smith bob@smith.com"
 * and
 * $ sh create_ca "Bob Smith bob@smith.com"
 */
public class TestCertificateVerification {

    public static void main(String[] args) {
        VerifyCertificate.verifyCertificate("ca.pem", "server.pem");
        VerifyCertificate.verifyCertificate("ca.pem", "client.pem");
    }
}
