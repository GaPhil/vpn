/**
 * Created by GaPhil on 2018-12-03.
 * <p>
 * Test Certificate Verification with cert_ca.pem and cert_server.pem files.
 * Ensure both certificates exist by running:
 * $ sh create_user "Bob Smith bob@smith.com"
 * and
 * $ sh create_ca "Bob Smith bob@smith.com"
 */
public class TestCertificateVerification {

    public static void main(String[] args) {
        VerifyCertificate.verifyCertificate("cert_ca.pem", "cert_server.pem");
        VerifyCertificate.verifyCertificate("cert_ca.pem", "cert_client.pem");
    }
}
