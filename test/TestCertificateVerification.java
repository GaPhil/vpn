/**
 * Created by GaPhil on 2018-12-03.
 */
public class TestCertificateVerification {

    public static void main(String[] args) throws Exception {
        VerifyCertificate verifyCertificate = new VerifyCertificate();
        verifyCertificate.verifyCertificate("cert_ca.pem", "cert_user.pem");
    }
}
