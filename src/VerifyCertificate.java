import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by GaPhil on 2018-12-03.
 */
public class VerifyCertificate {

    public static void main(String[] args) throws Exception{
        verifyCertificate(args[0], args[1]);
    }

    static void verifyCertificate(String caFile, String userFile) throws Exception {
        X509Certificate caCertificate = null;
        X509Certificate userCertificate = null;
        try {
            caCertificate = readCertificate(caFile);
            userCertificate = readCertificate(userFile);
        } catch (Exception exception) {
            System.out.println("Certificate reading failed.");
        }
        try {
            System.out.println("DN for CA: " + caCertificate.getSubjectDN());
            System.out.println("DN for user: " + userCertificate.getSubjectDN());
        } catch (Exception exception) {
            System.out.println("DN could not be read.");
        }
        try {
            caCertificate.verify(caCertificate.getPublicKey());
            userCertificate.verify(caCertificate.getPublicKey());
        } catch (Exception exception) {
            System.out.println("Certificate verification failed.");
        }
        try {
            caCertificate.checkValidity();
            userCertificate.checkValidity();
        } catch (Exception exception) {
            System.out.println("Certificate not valid.");
        }
        System.out.println("Pass");
    }


    static X509Certificate readCertificate(String certificateName) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fileInputStream = new FileInputStream(certificateName);
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
        PublicKey publicKey = certificate.getPublicKey();
        return certificate;
    }
}