import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by GaPhil on 2018-12-03.
 */
public class VerifyCertificate {

    /**
     * Main method for running Certificate verification from command line:
     * $ java VerifyCertificate <CA-file> <user-file>
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        verifyCertificate(args[0], args[1]);
    }


    /**
     * Verifies certificates of CA and user; readability, DN,
     * verify signature of certificate, check validity
     *
     * @param caFile   certificate authority certificate file
     * @param userFile user certificate file
     */
    static void verifyCertificate(String caFile, String userFile) {
        X509Certificate caCertificate = null;
        X509Certificate userCertificate = null;
        try {
            caCertificate = readCertificate(caFile);
            userCertificate = readCertificate(userFile);
        } catch (Exception exception) {
            System.out.println("Fail: Certificate could not be read.");
        }
        try {
            System.out.println("DN for CA: " + caCertificate.getSubjectDN());
            System.out.println("DN for user: " + userCertificate.getSubjectDN());
        } catch (Exception exception) {
            System.out.println("Fail: DN could not be read.");
        }
        try {
            caCertificate.verify(caCertificate.getPublicKey());
            userCertificate.verify(caCertificate.getPublicKey());
            System.out.println("Pass: Certificate verified.");
        } catch (Exception exception) {
            System.out.println("Fail: Certificate verification failed.");
        }
        try {
            caCertificate.checkValidity();
            userCertificate.checkValidity();
            System.out.println("Pass: Certificate valid.");
        } catch (Exception exception) {
            System.out.println("Fail: Certificate not valid.");
        }
    }

    /**
     * Reads X.509 certificate from file and returns java X509Certificate object
     *
     * @param certificateName name of certificate
     * @return X.509 certificate object
     */
    static X509Certificate readCertificate(String certificateName) throws CertificateException, FileNotFoundException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fileInputStream = new FileInputStream(certificateName);
        return (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
    }
}
