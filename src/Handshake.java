import javafx.util.Pair;

import java.security.cert.X509Certificate;

/**
 * Created by GaPhil on 2018-12-09.
 */
public class Handshake {
    /* Static data -- replace with handshake! */


    /**
     * client and server authenticate each other
     * * certificate exchange
     * <p>
     * client requests forwarding to a target server
     * <p>
     * server creates secret key for enc
     * * client and server
     * <p>
     * authenticate client and server to each other
     * * certificate based authentication
     * <p>
     * create session key (symmetric key)
     * <p>
     * set up an encrypted connection from client to server forwarder using symmetric key encryption
     */
    public Handshake() {
        VerifyCertificate.verifyCertificate("cert_ca.pem", "cert_server.pem");
        VerifyCertificate.verifyCertificate("cert_ca.pem", "cert_client.pem");
    }


    public void clientHelloMessage(String clientCertificate) throws Exception {
        Pair<String, String> message1 = new Pair<>("MessageType", "ClientHello");
        //Client's X.509 certificate encoded as a string
        X509Certificate certificate = VerifyCertificate.readCertificate(clientCertificate);
        Pair<String, String> message2 = new Pair<>("Certificate", certificate.toString());
    }


    public void serverHelloMessage(String serverCertificate) {

    }



    /* Where the client forwarder forwards data from  */
//    public static final String serverHost = "localhost";
//    public static final int serverPort = 4412;
//
//    /* The final destination */
//    public static String targetHost = "localhost";
//    public static int targetPort = 6789;


    static final String serverHost = "portfw.kth.se";
    static final int serverPort = 4412;
    static final String targetHost = "server.kth.se";
    static int targetPort = 6789;
}