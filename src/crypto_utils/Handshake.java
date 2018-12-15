package crypto_utils;


import utils.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static crypto_utils.VerifyCertificate.certificateToString;
import static crypto_utils.VerifyCertificate.verifyCertificate;

/**
 * Created by GaPhil on 2018-12-09.
 */
public class Handshake {
    /* Static data -- replace with handshake! */


//    /* Where the client forwarder forwards data from  */
//    public static final String serverHost = "localhost";
//    public static final int serverPort = 4412;
//
//    /* The final destination */
//    public static String targetHost = "localhost";
//    public static int targetPort = 6789;


    public String targetHost;
    public int targetPort;

    public String serverHost;
    public int serverPort;

    private X509Certificate clientCert;
    private X509Certificate serverCert;

    //    HandshakeMessage handshakeMessage = new HandshakeMessage();
    HandshakeCrypto handshakeCrypto = new HandshakeCrypto();

    private SessionKey sessionKey;
    private IvParameterSpec iv;


    public void clientHello(Socket socket, String certFile) {
        HandshakeMessage toServer = new HandshakeMessage();
        try {
            toServer.putParameter("MessageType", "ClientHello");
            toServer.send(socket);
            clientCert = VerifyCertificate.readCertificate(certFile);
            toServer.putParameter("Certificate", certificateToString(clientCert));
            toServer.send(socket);
            Logger.log("ClientHello message sent to " + socket);
        } catch (Exception exception) {
            System.out.println("ClientHello message sending failed!");
        }
    }

    public void receiveClientHello(Socket clientSocket, String caFile) {
        HandshakeMessage fromClient = new HandshakeMessage();
        try {
            fromClient.receive(clientSocket);
            if (fromClient.getParameter("MessageType").equals("ClientHello")) {
                fromClient.receive(clientSocket);
                String cert = fromClient.getParameter("Certificate");
                clientCert = VerifyCertificate.createCertificate(cert);
                verifyCertificate(caFile, clientCert);
                Logger.log("Client certificate verification successful from " + clientSocket);
            } else {
                clientSocket.close();
                throw new Exception();
            }
        } catch (Exception exception) {
            System.out.println("Client certificate verification failed!");
        }
    }

    public void serverHello(Socket clientSocket, String certFile) {
        HandshakeMessage toClient = new HandshakeMessage();
        try {
            toClient.putParameter("MessageType", "ServerHello");
            toClient.send(clientSocket);
            serverCert = VerifyCertificate.readCertificate(certFile);
            toClient.putParameter("Certificate", certificateToString(serverCert));
            toClient.send(clientSocket);
            Logger.log("ServerHello message sent to " + clientSocket);
        } catch (Exception exception) {
            System.out.println("ServerHello message sending failed!");
            exception.printStackTrace();
        }
    }

    public void receiveServerHello(Socket socket, String caCert) {
        HandshakeMessage fromServer = new HandshakeMessage();
        try {
            fromServer.receive(socket);
            if (fromServer.getParameter("MessageType").equals("ServerHello")) {
                fromServer.receive(socket);
                String cert = fromServer.getParameter("Certificate");
                serverCert = VerifyCertificate.createCertificate(cert);
                verifyCertificate(caCert, serverCert);
                Logger.log("Server certificate verification successful from " + socket);
            } else {
                socket.close();
                throw new Exception();
            }
        } catch (Exception exception) {
            System.out.println("Server certificate verification failed!");
        }
    }

    public void forward(Socket socket, String targetHost, String targetPort) {
        HandshakeMessage toServer = new HandshakeMessage();
        try {
            toServer.putParameter("MessageType", "Forward");
            toServer.send(socket);
            toServer.putParameter("TargetHost", targetHost);
            toServer.send(socket);
            toServer.putParameter("TargetPort", targetPort);
            toServer.send(socket);
            Logger.log("Forward message sent to " + socket);
        } catch (Exception exception) {
            System.out.println("Forward message sending failed!");
            exception.printStackTrace();
        }
    }

    public void receiveForward(Socket clientSocket) {
        HandshakeMessage fromClient = new HandshakeMessage();
        try {
            fromClient.receive(clientSocket);
            if (fromClient.getParameter("MessageType").equals("Forward")) {
                fromClient.receive(clientSocket);
                targetHost = fromClient.getParameter("TargetHost");
                fromClient.receive(clientSocket);
                targetPort = Integer.valueOf(fromClient.getParameter("TargetPort"));
                Logger.log("Forwarding set up to: " + targetHost + ":" + targetPort);
            } else {
                clientSocket.close();
                throw new Exception();
            }
        } catch (Exception exception) {
            System.out.println("Forward message handling failed!");
            exception.printStackTrace();
        }
    }

    public void session(Socket clientSocket) {
        HandshakeMessage toClient = new HandshakeMessage();
        try {
            toClient.putParameter("MessageType", "Session");
            toClient.send(clientSocket);

            sessionKey = new SessionKey(128);
            SecureRandom randomByteGenerator = new SecureRandom();
            iv = new IvParameterSpec(randomByteGenerator.generateSeed(16));

            PublicKey clientPublicKey = clientCert.getPublicKey();
            System.out.println(clientCert.getSubjectDN());
            HandshakeCrypto handshakeCrypto = new HandshakeCrypto();

            System.out.println("This is the session key in clear: " + sessionKey.encodeKey());
            byte[] encryptedSessionKey = handshakeCrypto.encrypt(sessionKey.encodeKey().getBytes(), clientPublicKey);
            System.out.println("this is the session key about to be sent: " + Base64.getEncoder().encodeToString(encryptedSessionKey));

            toClient.putParameter("SessionKey", Base64.getEncoder().encodeToString(encryptedSessionKey));
            toClient.send(clientSocket);

//            byte[] encryptedSessionIv = handshakeCrypto.encrypt(iv.getIV(), clientCertificate.getPublicKey());

//            toClient.putParameter("SessionIV", Base64.getEncoder().encodeToString(encryptedSessionIv));
//            toClient.send(clientSocket);

            System.out.println("Sent all the stuff to the client");

        } catch (Exception exception) {
            System.out.println("Session message sending failed!");
            exception.printStackTrace();
        }
    }

    public void receiveSession(Socket socket, String privateKeyFile) {
        HandshakeMessage fromServer = new HandshakeMessage();
        try {
            fromServer.receive(socket);
            if (fromServer.getParameter("MessageType").equals("Session")) {
                PrivateKey clientsPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(privateKeyFile);
                Cipher cipherKey = Cipher.getInstance("RSA");
                Cipher cipherIV = Cipher.getInstance("RSA");
                cipherKey.init(Cipher.DECRYPT_MODE, clientsPrivateKey);
                cipherIV.init(Cipher.DECRYPT_MODE, clientsPrivateKey);

                fromServer.receive(socket);
                String sessionKeyString = fromServer.getParameter("SessionKey");


                byte[] decryptedSessionKeyAsBytes = cipherKey.doFinal(Base64.getDecoder().decode(sessionKeyString));

                System.out.println("This is the decrypted key " + new String(decryptedSessionKeyAsBytes));


                fromServer.receive(socket);
                String sessionIvString = fromServer.getParameter("SessionIV");

                byte[] decryptedIVAsBytes = cipherIV.doFinal(Base64.getDecoder().decode(sessionIvString));
                String decryptedSessionKeyAsString = new String(decryptedSessionKeyAsBytes);

                sessionKey = new SessionKey(decryptedSessionKeyAsString);
                iv = new IvParameterSpec(decryptedIVAsBytes);

                System.out.println("Handshake complete!");

            } else {
                socket.close();
                throw new Exception();
            }
        } catch (Exception exception) {

        }
    }

    // if the server agrees to do port forwarding to the destination, it
    // will set up the session. For this the server needs to generate
    // session key and IV. Server creates a socket end point, and returns
    // the corresponding TCP port number.


    public String getTargetHost() {
        return targetHost;
    }

    public int getTargetPort() {
        return targetPort;
    }

    public String getServerHost() {
        return serverHost;
    }

    public int getServerPort() {
        return serverPort;

    }
}