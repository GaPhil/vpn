package crypto_utils;

import utils.Logger;

import javax.crypto.spec.IvParameterSpec;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static crypto_utils.VerifyCertificate.certificateToString;
import static crypto_utils.VerifyCertificate.verifyCertificate;

/**
 * Created by GaPhil on 2018-12-09.
 */
public class Handshake {

    private String targetHost;
    private int targetPort;

    private static String serverHost;
    private static int serverPort;

    private HandshakeCrypto handshakeCrypto = new HandshakeCrypto();

    private X509Certificate clientCert;
    private X509Certificate serverCert;
    //    public SessionKey sessionKey;
    public IvParameterSpec ivParameterSpec;

    public byte[] sessionKey;
    public byte[] sessionIv;


    public void clientHello(Socket socket, String certFile) {
        HandshakeMessage toServer = new HandshakeMessage();
        try {
            clientCert = VerifyCertificate.readCertificate(certFile);
            toServer.putParameter("MessageType", "ClientHello");
//            toServer.send(socket);
            toServer.putParameter("Certificate", certificateToString(clientCert));
            toServer.send(socket);
            Logger.log("ClientHello message sent to " + socket);
        } catch (Exception exception) {
            System.out.println("ClientHello message sending failed!");
            exception.printStackTrace();
        }
    }

    public void receiveClientHello(Socket clientSocket, String caFile) {
        HandshakeMessage fromClient = new HandshakeMessage();
        try {
            fromClient.receive(clientSocket);
            if (fromClient.getParameter("MessageType").equals("ClientHello")) {

                // fromClient.receive(clientSocket);
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
            exception.printStackTrace();
        }
    }

    public void serverHello(Socket clientSocket, String certFile) {
        HandshakeMessage toClient = new HandshakeMessage();
        try {
            toClient.putParameter("MessageType", "ServerHello");
//            toClient.send(clientSocket);
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
//                fromServer.receive(socket);
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
            exception.printStackTrace();
        }
    }

    public void forward(Socket socket, String targetHost, String targetPort) {
        HandshakeMessage toServer = new HandshakeMessage();
        try {
            toServer.putParameter("MessageType", "Forward");
//            toServer.send(socket);
            toServer.putParameter("TargetHost", targetHost);
//            toServer.send(socket);
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
//                fromClient.receive(clientSocket);
                targetHost = fromClient.getParameter("TargetHost");
//                fromClient.receive(clientSocket);
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

    public void session(Socket clientSocket, String serverHost, int serverPort) {
        HandshakeMessage toClient = new HandshakeMessage();
        try {
            PublicKey clientPublicKey = clientCert.getPublicKey();
            SessionEncrypter sessionEncrypter = new SessionEncrypter(128);
            sessionKey = sessionEncrypter.getSecretKey();
            sessionIv = sessionEncrypter.getIV();


            byte[] encryptedSessionKey = HandshakeCrypto.encrypt(sessionKey, clientPublicKey);
            byte[] encryptedSessionIv = HandshakeCrypto.encrypt(sessionIv, clientPublicKey);

            toClient.putParameter("MessageType", "Session");
            toClient.putParameter("SessionKey", Base64.getEncoder().encodeToString(encryptedSessionKey));
            toClient.putParameter("SessionIV", Base64.getEncoder().encodeToString(encryptedSessionIv));
            toClient.putParameter("ServerHost", serverHost);
            toClient.putParameter("ServerPort", String.valueOf(serverPort));
            toClient.send(clientSocket);
            Logger.log("Session message sent");
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

                byte[] decodedSessionKey = Base64.getDecoder().decode(fromServer.getParameter("SessionKey"));
                byte[] decodedSessionIV = Base64.getDecoder().decode(fromServer.getParameter("SessionIV"));

                sessionKey = HandshakeCrypto.decrypt(decodedSessionKey, clientsPrivateKey);
                sessionIv = HandshakeCrypto.decrypt(decodedSessionIV, clientsPrivateKey);

                serverHost = fromServer.getParameter("ServerHost");
                serverPort = Integer.valueOf(fromServer.getParameter("ServerPort"));

            } else {
                socket.close();
                throw new Exception();
            }
        } catch (Exception exception) {
            System.out.println("Session message receiving failed!");
            exception.printStackTrace();
        }
    }

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
