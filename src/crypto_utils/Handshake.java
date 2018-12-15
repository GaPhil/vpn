package crypto_utils;

import utils.Logger;

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

    private String targetHost;
    private int targetPort;

    private static String serverHost;
    private static int serverPort;

    private HandshakeCrypto handshakeCrypto = new HandshakeCrypto();

    private X509Certificate clientCert;
    private X509Certificate serverCert;
    private SessionKey sessionKey;
    private IvParameterSpec iv;

    public void clientHello(Socket socket, String certFile) {
        HandshakeMessage toServer = new HandshakeMessage();
        try {
            clientCert = VerifyCertificate.readCertificate(certFile);
            toServer.putParameter("MessageType", "ClientHello");
            toServer.send(socket);
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
            exception.printStackTrace();
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
            exception.printStackTrace();
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

    public void session(Socket clientSocket, String serverHost, int serverPort) {
        HandshakeMessage toClient = new HandshakeMessage();
        try {
            PublicKey clientPublicKey = clientCert.getPublicKey();
            sessionKey = new SessionKey(128);
            SecureRandom randomByteGenerator = new SecureRandom();
            iv = new IvParameterSpec(randomByteGenerator.generateSeed(16));

            byte[] encryptedSessionKey = handshakeCrypto.encrypt(sessionKey.encodeKey().getBytes(), clientPublicKey);
            byte[] encryptedSessionIv = handshakeCrypto.encrypt(iv.getIV(), clientPublicKey);

            toClient.putParameter("MessageType", "Session");
            toClient.send(clientSocket);
            toClient.putParameter("SessionKey", Base64.getEncoder().encodeToString(encryptedSessionKey));
            toClient.send(clientSocket);
            toClient.putParameter("SessionIV", Base64.getEncoder().encodeToString(encryptedSessionIv));
            toClient.send(clientSocket);

            toClient.putParameter("ServerHost", serverHost);
            toClient.send(clientSocket);
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
                fromServer.receive(socket);
                String sessionKeyString = fromServer.getParameter("SessionKey");
                fromServer.receive(socket);
                String sessionIvString = fromServer.getParameter("SessionIV");
                fromServer.receive(socket);
                serverHost = fromServer.getParameter("ServerHost");
                fromServer.receive(socket);
                serverPort = Integer.valueOf(fromServer.getParameter("ServerPort"));

                PrivateKey clientsPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(privateKeyFile);
                byte[] decryptedSessionKey = handshakeCrypto.decrypt(Base64.getDecoder().decode(sessionKeyString), clientsPrivateKey);
                byte[] decryptedIv = handshakeCrypto.decrypt(Base64.getDecoder().decode(sessionIvString), clientsPrivateKey);

                sessionKey = new SessionKey(new String(decryptedSessionKey));
                iv = new IvParameterSpec(decryptedIv);
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
