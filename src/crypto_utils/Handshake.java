package crypto_utils;


import utils.Logger;

import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
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

    HandshakeMessage handshakeMessage = new HandshakeMessage();

    public void clientHello(Socket socket, String certFile) {
        try {
            handshakeMessage.putParameter("MessageType", "ClientHello");
            handshakeMessage.send(socket);
            X509Certificate certificate = VerifyCertificate.readCertificate(certFile);
            handshakeMessage.putParameter("Certificate", certificateToString(certificate));
            handshakeMessage.send(socket);
            Logger.log("ClientHello message sent to " + socket);
        } catch (Exception exception) {
            System.out.println("ClientHello message sending failed!");
        }
    }

    public void receiveClientHello(Socket clientSocket, String caFile) {
        try {
            handshakeMessage.receive(clientSocket);
            if (handshakeMessage.getParameter("MessageType").equals("ClientHello")) {
                handshakeMessage.receive(clientSocket);
                String cert = handshakeMessage.getParameter("Certificate");
                X509Certificate clientCertificate = VerifyCertificate.createCertificate(cert);
                verifyCertificate(caFile, clientCertificate);
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
        try {
            handshakeMessage.putParameter("MessageType", "ServerHello");
            handshakeMessage.send(clientSocket);
            X509Certificate serverCertificate = VerifyCertificate.readCertificate(certFile);
            handshakeMessage.putParameter("Certificate", certificateToString(serverCertificate));
            handshakeMessage.send(clientSocket);
            Logger.log("ServerHello message sent to " + clientSocket);
        } catch (Exception exception) {
            System.out.println("ServerHello message sending failed!");
            exception.printStackTrace();
        }
    }

    public void receiveServerHello(Socket socket, String cacert) {
        try {
            handshakeMessage.receive(socket);
            if (handshakeMessage.getParameter("MessageType").equals("ServerHello")) {
                handshakeMessage.receive(socket);
                String cert = handshakeMessage.getParameter("Certificate");
                X509Certificate certificate = VerifyCertificate.createCertificate(cert);
                verifyCertificate(cacert, certificate);
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
        try {
            handshakeMessage.putParameter("MessageType", "Forward");
            handshakeMessage.send(socket);
            handshakeMessage.putParameter("TargetHost", targetHost);
            handshakeMessage.send(socket);
            handshakeMessage.putParameter("TargetPort", targetPort);
            handshakeMessage.send(socket);
            Logger.log("Forward message sent to " + socket);
        } catch (Exception exception) {
            System.out.println("Forward message sending failed!");
            exception.printStackTrace();
        }
    }

    public void receiveForward(Socket clientSocket) {
        try {
            handshakeMessage.receive(clientSocket);
            if (handshakeMessage.getParameter("MessageType").equals("Forward")) {
                handshakeMessage.receive(clientSocket);
                targetHost = handshakeMessage.getParameter("TargetHost");
                handshakeMessage.receive(clientSocket);
                targetPort = Integer.valueOf(handshakeMessage.getParameter("TargetPort"));
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


    public void session(Socket clientSocket, String certFile) {
        try {
            handshakeMessage.putParameter("MessageType", "Session");
            handshakeMessage.send(clientSocket);
            SessionEncrypter sessionEncrypter = new SessionEncrypter(128);
            HandshakeCrypto handshakeCrypto = new HandshakeCrypto();
            X509Certificate clientCertificate = VerifyCertificate.createCertificate(certFile);
            PublicKey clientPublicKey = clientCertificate.getPublicKey();
            byte[] encryptedSessionKey = handshakeCrypto.encrypt(sessionEncrypter.encodeStringKey().getBytes(), clientPublicKey);

            String sessionKey = Base64.getEncoder().encodeToString(encryptedSessionKey);

            handshakeMessage.putParameter("SessionKey", sessionKey);
            handshakeMessage.send(clientSocket);


            byte[] encryptedSessionIv = handshakeCrypto.encrypt(sessionEncrypter.encodeIv(), clientCertificate.getPublicKey());
            String sessionIv = Base64.getEncoder().encodeToString(encryptedSessionIv);
            handshakeMessage.putParameter("SessionIV", sessionIv);
            handshakeMessage.send(clientSocket);

            System.out.println("Plain text key: " + sessionEncrypter.encodeStringKey());
            System.out.println("Plain text vi: " + sessionEncrypter.encodeStringIv());
            System.out.println("Sent the following encrypted session key: " + sessionKey);
            System.out.println("Sent the following encrypted session iv: " + sessionIv);

            System.out.println("Session message sending done!");

        } catch (Exception exception) {
            System.out.println("Session message sending failed!");
            exception.printStackTrace();
        }

    }


    // if the server agrees to do port forwarding to the destination, it
    // will set up the session. For this the server needs to generate
    // session key and IV. Server creates a socket end point, and returns
    // the corresponding TCP port number.


//
//
//
//        try
//
//    {
//        HandshakeMessage receiveSession = new HandshakeMessage();
//        receiveSession.receive(socket);
//        receiveSession.getParameter("MessageType");
//
//        receiveSession.receive(socket);
//        String encryptedSessionKey = receiveSession.getParameter("SessionKey");
//        System.out.println("This enc key arrived: " + encryptedSessionKey);
//
//        HandshakeCrypto handshakeCrypto = new HandshakeCrypto();
//
//        PrivateKey privateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key"));
//
//
////            String decodeSessionKey = new String(Base64.getDecoder().decode(encryptedSessionKey));
//
////            System.out.println("Decoded session key: \n" + decodeSessionKey);
//
////            System.out.println("The bytes are: " + Arrays.toString(decodeSessionKey.getBytes("UTF-8")));
//
//
//        System.out.println("The key is: " + Arrays.toString(privateKey.getEncoded()));
//
//
//        // TODO: FAILURE POINT - DECRYPTION NOT WORKING
//        byte[] sessionKey = handshakeCrypto.decrypt(Base64.getDecoder().decode(encryptedSessionKey), privateKey);
//
//
//        System.out.println("decryption worked");
//
//
////            String sessionKeys = new String(Base64.getDecoder().decode(encryptedSessionKey.getBytes()));
//
//
////            System.out.println("This is the decrypted session key: " + sessionKeys);
//
////            byte[] encryptedSessionKey = handshakeCrypto.encrypt(sessionDecrypter..encodeStringKey().getBytes(), clientCertificate.getPublicKey());
//
//
//        System.out.println("Getting keys now3");
//        receiveSession.receive(socket);
//        String encryptedIv = receiveSession.getParameter("SessionIV");
//        byte[] sessionIv = handshakeCrypto.decrypt(encryptedIv.getBytes(), privateKey);
//        SessionDecrypter sessionDecrypter = new SessionDecrypter(Arrays.toString(sessionKey), Arrays.toString(sessionIv));
//
////            System.out.println("Successful decryption of shit: " + sessionDecrypter.encodeKey() + sessionDecrypter.encodeIv());
//
//        System.out.println("Plain text key: " + sessionDecrypter.encodeStringKey());
//        System.out.println("Plaing text vi: " + sessionDecrypter.encodeStringIv());
//        System.out.println("Sent the following encrypted session key: " + sessionKey);
//        System.out.println("Sent the following encrypted session iv: " + sessionIv);
//
//    } catch(
//    Exception exception)
//
//    {
//
//    }


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