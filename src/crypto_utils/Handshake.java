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
            } else throw new Exception();
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
            } else throw new Exception();
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
            } else throw new Exception();
        } catch (Exception exception) {
            System.out.println("Forward message handling failed!");
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