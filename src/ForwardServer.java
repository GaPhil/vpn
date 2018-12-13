import crypto_utils.*;
import utils.Arguments;
import utils.Logger;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;

import static crypto_utils.VerifyCertificate.certificateToString;
import static crypto_utils.VerifyCertificate.verifyCertificate;

/**
 * Port forwarding server. Forward data between two TCP ports. Based on Nakov
 * TCP Socket Forward Server and adapted for IK2206.
 * <p>
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */
public class ForwardServer {
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;


    private ServerSocket handshakeSocket;

    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;

    /**
     * Do handshake negotiation with client to authenticate, learn
     * target host/port, etc.
     */
    private void doHandshake() throws UnknownHostException, IOException, Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        X509Certificate clientCertificate = null;

        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* This is where the handshake should take place */

        System.out.println("Handling handshake from client!");

        try {
            HandshakeMessage receiveClientHello = new HandshakeMessage();
            receiveClientHello.receive(clientSocket);
            receiveClientHello.getParameter("MessageType");
            receiveClientHello.receive(clientSocket);
            String cert = receiveClientHello.getParameter("Certificate");
            clientCertificate = VerifyCertificate.createCertificate(cert);
            verifyCertificate("ca.pem", clientCertificate);
            Logger.log("Client certificate verification successful from " + clientHostPort);
        } catch (Exception exception) {
            System.out.println("Client certificate verification failed!");
        }
        try {
            HandshakeMessage serverHello = new HandshakeMessage();
            serverHello.putParameter("MessageType", "ServerHello");
            serverHello.send(clientSocket);
            X509Certificate serverCertificate = VerifyCertificate.readCertificate("server.pem");
            serverHello.putParameter("Certificate", certificateToString(serverCertificate));
            serverHello.send(clientSocket);
            Logger.log("ServerHello message sent to " + clientHostPort);
        } catch (Exception exception) {
            System.out.println("ServerHello message sending failed!");
            exception.printStackTrace();
        }


        // if the server agrees to do port forwarding to the destination, it
        // will set up the session. For this the server needs to generate
        // session key and IV. Server creates a socket end point, and returns
        // the corresponding TCP port number.

        try {
            HandshakeMessage receiveForward = new HandshakeMessage();
            receiveForward.receive(clientSocket);
            receiveForward.getParameter("MessageType");
            receiveForward.receive(clientSocket);
            targetHost = receiveForward.getParameter("TargetHost");
            receiveForward.receive(clientSocket);
            targetPort = Integer.valueOf(receiveForward.getParameter("TargetPort"));
            Logger.log("Forwarding set up to: " + targetHost + ":" + targetPort);
        } catch (Exception exception) {
            System.out.println("Forward message handling failed!");
            exception.printStackTrace();
        }
        try {
            HandshakeMessage session = new HandshakeMessage();
            session.putParameter("MessageType", "Session");
            session.send(clientSocket);
            SessionEncrypter sessionEncrypter = new SessionEncrypter(128);
            HandshakeCrypto handshakeCrypto = new HandshakeCrypto();
            byte[] encryptedSessionKey = handshakeCrypto.encrypt(sessionEncrypter.encodeKey(), clientCertificate.getPublicKey());
            String sessionKey = new String(encryptedSessionKey);
            session.putParameter("SessionKey", sessionKey);
            session.send(clientSocket);
            byte[] encryptedSessionIv = handshakeCrypto.encrypt(sessionEncrypter.encodeIV(), clientCertificate.getPublicKey());
            String sessionIv = new String(encryptedSessionIv);
            session.putParameter("SessionIV", sessionIv);
            session.send(clientSocket);

            listenSocket = new ServerSocket();
            listenSocket.bind(new InetSocketAddress(Handshake.serverHost, Handshake.serverPort));

            session.putParameter("ServerHost", listenSocket.getInetAddress().toString());
            session.send(clientSocket);

            session.putParameter("ServerPort", Integer.toString(listenSocket.getLocalPort()));
        } catch (Exception exception) {
            System.out.println("Session message sending failed!");
            exception.printStackTrace();
        }

        clientSocket.close();

        /*
         * Fake the handshake result with static parameters.
         */

        /* listenSocket is a new socket where the ForwardServer waits for the
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         * Here, we use a static address instead (serverHost/serverPort).
         * (This may give "Address already in use" errors, but that's OK for now.)
         */
//        listenSocket = new ServerSocket();
//        listenSocket.bind(new InetSocketAddress(Handshake.serverHost, Handshake.serverPort));

        /* The final destination. The ForwardServer sets up port forwarding
         * between the listensocket (ie., ServerHost/ServerPort) and the target.
         */
        targetHost = Handshake.targetHost;
        targetPort = Handshake.targetPort;
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
            throws Exception {

        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
            throw new IOException("Unable to bind to port " + port);
        }

        log("Forward Server started on TCP port " + port);

        // Accept client connections and process them until stopped
        while (true) {
            ForwardServerClientThread forwardThread;
            try {

                doHandshake();

                forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort);
                forwardThread.start();
            } catch (IOException e) {
                throw e;
            }
        }
    }

    /**
     * Prints given log message on the standard output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage) {
        if (ENABLE_LOGGING)
            System.out.println(aMessage);
    }

    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--serverhost=<hostname>");
        System.err.println(indent + "--serverport=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
    }

    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args) throws Exception {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);

        ForwardServer srv = new ForwardServer();
        try {
            srv.startForwardServer();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}