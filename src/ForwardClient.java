import crypto_utils.Handshake;
import crypto_utils.HandshakeMessage;
import crypto_utils.VerifyCertificate;
import utils.Arguments;
import utils.Logger;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;

import static crypto_utils.VerifyCertificate.certificateToString;
import static crypto_utils.VerifyCertificate.verifyCertificate;

/**
 * Port forwarding client. Forward data between two TCP ports. Based on Nakov
 * TCP Socket Forward Server and adapted for IK2206.
 * <p>
 * See original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */
public class ForwardClient {
    private static final boolean ENABLE_LOGGING = true;
    private static final int DEFAULTSERVERPORT = 2206;
    private static final String DEFAULTSERVERHOST = "localhost";
    private static final String PROGRAMNAME = "ForwardClient";

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;

    private static void doHandshake() throws IOException {

        /* Connect to forward server server */
        System.out.println("Connect to " + arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        /* This is where the handshake should take place */
        System.out.println("Initialising handshake to server! ");

        try {
            HandshakeMessage clientHello = new HandshakeMessage();
            clientHello.putParameter("MessageType", "ClientHello");
            clientHello.send(socket);
            X509Certificate certificate = VerifyCertificate.readCertificate("client.pem");
            clientHello.putParameter("Certificate", certificateToString(certificate));
            clientHello.send(socket);
            Logger.log("ClientHello message sent to " + socket);
        } catch (Exception exception) {
            System.out.println("ClientHello message sending failed!");
        }
        try {
            HandshakeMessage receiveServerHello = new HandshakeMessage();
            receiveServerHello.receive(socket);
            receiveServerHello.getParameter("MessageType");
            receiveServerHello.receive(socket);
            String cert = receiveServerHello.getParameter("Certificate");
            X509Certificate certificate = VerifyCertificate.createCertificate(cert);
            verifyCertificate("ca.pem", certificate);
            Logger.log("Server certificate verification successful from " + socket);
        } catch (Exception exception) {
            System.out.println("Server certificate verification failed!");
        }
        try {
            serverHost = Handshake.serverHost;
            serverPort = Handshake.serverPort;
            HandshakeMessage forward = new HandshakeMessage();
            forward.putParameter("MessageType", "Forward");
            forward.send(socket);
            forward.putParameter("TargetHost", serverHost);
            forward.send(socket);
            forward.putParameter("TargetPort", Integer.toString(serverPort));
            forward.send(socket);
            Logger.log("Forward message sent to " + socket);
        } catch (Exception exception) {
            System.out.println("Forward message sending failed!");
            exception.printStackTrace();
        }




        socket.close();

        /*
         * Fake the handshake result with static parameters.
         */

        /* This is to where the ForwardClient should connect.
         * The ForwardServer creates a socket
         * dynamically and communicates the address (hostname and port number)
         * to ForwardClient during the handshake (ServerHost, ServerPort parameters).
         * Here, we use a static address instead.
         */
        serverHost = Handshake.serverHost;
        serverPort = Handshake.serverPort;
    }

    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }

    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static private void startForwardClient() throws IOException {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;

        try {
            /* Create a new socket. This is to where the user should connect.
             * ForwardClient sets up port forwarding between this socket
             * and the ServerHost/ServerPort learned from the handshake */
            listensocket = new ServerSocket();
            /* Let the system pick a port number */
            listensocket.bind(null);
            /* Tell the user, so the user knows where to connect */
            tellUser(listensocket);

            Socket clientSocket = listensocket.accept();
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            log("Accepted client from " + clientHostPort);

            forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort);
            forwardThread.start();

        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            throw e;
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    static void log(String aMessage) {
        if (ENABLE_LOGGING)
            System.out.println(aMessage);
    }

    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
    }

    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args) {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch (IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        try {
            startForwardClient();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}