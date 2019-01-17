import crypto_utils.Handshake;
import crypto_utils.SessionDecrypter;
import crypto_utils.SessionEncrypter;
import utils.Arguments;
import utils.Logger;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

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

    private SessionDecrypter sessionDecrypter;
    private SessionEncrypter sessionEncrypter;


    public static Handshake handshake = new Handshake();


    /**
     * Do handshake negotiation with client to authenticate, learn
     * target host/port, etc.
     */
    private void doHandshake() throws Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();

        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* This is where the handshake should take place */

        System.out.println("Handling handshake from client!");

        handshake.receiveClientHello(clientSocket, arguments.get("cacert"));
        handshake.serverHello(clientSocket, arguments.get("usercert"));
        handshake.receiveForward(clientSocket);

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
        listenSocket = new ServerSocket(0, 10, InetAddress.getLocalHost());

        handshake.session(clientSocket, InetAddress.getLocalHost().getHostAddress(), listenSocket.getLocalPort());

        System.out.println("Handshake done!");

        clientSocket.close();


        /* The final destination. The ForwardServer sets up port forwarding
         * between the listensocket (ie., ServerHost/ServerPort) and the target.
         */
        targetHost = handshake.getTargetHost();
        targetPort = handshake.getTargetPort();

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

                forwardThread = new ForwardServerClientThread(listenSocket, targetHost, targetPort, handshake.sessionKey, handshake.sessionIv);
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