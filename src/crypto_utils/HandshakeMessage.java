package crypto_utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 * Adapted by GaPhil on 2018-12-09 based on psj .
 * <p>
 * Handshake message encoding/decoding and transmission. A Handshake message is
 * represented as a set of parameters <key, value> pair.
 */
public class HandshakeMessage extends Properties {

    /**
     * Returns the value of a key value pair.
     *
     * @param param key as string
     * @return value as string
     */
    public String getParameter(String param) {
        return this.getProperty(param);
    }

    /**
     * Assign a parameter and value.
     *
     * @param param parameter as string
     * @param value value as string
     */
    public void putParameter(String param, String value) {
        this.put(param, value);
    }

    /*
     * Send a handshake message out on a socket
     *
     * Use the built-in encoding of Properties as XML:
     *   - Encode the message in XML
     *   - Convert XML to a byte array, and write the byte array to the socket
     *
     * Prepend the byte array with an integer string with the length of the string.
     * The integer string is terminated by a whitespace.
     */
    public void send(Socket socket) throws IOException {
        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        String comment = "From " + InetAddress.getLocalHost() + ":" + socket.getLocalPort() +
                " to " + socket.getInetAddress().getHostAddress() + ":" + socket.getPort();
        this.storeToXML(byteOutputStream, comment);
        byte[] bytes = byteOutputStream.toByteArray();
        socket.getOutputStream().write(String.format("%d ", bytes.length).getBytes(StandardCharsets.UTF_8));
        socket.getOutputStream().write(bytes);
        socket.getOutputStream().flush();
    }

    /*
     * Receive a handshake message on a socket
     *
     * First read a string with an integer followed by whitespace,
     * which gives the size of the message in bytes. Then read the XML data
     * and convert it to a crypto_utils.HandshakeMessage.
     */
    public void recv(Socket socket) throws IOException {
        int length = 0;
        for (int n = socket.getInputStream().read(); !Character.isWhitespace(n); n = socket.getInputStream().read()) {
            length = length * 10 + Character.getNumericValue(n);
        }
        byte[] data = new byte[length];
        int nread = 0;
        while (nread < length) {
            nread += socket.getInputStream().read(data, nread, length - nread);
        }
        this.loadFromXML(new ByteArrayInputStream(data));
    }
}