package com.psbdx.netshield;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** DNS-over-TLS (RFC 7858) upstream client. */
public final class DoTClient {
    private DoTClient() {}

    private static final int TIMEOUT_MS = 5000;

    public static byte[] query(String host, int port, byte[] queryPacket, int length) {
        Socket socket = null;
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            // Layer TLS over a connected plain socket so the SNI/verification hostname is the configured host.
            Socket plain = new Socket();
            plain.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            plain.setSoTimeout(TIMEOUT_MS);
            SSLSocket ssl = (SSLSocket) factory.createSocket(plain, host, port, true);
            socket = ssl;

            // The JDK does not check the certificate hostname for raw SSLSockets unless asked to.
            SSLParameters params = ssl.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            ssl.setSSLParameters(params);
            ssl.startHandshake();

            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            dos.writeShort(length); // 2-byte length prefix
            dos.write(queryPacket, 0, length);
            dos.flush();

            DataInputStream dis = new DataInputStream(socket.getInputStream());
            int responseLength = dis.readUnsignedShort();
            if (responseLength > 0) {
                byte[] response = new byte[responseLength];
                dis.readFully(response);
                return response;
            }
        } catch (Exception ignored) {
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (Exception ignored) {
                }
            }
        }
        return null;
    }
}
