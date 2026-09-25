package com.psbdx.netshield;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

/** Plain UDP upstream client. Servers may be "ip" (port 53), "ip:port" or "[v6]:port". */
public final class DnsUdpClient {
    private DnsUdpClient() {}

    private static final int TIMEOUT_MS = 3000;

    public static byte[] query(String primaryDns, String secondaryDns, byte[] queryPacket, int length) {
        byte[] result = tryQuery(primaryDns, queryPacket, length);
        if (result != null) {
            return result;
        }
        if (secondaryDns != null && !secondaryDns.isEmpty() && !secondaryDns.equals(primaryDns)) {
            return tryQuery(secondaryDns, queryPacket, length);
        }
        return null;
    }

    private static byte[] tryQuery(String server, byte[] queryPacket, int length) {
        if (server == null || server.isEmpty()) return null;
        String host = server;
        int port = 53;
        if (server.startsWith("[")) { // [v6]:port
            int end = server.indexOf(']');
            if (end > 0) {
                host = server.substring(1, end);
                if (server.length() > end + 2 && server.charAt(end + 1) == ':') {
                    port = parsePort(server.substring(end + 2));
                }
            }
        } else if (server.indexOf(':') > 0 && server.indexOf(':') == server.lastIndexOf(':')) { // v4:port
            host = server.substring(0, server.indexOf(':'));
            port = parsePort(server.substring(server.indexOf(':') + 1));
        }
        if (port <= 0) return null;

        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(TIMEOUT_MS);
            InetAddress address = InetAddress.getByName(host);
            socket.send(new DatagramPacket(queryPacket, length, address, port));

            byte[] buffer = new byte[4096];
            DatagramPacket receivePacket = new DatagramPacket(buffer, buffer.length);
            socket.receive(receivePacket);

            byte[] response = new byte[receivePacket.getLength()];
            System.arraycopy(receivePacket.getData(), 0, response, 0, receivePacket.getLength());
            return response;
        } catch (Exception ignored) {
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
        return null;
    }

    private static int parsePort(String s) {
        try {
            int p = Integer.parseInt(s.trim());
            return (p > 0 && p < 65536) ? p : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
