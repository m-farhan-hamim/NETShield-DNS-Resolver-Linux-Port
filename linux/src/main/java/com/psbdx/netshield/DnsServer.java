package com.psbdx.netshield;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Local DNS listener (the Linux equivalent of the Android DnsServerService's
 * "local server" mode): UDP plus TCP on the same address/port. TCP is needed
 * because clients retry over TCP when a UDP answer had to be truncated.
 */
public final class DnsServer {
    private static final int TCP_IDLE_TIMEOUT_MS = 5000;

    private final Config cfg;
    private final Engine engine;
    private final ThreadPoolExecutor pool;
    private DatagramSocket udp;
    private ServerSocket tcp;
    private volatile boolean running;
    private Thread udpThread;
    private Thread tcpThread;

    public DnsServer(Config cfg, Engine engine) {
        this.cfg = cfg;
        this.engine = engine;
        int n = cfg.workerThreads;
        this.pool = new ThreadPoolExecutor(n, n, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<>(2000),
                r -> {
                    Thread t = new Thread(r, "netshield-worker");
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.DiscardPolicy()); // overload: drop queries, clients retry
        this.pool.allowCoreThreadTimeOut(true);
    }

    /** Binds both sockets (throws if the port is taken or not permitted) and starts serving. */
    public void start() throws IOException {
        InetAddress addr = InetAddress.getByName(cfg.listenAddress);
        InetSocketAddress bind = new InetSocketAddress(addr, cfg.port);

        udp = new DatagramSocket(null);
        udp.setReuseAddress(true);
        udp.bind(bind);

        tcp = new ServerSocket();
        tcp.setReuseAddress(true);
        try {
            tcp.bind(bind, 128);
        } catch (IOException e) {
            udp.close();
            throw e;
        }

        running = true;
        udpThread = new Thread(this::udpLoop, "netshield-udp");
        tcpThread = new Thread(this::tcpLoop, "netshield-tcp");
        udpThread.start();
        tcpThread.start();
        Log.info("listening on " + cfg.listenAddress + ":" + cfg.port + " (udp+tcp)");
    }

    public void stop() {
        running = false;
        try {
            if (udp != null) udp.close();
        } catch (Exception ignored) {
        }
        try {
            if (tcp != null) tcp.close();
        } catch (Exception ignored) {
        }
        pool.shutdownNow();
    }

    private void udpLoop() {
        byte[] buffer = new byte[4096];
        while (running && !udp.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                udp.receive(packet);
                final byte[] query = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), 0, query, 0, packet.getLength());
                final InetAddress clientAddr = packet.getAddress();
                final int clientPort = packet.getPort();
                try {
                    pool.execute(() -> handleUdp(query, clientAddr, clientPort));
                } catch (RejectedExecutionException ignored) {
                }
            } catch (IOException e) {
                if (running) Log.warn("udp receive error: " + e.getMessage());
            }
        }
    }

    private void handleUdp(byte[] query, InetAddress clientAddr, int clientPort) {
        try {
            String clientIp = clientAddr != null ? clientAddr.getHostAddress() : "127.0.0.1";
            byte[] response = engine.resolve(query, query.length, clientIp);
            if (response == null || udp.isClosed()) return;
            if (response.length > DnsPacketParser.udpPayloadLimit(query, query.length)) {
                response = DnsPacketParser.buildTruncated(response); // client will retry over TCP
            }
            udp.send(new DatagramPacket(response, response.length, clientAddr, clientPort));
        } catch (Exception ignored) {
        }
    }

    private void tcpLoop() {
        while (running && !tcp.isClosed()) {
            try {
                final Socket s = tcp.accept();
                try {
                    pool.execute(() -> handleTcp(s));
                } catch (RejectedExecutionException e) {
                    closeQuietly(s);
                }
            } catch (IOException e) {
                if (running) Log.warn("tcp accept error: " + e.getMessage());
            }
        }
    }

    private void handleTcp(Socket s) {
        try {
            s.setSoTimeout(TCP_IDLE_TIMEOUT_MS);
            String clientIp = s.getInetAddress() != null ? s.getInetAddress().getHostAddress() : "127.0.0.1";
            DataInputStream in = new DataInputStream(s.getInputStream());
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            while (running) {
                int len;
                try {
                    len = in.readUnsignedShort();
                } catch (java.io.EOFException | java.net.SocketTimeoutException e) {
                    break; // client done / idle
                }
                if (len < 12) break;
                byte[] query = new byte[len];
                in.readFully(query);
                byte[] response = engine.resolve(query, len, clientIp);
                if (response == null) break;
                out.writeShort(response.length);
                out.write(response);
                out.flush();
            }
        } catch (Exception ignored) {
        } finally {
            closeQuietly(s);
        }
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (Exception ignored) {
        }
    }
}
