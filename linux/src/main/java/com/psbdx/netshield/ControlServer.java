package com.psbdx.netshield;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Locale;

/**
 * Line-based admin protocol on a Unix domain socket (default /run/netshield/control.sock,
 * mode 0660, group netshield). One command per connection; the reply is plain text.
 * This replaces the Android app's UI, notification actions, Quick Settings tile and widgets.
 */
public final class ControlServer {
    /** Callbacks into the daemon for things the control socket can trigger. */
    public interface Handler {
        String status();
        String reload();
        String sync();
    }

    private final Path socketPath;
    private final RuleSet rules;
    private final Engine engine;
    private final QueryLog queryLog;
    private final Handler handler;
    private ServerSocketChannel server;
    private volatile boolean running;
    private Thread thread;

    public ControlServer(Path socketPath, RuleSet rules, Engine engine, QueryLog queryLog, Handler handler) {
        this.socketPath = socketPath;
        this.rules = rules;
        this.engine = engine;
        this.queryLog = queryLog;
        this.handler = handler;
    }

    public void start() throws IOException {
        Path parent = socketPath.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        Files.deleteIfExists(socketPath); // stale socket from an unclean exit

        server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        server.bind(UnixDomainSocketAddress.of(socketPath));
        try {
            Files.setPosixFilePermissions(socketPath, PosixFilePermissions.fromString("rw-rw----"));
        } catch (Exception e) {
            Log.warn("cannot chmod control socket: " + e.getMessage());
        }
        running = true;
        thread = new Thread(this::loop, "netshield-control");
        thread.setDaemon(true);
        thread.start();
        Log.info("control socket at " + socketPath);
    }

    public void stop() {
        running = false;
        try {
            if (server != null) server.close();
        } catch (Exception ignored) {
        }
        try {
            Files.deleteIfExists(socketPath);
        } catch (Exception ignored) {
        }
    }

    private void loop() {
        while (running) {
            try {
                SocketChannel ch = server.accept();
                Thread t = new Thread(() -> serve(ch), "netshield-control-conn");
                t.setDaemon(true);
                t.start();
            } catch (IOException e) {
                if (running) Log.warn("control accept error: " + e.getMessage());
            }
        }
    }

    private void serve(SocketChannel ch) {
        try (SocketChannel c = ch) {
            BufferedReader in = new BufferedReader(new InputStreamReader(Channels.newInputStream(c), StandardCharsets.UTF_8));
            OutputStream os = Channels.newOutputStream(c);
            PrintWriter out = new PrintWriter(new java.io.OutputStreamWriter(os, StandardCharsets.UTF_8), true);
            String line = in.readLine();
            if (line == null) return;
            out.println(execute(line.trim()));
            out.flush();
        } catch (Exception ignored) {
        }
    }

    String execute(String line) {
        String[] parts = line.split("\\s+", 2);
        String cmd = parts[0].toLowerCase(Locale.ROOT);
        String arg = parts.length > 1 ? parts[1].trim() : "";
        try {
            switch (cmd) {
                case "status":
                    return handler.status();
                case "pause": {
                    long secs = arg.isEmpty() ? 300 : Long.parseLong(arg);
                    if (secs <= 0 || secs > 7 * 24 * 3600) return "error: pause seconds must be 1..604800";
                    rules.pauseProtection(secs * 1000L);
                    return "protection paused for " + secs + "s";
                }
                case "resume":
                    rules.resumeProtection();
                    return "protection resumed";
                case "reload":
                    return handler.reload();
                case "sync":
                    return handler.sync();
                case "flush":
                    engine.getCache().clear();
                    return "cache cleared";
                case "check":
                    return rules.explain(arg);
                case "logs": {
                    if (!queryLog.isEnabled()) return "query logging is disabled (log_queries=false)";
                    int n = arg.isEmpty() ? 20 : Math.min(500, Math.max(1, Integer.parseInt(arg)));
                    List<String> lines = queryLog.tail(n);
                    return lines.isEmpty() ? "(no queries yet)" : String.join("\n", lines);
                }
                default:
                    return "error: unknown command '" + cmd + "' (status, pause, resume, reload, sync, flush, check, logs)";
            }
        } catch (NumberFormatException e) {
            return "error: expected a number";
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }
}
