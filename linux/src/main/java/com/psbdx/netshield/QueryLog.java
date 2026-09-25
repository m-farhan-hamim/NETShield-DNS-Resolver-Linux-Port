package com.psbdx.netshield;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Replacement for the Android app's SQLite dns_logs table: an asynchronous,
 * size-rotated TSV file plus a small in-memory tail for {@code netshield logs}.
 * Columns: time, client, status, type, domain, latency_ms, upstream.
 * If logging is disabled nothing is written and nothing is kept.
 */
public final class QueryLog {
    private static final int TAIL_SIZE = 500;
    private static final int QUEUE_CAPACITY = 20000;

    private final boolean enabled;
    private final Path file;
    private final long maxBytes;
    private final BlockingQueue<String> queue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
    private final Deque<String> tail = new ArrayDeque<>();
    private volatile boolean running = true;
    private Thread writer;

    public QueryLog(Config cfg) {
        this.enabled = cfg.logQueries;
        this.file = cfg.logDir.resolve("queries.log");
        this.maxBytes = cfg.logMaxBytes;
        if (enabled) {
            try {
                Files.createDirectories(cfg.logDir);
            } catch (IOException e) {
                Log.warn("cannot create log dir " + cfg.logDir + ": " + e.getMessage());
            }
            writer = new Thread(this::writeLoop, "netshield-querylog");
            writer.setDaemon(true);
            writer.start();
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void log(String domain, String type, String status, long latencyMs, String upstream, String clientIp) {
        if (!enabled) return;
        String line = Instant.now() + "\t" + clientIp + "\t" + status + "\t" + type + "\t"
                + domain + "\t" + latencyMs + "ms\t" + upstream;
        synchronized (tail) {
            tail.addLast(line);
            while (tail.size() > TAIL_SIZE) tail.removeFirst();
        }
        queue.offer(line); // never block a DNS answer on disk; drop if the writer is far behind
    }

    public List<String> tail(int n) {
        synchronized (tail) {
            List<String> all = new ArrayList<>(tail);
            int from = Math.max(0, all.size() - Math.max(1, n));
            return all.subList(from, all.size());
        }
    }

    public void close() {
        running = false;
        if (writer != null) {
            writer.interrupt();
            try {
                writer.join(2000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void writeLoop() {
        BufferedWriter out = null;
        try {
            out = open();
            while (running || !queue.isEmpty()) {
                String line;
                try {
                    line = queue.take();
                } catch (InterruptedException e) {
                    // shutting down: drain what is left
                    line = queue.poll();
                    if (line == null) break;
                }
                if (out == null) out = open();
                if (out == null) continue;
                out.write(line);
                out.newLine();
                if (queue.isEmpty()) out.flush();
                if (Files.size(file) > maxBytes) {
                    out.close();
                    Files.move(file, file.resolveSibling("queries.log.1"), StandardCopyOption.REPLACE_EXISTING);
                    out = open();
                }
            }
        } catch (Exception e) {
            Log.warn("query log writer stopped: " + e.getMessage());
        } finally {
            if (out != null) {
                try {
                    out.flush();
                    out.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    private BufferedWriter open() {
        try {
            return Files.newBufferedWriter(file, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            Log.warn("cannot open " + file + ": " + e.getMessage());
            return null;
        }
    }
}
