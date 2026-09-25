package com.psbdx.netshield;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

/**
 * Daemon configuration, loaded from a java-properties style file
 * (default /etc/netshield/netshield.conf). The keys mirror the Android app's
 * SharedPreferences ("dns_prefs") so the two stay recognisable side by side.
 * Instances are immutable; a reload builds a new one.
 */
public final class Config {
    public final Path configFile;
    public final Path configDir;

    // Listener (Android: server_port / server_listen_all_interfaces)
    public final String listenAddress;
    public final int port;
    public final int workerThreads;

    // Upstream (Android: upstream_mode, doh_url, dot_host, dot_port, upstream_primary/secondary)
    public final String upstreamMode; // DOH | DOT | UDP
    public final String dohUrl;
    public final String dotHost;
    public final int dotPort;
    public final String upstreamPrimary;
    public final String upstreamSecondary;
    public final boolean fallbackUdp;
    public final String fallbackPrimary;
    public final String fallbackSecondary;

    // Behaviour (Android: block_action, cache_enabled)
    public final String blockAction; // ZERO_IP | NXDOMAIN
    public final boolean cacheEnabled;
    public final int cacheSize;

    // Per-client policy (Android "Hotspot" tab)
    public final Set<String> blockedClients;
    public final int dailyQueryLimit;   // 0 = unlimited (all clients combined)
    public final int clientDailyLimit;  // 0 = unlimited (per client IP)

    // Blocklist syncing
    public final int syncIntervalHours; // 0 = never automatically

    // Logging
    public final boolean logQueries;
    public final long logMaxBytes;

    // Paths
    public final Path stateDir;
    public final Path logDir;
    public final Path controlSocket;
    public final Path rulesFile;
    public final Path sourcesFile;
    public final Path trustedFile;

    private Config(Properties p, Path configFile) {
        this.configFile = configFile;
        Path dir = configFile.toAbsolutePath().getParent();
        this.configDir = dir != null ? dir : Paths.get("/");

        listenAddress = str(p, "listen_address", "127.0.0.1");
        port = intRange(p, "port", 5335, 1, 65535);
        workerThreads = intRange(p, "worker_threads", 32, 1, 1024);

        upstreamMode = str(p, "upstream_mode", "DOH").toUpperCase(Locale.ROOT);
        if (!upstreamMode.equals("DOH") && !upstreamMode.equals("DOT") && !upstreamMode.equals("UDP")) {
            throw new IllegalArgumentException("upstream_mode must be DOH, DOT or UDP (got '" + upstreamMode + "')");
        }
        dohUrl = str(p, "doh_url", "https://cloudflare-dns.com/dns-query");
        dotHost = str(p, "dot_host", "dns.google");
        dotPort = intRange(p, "dot_port", 853, 1, 65535);
        upstreamPrimary = str(p, "upstream_primary", "1.1.1.1");
        upstreamSecondary = strOrEmpty(p, "upstream_secondary", "8.8.8.8");
        fallbackUdp = bool(p, "fallback_udp", true);
        fallbackPrimary = str(p, "fallback_primary", "1.1.1.1");
        fallbackSecondary = strOrEmpty(p, "fallback_secondary", "8.8.8.8");

        blockAction = str(p, "block_action", "ZERO_IP").toUpperCase(Locale.ROOT);
        if (!blockAction.equals("ZERO_IP") && !blockAction.equals("NXDOMAIN")) {
            throw new IllegalArgumentException("block_action must be ZERO_IP or NXDOMAIN (got '" + blockAction + "')");
        }
        cacheEnabled = bool(p, "cache_enabled", true);
        cacheSize = intRange(p, "cache_size", 2000, 1, 1_000_000);

        Set<String> bc = new HashSet<>();
        for (String s : str(p, "blocked_clients", "").split("[,\\s]+")) {
            if (!s.isEmpty()) bc.add(s);
        }
        blockedClients = Collections.unmodifiableSet(bc);
        dailyQueryLimit = intRange(p, "daily_query_limit", 0, 0, Integer.MAX_VALUE);
        clientDailyLimit = intRange(p, "client_daily_limit", 0, 0, Integer.MAX_VALUE);

        syncIntervalHours = intRange(p, "sync_interval_hours", 24, 0, 24 * 365);

        logQueries = bool(p, "log_queries", true);
        logMaxBytes = intRange(p, "log_max_mb", 10, 1, 4096) * 1024L * 1024L;

        stateDir = Paths.get(str(p, "state_dir", "/var/lib/netshield"));
        logDir = Paths.get(str(p, "log_dir", "/var/log/netshield"));
        controlSocket = Paths.get(str(p, "control_socket", "/run/netshield/control.sock"));
        rulesFile = configDir.resolve("rules.conf");
        sourcesFile = configDir.resolve("sources.list");
        trustedFile = configDir.resolve("trusted.list");
    }

    public static Config load(Path file) throws IOException {
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(file)) {
            p.load(in);
        }
        return new Config(p, file);
    }

    /** All non-blank, non-comment lines of a list file (returns empty if the file does not exist). */
    static List<String> readLines(Path file) {
        return readLines(file, false);
    }

    /** As above; with {@code inlineComments} a trailing "# ..." on a line is stripped too. */
    static List<String> readLines(Path file, boolean inlineComments) {
        List<String> out = new ArrayList<>();
        if (!Files.isReadable(file)) return out;
        try {
            for (String line : Files.readAllLines(file)) {
                String t = line.trim();
                if (inlineComments) {
                    int hash = t.indexOf('#');
                    if (hash >= 0) t = t.substring(0, hash).trim();
                }
                if (t.isEmpty() || t.startsWith("#")) continue;
                out.add(t);
            }
        } catch (IOException e) {
            Log.warn("cannot read " + file + ": " + e.getMessage());
        }
        return out;
    }

    private static String str(Properties p, String key, String def) {
        String v = p.getProperty(key);
        return v == null || v.trim().isEmpty() ? def : v.trim();
    }

    /** Like str(), but a key that is present and blank means "none" instead of "use the default". */
    private static String strOrEmpty(Properties p, String key, String def) {
        String v = p.getProperty(key);
        return v == null ? def : v.trim();
    }

    private static boolean bool(Properties p, String key, boolean def) {
        String v = p.getProperty(key);
        if (v == null || v.trim().isEmpty()) return def;
        String t = v.trim().toLowerCase(Locale.ROOT);
        if (t.equals("true") || t.equals("yes") || t.equals("1") || t.equals("on")) return true;
        if (t.equals("false") || t.equals("no") || t.equals("0") || t.equals("off")) return false;
        throw new IllegalArgumentException(key + " must be true or false (got '" + v + "')");
    }

    private static int intRange(Properties p, String key, int def, int min, int max) {
        String v = p.getProperty(key);
        if (v == null || v.trim().isEmpty()) return def;
        try {
            long n = Long.parseLong(v.trim());
            if (n < min || n > max) {
                throw new IllegalArgumentException(key + " must be between " + min + " and " + max + " (got " + n + ")");
            }
            return (int) n;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(key + " must be a number (got '" + v + "')");
        }
    }
}
