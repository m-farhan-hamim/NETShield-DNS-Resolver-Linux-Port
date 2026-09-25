package com.psbdx.netshield;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * NetShield DNS Resolver for Linux - headless daemon.
 * Usage: java -cp netshield-dns.jar com.psbdx.netshield.Daemon [--config /etc/netshield/netshield.conf]
 */
public final class Daemon implements ControlServer.Handler {
    private final long startedAt = System.currentTimeMillis();
    private final Path configFile;
    private volatile Config cfg;
    private RuleSet rules;
    private Engine engine;
    private QueryLog queryLog;
    private DnsServer dns;
    private ControlServer control;
    private ScheduledExecutorService scheduler;

    private Daemon(Path configFile, Config cfg) {
        this.configFile = configFile;
        this.cfg = cfg;
    }

    public static void main(String[] args) {
        Path configFile = Paths.get("/etc/netshield/netshield.conf");
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--config") && i + 1 < args.length) {
                configFile = Paths.get(args[++i]);
            } else if (args[i].equals("--version")) {
                System.out.println("netshield-dns " + Version.get());
                return;
            } else {
                System.err.println("usage: Daemon [--config FILE] [--version]");
                System.exit(2);
            }
        }

        Config cfg;
        try {
            cfg = Config.load(configFile);
        } catch (Exception e) {
            System.err.println("netshield: cannot load " + configFile + ": " + e.getMessage());
            System.exit(1);
            return;
        }

        Daemon d = new Daemon(configFile, cfg);
        try {
            d.start();
        } catch (Exception e) {
            Log.warn("failed to start: " + e);
            d.shutdown();
            System.exit(1);
            return;
        }

        CountDownLatch stop = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            Log.info("shutting down");
            d.shutdown();
            stop.countDown();
        }, "netshield-shutdown"));
        try {
            stop.await();
        } catch (InterruptedException ignored) {
        }
    }

    private void start() throws Exception {
        Log.info("NetShield DNS Resolver " + Version.get() + " starting (config " + configFile + ")");
        Files.createDirectories(cfg.stateDir);

        queryLog = new QueryLog(cfg);
        rules = new RuleSet(cfg);
        engine = new Engine(cfg, rules, queryLog);
        dns = new DnsServer(cfg, engine);
        dns.start();
        control = new ControlServer(cfg.controlSocket, rules, engine, queryLog, this);
        control.start();

        Log.info("upstream: " + describeUpstream(cfg) + "; blocking " + rules.getBlockedCount() + " domains");

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "netshield-sync");
            t.setDaemon(true);
            return t;
        });
        scheduleSync();
    }

    private static final int NO_RETRY = 99;

    private void scheduleSync() {
        long periodSec = cfg.syncIntervalHours * 3600L;
        if (periodSec > 0) {
            scheduler.scheduleWithFixedDelay(() -> runSync(NO_RETRY), periodSec, periodSec, TimeUnit.SECONDS);
        }
        // First run (no cached lists yet): fetch shortly after startup so the resolver is already answering.
        if (rules.needsInitialSync()) {
            scheduler.schedule(() -> runSync(1), 5, TimeUnit.SECONDS);
        }
    }

    private void runSync(int attempt) {
        try {
            Log.info("blocklist sync: " + rules.sync());
        } catch (Exception e) {
            Log.warn("blocklist sync error: " + e);
        }
        // Network not up yet at boot? Retry a few times instead of waiting a whole interval.
        if (rules.needsInitialSync() && attempt < 6 && !scheduler.isShutdown()) {
            scheduler.schedule(() -> runSync(attempt + 1), 10, TimeUnit.MINUTES);
        }
    }

    private void shutdown() {
        if (scheduler != null) scheduler.shutdownNow();
        if (control != null) control.stop();
        if (dns != null) dns.stop();
        if (queryLog != null) queryLog.close();
    }

    // ---- ControlServer.Handler ----------------------------------------------------------

    @Override
    public String reload() {
        try {
            Config fresh = Config.load(configFile);
            boolean bindChanged = !fresh.listenAddress.equals(cfg.listenAddress) || fresh.port != cfg.port;
            cfg = fresh;
            engine.setConfig(fresh);
            rules.reload(fresh);
            return "reloaded" + (bindChanged ? " (listen_address/port changes need a service restart)" : "");
        } catch (Exception e) {
            return "error: reload failed, keeping previous settings: " + e.getMessage();
        }
    }

    @Override
    public String sync() {
        return rules.sync();
    }

    @Override
    public String status() {
        Config c = cfg;
        StringBuilder sb = new StringBuilder();
        sb.append("NetShield DNS Resolver ").append(Version.get()).append('\n');
        sb.append("uptime:      ").append(formatDuration(System.currentTimeMillis() - startedAt)).append('\n');
        sb.append("listening:   ").append(c.listenAddress).append(':').append(c.port).append(" (udp+tcp)\n");
        sb.append("upstream:    ").append(describeUpstream(c)).append(c.fallbackUdp && !c.upstreamMode.equals("UDP") ? " (plain-UDP fallback on)" : "").append('\n');
        sb.append("protection:  ");
        if (rules.isPaused()) {
            sb.append("PAUSED (").append(formatDuration(rules.getRemainingPauseMillis())).append(" left)\n");
        } else {
            sb.append("active (").append(c.blockAction.toLowerCase(Locale.ROOT)).append(")\n");
        }
        sb.append("rules:       ").append(rules.getBlockedCount()).append(" blocked domains (")
                .append(rules.getListCount()).append(" from lists), ")
                .append(rules.getWhitelistCount()).append(" allowed, ")
                .append(rules.getMappingCount()).append(" local records\n");
        long total = engine.allowed.get() + engine.blocked.get() + engine.cached.get() + engine.local.get() + engine.failed.get();
        sb.append("queries:     ").append(total).append(" total - ")
                .append(engine.allowed.get()).append(" forwarded, ")
                .append(engine.cached.get()).append(" cached, ")
                .append(engine.blocked.get()).append(" blocked, ")
                .append(engine.local.get()).append(" local, ")
                .append(engine.failed.get()).append(" failed\n");
        sb.append("cache:       ").append(engine.getCache().size()).append(" entries, ")
                .append(engine.getCache().getHitCount()).append(" hits / ")
                .append(engine.getCache().getMissCount()).append(" misses\n");
        sb.append("query log:   ").append(queryLog.isEnabled() ? c.logDir.resolve("queries.log") : "disabled");
        return sb.toString();
    }

    private static String describeUpstream(Config c) {
        switch (c.upstreamMode) {
            case "DOT":
                return "DoT " + c.dotHost + ":" + c.dotPort;
            case "UDP":
                return "UDP " + c.upstreamPrimary + (c.upstreamSecondary.isEmpty() ? "" : ", " + c.upstreamSecondary);
            default:
                return "DoH " + c.dohUrl;
        }
    }

    private static String formatDuration(long ms) {
        Duration d = Duration.ofMillis(Math.max(0, ms));
        long days = d.toDays();
        long h = d.toHours() % 24;
        long m = d.toMinutes() % 60;
        long s = d.getSeconds() % 60;
        if (days > 0) return days + "d " + h + "h " + m + "m";
        if (h > 0) return h + "h " + m + "m " + s + "s";
        if (m > 0) return m + "m " + s + "s";
        return s + "s";
    }
}
