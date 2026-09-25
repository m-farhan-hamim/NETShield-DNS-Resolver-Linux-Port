package com.psbdx.netshield;

import java.net.URI;
import java.time.LocalDate;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The resolution pipeline, ported from the Android DnsResolverEngine:
 *   trusted bypass -> client policy -> local mapping -> sinkhole -> cache -> upstream (+ UDP fallback)
 * Android-only parts (per-app UID attribution, broadcast intents, SQLite log) are gone;
 * results go to {@link QueryLog} and the counters below instead.
 */
public final class Engine {
    private final RuleSet rules;
    private final QueryLog queryLog;
    private final DnsCache cache;
    private volatile Config cfg;

    public final AtomicLong allowed = new AtomicLong();
    public final AtomicLong blocked = new AtomicLong();
    public final AtomicLong cached = new AtomicLong();
    public final AtomicLong local = new AtomicLong();
    public final AtomicLong failed = new AtomicLong();

    // Per-client daily counters (Android "Hotspot" limits)
    private final AtomicLong globalToday = new AtomicLong();
    private final ConcurrentMap<String, AtomicInteger> clientToday = new ConcurrentHashMap<>();
    private volatile LocalDate counterDay = LocalDate.now();

    public Engine(Config cfg, RuleSet rules, QueryLog queryLog) {
        this.cfg = cfg;
        this.rules = rules;
        this.queryLog = queryLog;
        this.cache = new DnsCache(cfg.cacheSize);
    }

    public void setConfig(Config newCfg) {
        this.cfg = newCfg;
    }

    public DnsCache getCache() {
        return cache;
    }

    /** Returns the response packet, or null if the query is malformed / should be dropped. Never throws. */
    public byte[] resolve(byte[] queryPacket, int length, String clientIp) {
        try {
            return doResolve(queryPacket, length, clientIp != null ? clientIp : "127.0.0.1");
        } catch (Exception e) {
            Log.warn("resolve error: " + e);
            return DnsPacketParser.buildServFail(queryPacket, length);
        }
    }

    private byte[] doResolve(byte[] queryPacket, int length, String clientIp) {
        long start = System.nanoTime();
        Config c = cfg;

        if (DnsPacketParser.isResponse(queryPacket, length)) {
            return null; // never answer responses (reflection / loop protection)
        }
        DnsPacketParser.DnsQuestion q = DnsPacketParser.parseQuestion(queryPacket, length);
        if (q == null || q.domain == null || q.domain.isEmpty()) {
            return null;
        }
        String domain = q.domain;
        String typeName = DnsPacketParser.getTypeName(q.qType);

        // -1. Trusted domains: unconditional bypass of every block/limit check below.
        boolean trusted = rules.isTrusted(domain);

        // 0. Per-client block / daily limits
        if (!trusted) {
            if (c.blockedClients.contains(clientIp)) {
                blocked.incrementAndGet();
                record(domain, typeName, "BLOCKED", start, "Client blocked", clientIp);
                return DnsPacketParser.buildBlockedResponse(queryPacket, length, "ZERO_IP");
            }
            if (!recordAndCheckAllowed(c, clientIp)) {
                blocked.incrementAndGet();
                record(domain, typeName, "BLOCKED", start, "Daily query limit reached", clientIp);
                return DnsPacketParser.buildBlockedResponse(queryPacket, length, "ZERO_IP");
            }
        }

        // 1. Custom local mapping
        String customIp = rules.getCustomMapping(domain);
        if (customIp != null && !customIp.isEmpty()) {
            byte[] response = DnsPacketParser.buildCustomMappingResponse(queryPacket, length, customIp);
            if (response != null) {
                local.incrementAndGet();
                record(domain, typeName, "LOCAL", start, "Local Record (" + customIp + ")", clientIp);
                return response;
            }
        }

        // 2. Whitelist & blocklist (sinkhole)
        if (!trusted && rules.isBlocked(domain)) {
            byte[] response = DnsPacketParser.buildBlockedResponse(queryPacket, length, c.blockAction);
            blocked.incrementAndGet();
            record(domain, typeName, "BLOCKED", start, "Sinkhole (" + c.blockAction + ")", clientIp);
            return response;
        }

        // 3. In-memory cache
        if (c.cacheEnabled) {
            byte[] hit = cache.get(domain, q.qType, q.transactionId);
            if (hit != null) {
                cached.incrementAndGet();
                record(domain, typeName, "CACHED", start, "In-Memory LRU Cache", clientIp);
                return hit;
            }
        }

        // 4. Upstream
        String upstreamDesc;
        byte[] upstream;
        if ("DOT".equals(c.upstreamMode)) {
            upstreamDesc = "DoT (" + c.dotHost + ")";
            upstream = DoTClient.query(c.dotHost, c.dotPort, queryPacket, length);
        } else if ("UDP".equals(c.upstreamMode)) {
            upstreamDesc = "UDP (" + c.upstreamPrimary + ")";
            upstream = DnsUdpClient.query(c.upstreamPrimary, c.upstreamSecondary, queryPacket, length);
        } else {
            upstreamDesc = "DoH (" + extractHost(c.dohUrl) + ")";
            upstream = DoHClient.query(c.dohUrl, queryPacket, length);
        }

        if (upstream != null && upstream.length >= 12) {
            if (c.cacheEnabled && DnsPacketParser.getRcode(upstream) != 2 /* SERVFAIL */) {
                cache.put(domain, q.qType, upstream, DnsPacketParser.extractTtl(upstream, upstream.length));
            }
            allowed.incrementAndGet();
            record(domain, typeName, "ALLOWED", start, upstreamDesc, clientIp);
            return upstream;
        }

        // DoH/DoT failed: optional plain-UDP fallback (privacy trade-off; see fallback_udp in netshield.conf)
        if (c.fallbackUdp && !"UDP".equals(c.upstreamMode)) {
            byte[] fb = DnsUdpClient.query(c.fallbackPrimary, c.fallbackSecondary, queryPacket, length);
            if (fb != null && fb.length >= 12) {
                allowed.incrementAndGet();
                record(domain, typeName, "ALLOWED", start, "Fallback UDP (" + c.fallbackPrimary + ")", clientIp);
                return fb;
            }
        }
        failed.incrementAndGet();
        record(domain, typeName, "FAILED", start, upstreamDesc + " [Timeout]", clientIp);
        return DnsPacketParser.buildServFail(queryPacket, length);
    }

    private boolean recordAndCheckAllowed(Config c, String clientIp) {
        rolloverCountersIfNewDay();
        long g = globalToday.incrementAndGet();
        if (c.dailyQueryLimit > 0 && g > c.dailyQueryLimit) {
            return false;
        }
        AtomicInteger counter = clientToday.computeIfAbsent(clientIp, k -> new AtomicInteger());
        int n = counter.incrementAndGet();
        return c.clientDailyLimit <= 0 || n <= c.clientDailyLimit;
    }

    private void rolloverCountersIfNewDay() {
        LocalDate today = LocalDate.now();
        if (!today.equals(counterDay)) {
            synchronized (this) {
                if (!today.equals(counterDay)) {
                    counterDay = today;
                    globalToday.set(0);
                    clientToday.clear();
                }
            }
        }
    }

    private void record(String domain, String type, String status, long startNanos, String upstream, String clientIp) {
        long latencyMs = (System.nanoTime() - startNanos) / 1_000_000L;
        queryLog.log(domain, type, status, latencyMs, upstream, clientIp);
    }

    private static String extractHost(String url) {
        try {
            String host = new URI(url).getHost();
            return host != null ? host : url;
        } catch (Exception e) {
            return url;
        }
    }
}
