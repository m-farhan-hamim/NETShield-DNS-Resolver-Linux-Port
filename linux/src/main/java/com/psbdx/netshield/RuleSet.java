package com.psbdx.netshield;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Port of the Android BlocklistManager + TrustedListManager.
 *
 * Differences from the Android version:
 *  - user rules (rules.conf) and downloaded lists (sources.list) live in
 *    separate sets, so reloading rules can never wipe out a downloaded list
 *  - downloaded lists are cached on disk and re-loaded at startup
 *  - state is swapped in atomically, so lookups never see a half-loaded set
 *
 * rules.conf syntax (one rule per line, '#' starts a comment):
 *   block  example.com          sinkhole example.com and all its subdomains
 *   allow  example.com          never block example.com or its subdomains
 *   map    nas.home 10.0.0.5    answer A/AAAA for exactly nas.home with this address
 */
public final class RuleSet {
    private static final long MAX_DOWNLOAD_BYTES = 200L * 1024 * 1024;

    private volatile Config cfg;
    private volatile Set<String> ruleBlock = Collections.emptySet();
    private volatile Set<String> ruleAllow = Collections.emptySet();
    private volatile Set<String> trusted = Collections.emptySet();
    private volatile Set<String> remoteBlock = Collections.emptySet();
    private volatile Map<String, String> mappings = Collections.emptyMap();
    private volatile long pauseUntil = 0;
    private final Object syncLock = new Object();

    public RuleSet(Config cfg) {
        this.cfg = cfg;
        reload(cfg);
    }

    // ---- loading -------------------------------------------------------------------------

    /** (Re)reads rules.conf, trusted.list and the cached downloaded blocklists. */
    public void reload(Config newCfg) {
        this.cfg = newCfg;

        Set<String> block = new HashSet<>();
        Set<String> allow = new HashSet<>();
        Map<String, String> map = new HashMap<>();
        for (String line : Config.readLines(newCfg.rulesFile, true)) {
            String[] parts = line.split("\\s+");
            String kind = parts[0].toLowerCase(Locale.ROOT);
            if (parts.length < 2) {
                Log.warn("rules.conf: ignoring malformed line: " + line);
                continue;
            }
            String domain = normalize(parts[1]);
            if (domain.isEmpty()) continue;
            switch (kind) {
                case "block":
                    block.add(domain);
                    break;
                case "allow":
                    allow.add(domain);
                    break;
                case "map":
                    if (parts.length >= 3) {
                        map.put(domain, parts[2]);
                    } else {
                        Log.warn("rules.conf: 'map' needs a domain and an address: " + line);
                    }
                    break;
                default:
                    Log.warn("rules.conf: unknown rule type '" + parts[0] + "'");
            }
        }
        ruleBlock = block;
        ruleAllow = allow;
        mappings = map;

        Set<String> trust = new HashSet<>();
        for (String line : Config.readLines(newCfg.trustedFile, true)) {
            String d = normalize(line.split("\\s+")[0]);
            if (!d.isEmpty()) trust.add(d);
        }
        trusted = trust;

        loadCachedLists();
        Log.info("rules loaded: " + block.size() + " block, " + allow.size() + " allow, "
                + map.size() + " map, " + trust.size() + " trusted, " + remoteBlock.size() + " from lists");
    }

    private void loadCachedLists() {
        Set<String> all = new HashSet<>();
        for (String[] src : readSources(cfg)) {
            Path cached = cachePath(src[0]);
            if (!Files.isReadable(cached)) continue;
            try (BufferedReader r = Files.newBufferedReader(cached, StandardCharsets.UTF_8)) {
                parseHosts(r, all);
            } catch (IOException e) {
                Log.warn("cannot read cached list " + cached + ": " + e.getMessage());
            }
        }
        remoteBlock = all;
    }

    // ---- lookups -------------------------------------------------------------------------

    public boolean isTrusted(String domain) {
        return matchesOrParent(trusted, domain);
    }

    public boolean isWhitelisted(String domain) {
        return matchesOrParent(ruleAllow, domain);
    }

    public String getCustomMapping(String domain) {
        return domain == null ? null : mappings.get(domain.toLowerCase(Locale.ROOT));
    }

    /** Whitelist wins, then exact/parent-domain match against user rules and downloaded lists. Never blocks while paused. */
    public boolean isBlocked(String domain) {
        if (domain == null || isPaused()) return false;
        String d = domain.toLowerCase(Locale.ROOT);
        if (isWhitelisted(d)) return false;
        return matchesOrParent(ruleBlock, d) || matchesOrParent(remoteBlock, d);
    }

    /** Human-readable verdict for {@code netshield check <domain>}. */
    public String explain(String domain) {
        String d = normalize(domain);
        if (d.isEmpty()) return "usage: check <domain>";
        StringBuilder sb = new StringBuilder(d).append(": ");
        if (isTrusted(d)) return sb.append("TRUSTED (bypasses blocking and client limits)").toString();
        String m = getCustomMapping(d);
        if (m != null) return sb.append("LOCAL mapping -> ").append(m).toString();
        if (isWhitelisted(d)) return sb.append("ALLOWED (allow rule)").toString();
        if (matchesOrParent(ruleBlock, d)) return sb.append(isPaused() ? "would be BLOCKED by a block rule (protection paused)" : "BLOCKED by a block rule").toString();
        if (matchesOrParent(remoteBlock, d)) return sb.append(isPaused() ? "would be BLOCKED by a downloaded list (protection paused)" : "BLOCKED by a downloaded list").toString();
        return sb.append("not blocked").toString();
    }

    private static boolean matchesOrParent(Set<String> set, String domain) {
        if (domain == null || domain.isEmpty() || set.isEmpty()) return false;
        String d = domain.toLowerCase(Locale.ROOT);
        if (set.contains(d)) return true;
        int dot = d.indexOf('.');
        while (dot != -1) {
            if (set.contains(d.substring(dot + 1))) return true;
            dot = d.indexOf('.', dot + 1);
        }
        return false;
    }

    // ---- pause / resume ------------------------------------------------------------------

    public void pauseProtection(long durationMillis) {
        pauseUntil = System.currentTimeMillis() + durationMillis;
    }

    public void resumeProtection() {
        pauseUntil = 0;
    }

    public boolean isPaused() {
        return System.currentTimeMillis() < pauseUntil;
    }

    public long getRemainingPauseMillis() {
        long remaining = pauseUntil - System.currentTimeMillis();
        return remaining > 0 ? remaining : 0;
    }

    // ---- counts --------------------------------------------------------------------------

    public int getBlockedCount() {
        return ruleBlock.size() + remoteBlock.size();
    }

    public int getListCount() {
        return remoteBlock.size();
    }

    public int getWhitelistCount() {
        return ruleAllow.size();
    }

    public int getMappingCount() {
        return mappings.size();
    }

    // ---- remote list sync ----------------------------------------------------------------

    /** Downloads every source in sources.list into the state dir, then reloads. Returns a one-line summary. */
    public String sync() {
        synchronized (syncLock) {
            List<String[]> sources = readSources(cfg);
            if (sources.isEmpty()) {
                return "no sources configured in " + cfg.sourcesFile;
            }
            int ok = 0;
            List<String> failed = new ArrayList<>();
            for (String[] src : sources) {
                try {
                    int n = download(src[0]);
                    Log.info("synced " + src[1] + ": " + n + " domains");
                    ok++;
                } catch (Exception e) {
                    Log.warn("sync failed for " + src[1] + ": " + e.getMessage() + " (keeping previous copy, if any)");
                    failed.add(src[1]);
                }
            }
            loadCachedLists();
            String summary = "synced " + ok + "/" + sources.size() + " sources, " + remoteBlock.size() + " domains in downloaded lists";
            if (!failed.isEmpty()) summary += " (failed: " + String.join(", ", failed) + ")";
            return summary;
        }
    }

    /** True if no downloaded copy exists for at least one configured source. */
    public boolean needsInitialSync() {
        for (String[] src : readSources(cfg)) {
            if (!Files.exists(cachePath(src[0]))) return true;
        }
        return false;
    }

    private int download(String sourceUrl) throws IOException {
        Path dir = cfg.stateDir.resolve("blocklists");
        Files.createDirectories(dir);
        Path target = cachePath(sourceUrl);
        Path tmp = dir.resolve(target.getFileName() + ".part");

        URLConnection conn = java.net.URI.create(sourceUrl).toURL().openConnection();
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(30000);
        conn.setUseCaches(false);
        conn.setRequestProperty("User-Agent", "NetShield-DNS-Linux/" + Version.get());
        if (conn instanceof HttpURLConnection) {
            int code = ((HttpURLConnection) conn).getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                throw new IOException("HTTP " + code);
            }
        }

        long total = 0;
        try (InputStream in = conn.getInputStream(); OutputStream out = Files.newOutputStream(tmp)) {
            byte[] buf = new byte[16384];
            int n;
            while ((n = in.read(buf)) != -1) {
                total += n;
                if (total > MAX_DOWNLOAD_BYTES) throw new IOException("list too large");
                out.write(buf, 0, n);
            }
        } catch (IOException e) {
            Files.deleteIfExists(tmp);
            throw e;
        }

        // Only replace the previous good copy if the download actually parses into something.
        Set<String> probe = new HashSet<>();
        try (BufferedReader r = Files.newBufferedReader(tmp, StandardCharsets.UTF_8)) {
            parseHosts(r, probe);
        } catch (IOException e) {
            Files.deleteIfExists(tmp);
            throw e;
        }
        if (probe.isEmpty()) {
            Files.deleteIfExists(tmp);
            throw new IOException("no domains found in download");
        }
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        return probe.size();
    }

    /** Sources are "URL [name...]" lines; returns {url, displayName} pairs. */
    private static List<String[]> readSources(Config c) {
        List<String[]> out = new ArrayList<>();
        for (String line : Config.readLines(c.sourcesFile)) {
            String[] parts = line.split("\\s+", 2);
            String name = parts.length > 1 && !parts[1].trim().isEmpty() ? parts[1].trim() : parts[0];
            out.add(new String[]{parts[0], name});
        }
        return out;
    }

    private Path cachePath(String url) {
        return cfg.stateDir.resolve("blocklists").resolve(sha1(url) + ".txt");
    }

    private static String sha1(String s) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-1").digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Parses a hosts-style or plain-domain list (same rules as the Android
     * app): "0.0.0.0 domain", "127.0.0.1 domain" or a bare "domain"; '#'
     * comments; localhost/broadcasthost/local and dot-less names are skipped.
     * Returns the number of accepted lines.
     */
    static int parseHosts(BufferedReader reader, Set<String> into) throws IOException {
        int count = 0;
        String line;
        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            int hashIdx = line.indexOf('#');
            if (hashIdx != -1) line = line.substring(0, hashIdx).trim();

            String[] parts = line.split("\\s+");
            String domain = null;
            if (parts.length >= 2) {
                if (parts[0].equals("127.0.0.1") || parts[0].equals("0.0.0.0")) domain = parts[1];
            } else if (parts.length == 1) {
                domain = parts[0];
            }
            if (domain != null) {
                domain = normalize(domain);
                if (!domain.equals("localhost") && !domain.equals("broadcasthost")
                        && !domain.equals("local") && domain.contains(".")) {
                    into.add(domain);
                    count++;
                }
            }
        }
        return count;
    }

    /** Lower-case, strip a leading "*." wildcard and any trailing dot. */
    static String normalize(String s) {
        if (s == null) return "";
        String d = s.trim().toLowerCase(Locale.ROOT);
        if (d.startsWith("*.")) d = d.substring(2);
        while (d.endsWith(".")) d = d.substring(0, d.length() - 1);
        return d;
    }
}
