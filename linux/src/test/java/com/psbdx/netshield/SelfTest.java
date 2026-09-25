package com.psbdx.netshield;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

/**
 * Dependency-free unit tests (no JUnit needed, so the .deb build has zero
 * third-party requirements). Run with:
 *   java -cp <classes> com.psbdx.netshield.SelfTest
 * Exits non-zero if any check fails.
 */
public final class SelfTest {
    private static int checks = 0;
    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        testParseQuestion();
        testBlockedResponses();
        testCustomMapping();
        testServFailAndTruncation();
        testUdpPayloadLimit();
        testExtractTtl();
        testCache();
        testHostsParsing();
        testRuleSet();
        testConfigValidation();
        testDuration();

        System.out.println(checks + " checks, " + failures + " failures");
        if (failures > 0) System.exit(1);
    }

    // ---- helpers ------------------------------------------------------------------------

    static byte[] query(int id, String name, int type, int ednsSize) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(id >> 8);
        o.write(id);
        o.write(0x01); // RD
        o.write(0x00);
        o.write(0);
        o.write(1); // QDCOUNT
        o.write(0);
        o.write(0); // AN
        o.write(0);
        o.write(0); // NS
        o.write(0);
        o.write(ednsSize > 0 ? 1 : 0); // AR
        for (String label : name.split("\\.")) {
            byte[] b = label.getBytes(StandardCharsets.US_ASCII);
            o.write(b.length);
            o.write(b, 0, b.length);
        }
        o.write(0);
        o.write(type >> 8);
        o.write(type);
        o.write(0);
        o.write(1); // IN
        if (ednsSize > 0) {
            o.write(0); // root name
            o.write(0);
            o.write(41); // OPT
            o.write(ednsSize >> 8);
            o.write(ednsSize); // class = UDP payload size
            o.write(0);
            o.write(0);
            o.write(0);
            o.write(0); // ttl
            o.write(0);
            o.write(0); // rdlen
        }
        return o.toByteArray();
    }

    static void check(boolean cond, String what) {
        checks++;
        if (!cond) {
            failures++;
            System.out.println("FAIL: " + what);
        }
    }

    static int u16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    // ---- tests --------------------------------------------------------------------------

    static void testParseQuestion() {
        byte[] q = query(0xBEEF, "WWW.Example.COM", 1, 0);
        DnsPacketParser.DnsQuestion p = DnsPacketParser.parseQuestion(q, q.length);
        check(p != null, "parse ok");
        check(p.transactionId == 0xBEEF, "transaction id");
        check("www.example.com".equals(p.domain), "domain lower-cased: " + p.domain);
        check(p.qType == 1 && p.qClass == 1, "type/class");
        check(DnsPacketParser.parseQuestion(new byte[5], 5) == null, "short packet rejected");
        check(!DnsPacketParser.isResponse(q, q.length), "query is not a response");
        byte[] r = q.clone();
        r[2] |= (byte) 0x80;
        check(DnsPacketParser.isResponse(r, r.length), "QR bit detected");
    }

    static void testBlockedResponses() {
        byte[] qa = query(1, "ads.example.com", 1, 0);
        byte[] a = DnsPacketParser.buildBlockedResponse(qa, qa.length, "ZERO_IP");
        check(u16(a, 0) == 1, "blocked keeps transaction id");
        check((a[2] & 0x80) != 0, "blocked is a response");
        check(DnsPacketParser.getRcode(a) == 0, "ZERO_IP rcode NOERROR");
        check(u16(a, 6) == 1, "A: one answer");
        check(a[a.length - 1] == 0 && a[a.length - 4] == 0 && a.length > 16, "A: 0.0.0.0 rdata");

        byte[] q6 = query(2, "ads.example.com", 28, 0);
        byte[] a6 = DnsPacketParser.buildBlockedResponse(q6, q6.length, "ZERO_IP");
        check(u16(a6, 6) == 1 && u16(a6, a6.length - 18) == 16, "AAAA: one answer with 16-byte rdata");

        byte[] qt = query(3, "ads.example.com", 16, 0);
        byte[] at = DnsPacketParser.buildBlockedResponse(qt, qt.length, "ZERO_IP");
        check(u16(at, 6) == 0 && DnsPacketParser.getRcode(at) == 0, "TXT: NODATA (no fake A record)");

        byte[] qh = query(4, "ads.example.com", 65, 0);
        byte[] ah = DnsPacketParser.buildBlockedResponse(qh, qh.length, "ZERO_IP");
        check(u16(ah, 6) == 0, "HTTPS: NODATA");

        byte[] nx = DnsPacketParser.buildBlockedResponse(qa, qa.length, "NXDOMAIN");
        check(DnsPacketParser.getRcode(nx) == 3 && u16(nx, 6) == 0, "NXDOMAIN response");
    }

    static void testCustomMapping() {
        byte[] qa = query(7, "nas.home", 1, 0);
        byte[] r = DnsPacketParser.buildCustomMappingResponse(qa, qa.length, "10.0.0.5");
        check(u16(r, 6) == 1, "mapping A answered");
        check((r[r.length - 4] & 0xFF) == 10 && (r[r.length - 1] & 0xFF) == 5, "mapping A rdata 10.0.0.5");

        byte[] q6 = query(8, "nas.home", 28, 0);
        byte[] n = DnsPacketParser.buildCustomMappingResponse(q6, q6.length, "10.0.0.5");
        check(u16(n, 6) == 0 && DnsPacketParser.getRcode(n) == 0, "IPv4 mapping + AAAA question -> NODATA");

        byte[] r6 = DnsPacketParser.buildCustomMappingResponse(q6, q6.length, "fd00::5");
        check(u16(r6, 6) == 1 && (r6[r6.length - 1] & 0xFF) == 5, "IPv6 mapping answers AAAA");
    }

    static void testServFailAndTruncation() {
        byte[] q = query(0x1234, "example.com", 1, 0);
        byte[] sf = DnsPacketParser.buildServFail(q, q.length);
        check(u16(sf, 0) == 0x1234 && DnsPacketParser.getRcode(sf) == 2, "SERVFAIL built");

        byte[] big = DnsPacketParser.buildCustomMappingResponse(q, q.length, "1.2.3.4");
        byte[] tc = DnsPacketParser.buildTruncated(big);
        check((tc[2] & 0x02) != 0, "TC bit set");
        check(u16(tc, 6) == 0 && tc.length < big.length, "answers stripped from truncated reply");
    }

    static void testUdpPayloadLimit() {
        byte[] plain = query(1, "example.com", 1, 0);
        byte[] edns = query(1, "example.com", 1, 4096);
        byte[] tiny = query(1, "example.com", 1, 100);
        check(DnsPacketParser.udpPayloadLimit(plain, plain.length) == 512, "no EDNS -> 512");
        check(DnsPacketParser.udpPayloadLimit(edns, edns.length) == 4096, "EDNS 4096");
        check(DnsPacketParser.udpPayloadLimit(tiny, tiny.length) == 512, "EDNS <512 clamps to 512");
    }

    static void testExtractTtl() {
        byte[] q = query(9, "example.com", 1, 0);
        byte[] r = DnsPacketParser.buildCustomMappingResponse(q, q.length, "1.2.3.4"); // TTL 300
        check(DnsPacketParser.extractTtl(r, r.length) == 300, "TTL 300 extracted");
        byte[] nodata = DnsPacketParser.buildBlockedResponse(query(9, "example.com", 16, 0), 0, "ZERO_IP");
        check(nodata == null, "zero-length query -> null");
    }

    static void testCache() throws Exception {
        DnsCache c = new DnsCache(2);
        byte[] q = query(0x1111, "a.example.com", 1, 0);
        byte[] r = DnsPacketParser.buildCustomMappingResponse(q, q.length, "1.2.3.4");
        check(c.get("a.example.com", 1, 0x2222) == null, "miss on empty cache");
        c.put("a.example.com", 1, r, 300);
        byte[] hit = c.get("a.example.com", 1, 0x2222);
        check(hit != null && DnsPacketParser.getTransactionId(hit) == 0x2222, "hit rewrites transaction id");
        c.put("b.example.com", 1, r, 300);
        c.put("c.example.com", 1, r, 300);
        check(c.size() == 2, "LRU evicts beyond capacity");
        check(c.getHitCount() == 1 && c.getMissCount() == 1, "hit/miss counters");
        c.put("d.example.com", 1, r, 0);
        check(c.get("d.example.com", 1, 1) == null, "ttl<=0 not cached");
    }

    static void testHostsParsing() throws Exception {
        Set<String> out = new HashSet<>();
        String text = "# comment\n127.0.0.1 localhost\n0.0.0.0 Ads.Example.com # trailing\n"
                + "0.0.0.0 tracker.net\nplain.org\n1.2.3.4 ignored.com\n0.0.0.0 broadcasthost\n0.0.0.0 nodots\n\n";
        int n = RuleSet.parseHosts(new BufferedReader(new StringReader(text)), out);
        check(out.contains("ads.example.com"), "hosts line parsed + lower-cased");
        check(out.contains("tracker.net") && out.contains("plain.org"), "hosts + bare domain");
        check(!out.contains("ignored.com"), "non-sinkhole IP lines ignored");
        check(!out.contains("localhost") && !out.contains("broadcasthost") && !out.contains("nodots"), "reserved/dotless skipped");
        check(n == 3, "accepted count = " + n);
    }

    static Config tempConfig(Path dir, String extraConf, String rules, String sources, String trusted) throws Exception {
        Files.write(dir.resolve("netshield.conf"), ("state_dir=" + dir.resolve("state") + "\nlog_dir=" + dir.resolve("log")
                + "\ncontrol_socket=" + dir.resolve("ctl.sock") + "\nlog_queries=false\n" + extraConf + "\n").getBytes(StandardCharsets.UTF_8));
        Files.write(dir.resolve("rules.conf"), rules.getBytes(StandardCharsets.UTF_8));
        Files.write(dir.resolve("sources.list"), sources.getBytes(StandardCharsets.UTF_8));
        Files.write(dir.resolve("trusted.list"), trusted.getBytes(StandardCharsets.UTF_8));
        return Config.load(dir.resolve("netshield.conf"));
    }

    static void testRuleSet() throws Exception {
        Path dir = Files.createTempDirectory("netshield-test");
        Path list = dir.resolve("hosts.txt");
        Files.write(list, "0.0.0.0 listed.example\n0.0.0.0 cdn.tracker.example\n".getBytes(StandardCharsets.UTF_8));
        Config cfg = tempConfig(dir, "",
                "block *.blocked.test\nblock Bad.Example.\nallow ok.bad.example\nmap nas.home 10.0.0.5\nmap  # malformed\n",
                list.toUri().toString() + " Local test list\n",
                "trusted.test\n");
        RuleSet rs = new RuleSet(cfg);

        check(rs.isBlocked("blocked.test"), "wildcard rule blocks apex");
        check(rs.isBlocked("a.b.blocked.test"), "rule blocks deep subdomain");
        check(rs.isBlocked("bad.example"), "trailing-dot/case normalised");
        check(!rs.isBlocked("ok.bad.example"), "allow rule wins over parent block");
        check(!rs.isBlocked("sub.ok.bad.example"), "allow rule covers subdomains");
        check(!rs.isBlocked("example.org"), "unrelated domain not blocked");
        check("10.0.0.5".equals(rs.getCustomMapping("NAS.home")), "mapping lookup case-insensitive");
        check(rs.getCustomMapping("x.nas.home") == null, "mapping is exact-match only");
        check(rs.isTrusted("api.trusted.test"), "trusted covers subdomains");

        check(rs.needsInitialSync(), "needs initial sync before download");
        check(!rs.isBlocked("listed.example"), "list not active before sync");
        String summary = rs.sync();
        check(summary.startsWith("synced 1/1"), "sync summary: " + summary);
        check(rs.isBlocked("listed.example") && rs.isBlocked("x.cdn.tracker.example"), "downloaded list active after sync");
        check(!rs.needsInitialSync(), "no initial sync needed after download");

        // The Android app lost downloaded lists whenever rules were reloaded; make sure we do not.
        rs.reload(cfg);
        check(rs.isBlocked("listed.example"), "downloaded list survives a rules reload");

        rs.pauseProtection(60_000);
        check(rs.isPaused() && !rs.isBlocked("blocked.test"), "paused -> nothing blocked");
        check(rs.getCustomMapping("nas.home") != null, "mappings still work while paused");
        rs.resumeProtection();
        check(!rs.isPaused() && rs.isBlocked("blocked.test"), "resume restores blocking");

        check(rs.explain("nas.home").contains("LOCAL"), "explain: mapping");
        check(rs.explain("a.blocked.test").contains("BLOCKED by a block rule"), "explain: rule");
        check(rs.explain("listed.example").contains("downloaded list"), "explain: list");
        check(rs.explain("example.org").contains("not blocked"), "explain: clean");
    }

    static void testConfigValidation() throws Exception {
        Path dir = Files.createTempDirectory("netshield-test-cfg");
        try {
            tempConfig(dir, "upstream_mode=CARRIERPIGEON", "", "", "");
            check(false, "bad upstream_mode should be rejected");
        } catch (IllegalArgumentException e) {
            check(e.getMessage().contains("upstream_mode"), "bad upstream_mode rejected");
        }
        try {
            tempConfig(dir, "port=70000", "", "", "");
            check(false, "bad port should be rejected");
        } catch (IllegalArgumentException e) {
            check(e.getMessage().contains("port"), "bad port rejected");
        }
        Config ok = tempConfig(dir, "blocked_clients=10.0.0.9, 10.0.0.10", "", "", "");
        check(ok.port == 5335 && "127.0.0.1".equals(ok.listenAddress), "defaults: 127.0.0.1:5335");
        check(ok.blockedClients.contains("10.0.0.9") && ok.blockedClients.contains("10.0.0.10"), "blocked_clients parsed");
    }

    static void testDuration() {
        check(Cli.parseDuration("90") == 90, "90 -> 90s");
        check(Cli.parseDuration("10m") == 600, "10m");
        check(Cli.parseDuration("2h") == 7200, "2h");
        check(Cli.parseDuration("abc") == -1, "invalid duration");
    }
}
