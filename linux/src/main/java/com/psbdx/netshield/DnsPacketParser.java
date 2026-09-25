package com.psbdx.netshield;

import java.io.ByteArrayOutputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * DNS wire-format helpers. Ported from the Android app's DnsPacketParser.
 *
 * Behavioural fixes vs. the Android original:
 *  - sinkhole responses only synthesize an answer for A/AAAA questions; every
 *    other type (HTTPS, TXT, MX, ...) gets an empty NOERROR (NODATA) answer
 *  - custom mappings answer only when the record type matches the address
 *    family (A for IPv4, AAAA for IPv6), otherwise NODATA
 *  - domain bytes are read unsigned
 */
public final class DnsPacketParser {
    private DnsPacketParser() {}

    public static final int TYPE_A = 1;
    public static final int TYPE_AAAA = 28;
    public static final int TYPE_OPT = 41;

    public static class DnsQuestion {
        public int transactionId;
        public String domain;
        public int qType;
        public int qClass;
        public int questionSectionLength; // length of QNAME + QTYPE + QCLASS
    }

    public static DnsQuestion parseQuestion(byte[] data, int length) {
        if (data == null || length < 12) {
            return null;
        }
        try {
            ByteBuffer buffer = ByteBuffer.wrap(data, 0, length);
            DnsQuestion q = new DnsQuestion();
            q.transactionId = buffer.getShort(0) & 0xFFFF;

            int qdCount = buffer.getShort(4) & 0xFFFF;
            if (qdCount < 1) {
                return null;
            }

            int offset = 12;
            StringBuilder domain = new StringBuilder();

            while (offset < length) {
                int len = data[offset] & 0xFF;
                if (len == 0) {
                    offset++;
                    break;
                }
                if ((len & 0xC0) == 0xC0) {
                    offset += 2;
                    break;
                }
                offset++;
                if (offset + len > length) {
                    return null;
                }
                for (int i = 0; i < len; i++) {
                    domain.append((char) (data[offset++] & 0xFF));
                }
                domain.append('.');
            }

            if (domain.length() > 0 && domain.charAt(domain.length() - 1) == '.') {
                domain.setLength(domain.length() - 1);
            }
            q.domain = domain.toString().toLowerCase();

            if (offset + 4 <= length) {
                q.qType = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                q.qClass = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
                offset += 4;
            }

            q.questionSectionLength = offset - 12;
            return q;
        } catch (Exception e) {
            return null;
        }
    }

    public static String getTypeName(int qType) {
        switch (qType) {
            case 1: return "A";
            case 28: return "AAAA";
            case 5: return "CNAME";
            case 15: return "MX";
            case 16: return "TXT";
            case 12: return "PTR";
            case 2: return "NS";
            case 6: return "SOA";
            case 65: return "HTTPS";
            default: return "TYPE" + qType;
        }
    }

    public static int getTransactionId(byte[] packet) {
        if (packet == null || packet.length < 2) return 0;
        return ((packet[0] & 0xFF) << 8) | (packet[1] & 0xFF);
    }

    public static void setTransactionId(byte[] packet, int id) {
        if (packet != null && packet.length >= 2) {
            packet[0] = (byte) ((id >> 8) & 0xFF);
            packet[1] = (byte) (id & 0xFF);
        }
    }

    /** True if the QR bit says this packet is a response (we must never answer those). */
    public static boolean isResponse(byte[] packet, int length) {
        return packet != null && length >= 3 && (packet[2] & 0x80) != 0;
    }

    public static int getRcode(byte[] packet) {
        return (packet == null || packet.length < 4) ? 0 : (packet[3] & 0x0F);
    }

    public static long extractTtl(byte[] response, int length) {
        if (response == null || length < 12) return 60;
        try {
            int qdCount = ((response[4] & 0xFF) << 8) | (response[5] & 0xFF);
            int anCount = ((response[6] & 0xFF) << 8) | (response[7] & 0xFF);
            if (anCount == 0) return 60;

            int offset = 12;
            for (int i = 0; i < qdCount && offset < length; i++) {
                offset = skipName(response, offset, length);
                if (offset < 0) return 60;
                offset += 4; // QTYPE + QCLASS
            }

            if (offset < length) {
                offset = skipName(response, offset, length);
                if (offset < 0) return 60;
                // Now at TYPE (2) + CLASS (2) + TTL (4)
                if (offset + 8 <= length) {
                    offset += 4;
                    long ttl = ((long) (response[offset] & 0xFF) << 24)
                            | ((long) (response[offset + 1] & 0xFF) << 16)
                            | ((long) (response[offset + 2] & 0xFF) << 8)
                            | ((long) (response[offset + 3] & 0xFF));
                    if (ttl > 0 && ttl < 86400) {
                        return ttl;
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return 60;
    }

    /** Returns the offset just past the (possibly compressed) name at {@code offset}, or -1 if malformed. */
    static int skipName(byte[] data, int offset, int length) {
        while (offset < length) {
            int len = data[offset] & 0xFF;
            if (len == 0) return offset + 1;
            if ((len & 0xC0) == 0xC0) return offset + 2 <= length ? offset + 2 : -1;
            offset += 1 + len;
        }
        return -1;
    }

    /**
     * Maximum UDP response size the client accepts: the EDNS0 payload size from
     * the query's OPT record, or the classic 512 when there is none.
     */
    public static int udpPayloadLimit(byte[] query, int length) {
        try {
            DnsQuestion q = parseQuestion(query, length);
            if (q == null) return 512;
            int arCount = ((query[10] & 0xFF) << 8) | (query[11] & 0xFF);
            int offset = 12 + q.questionSectionLength;
            for (int i = 0; i < arCount && offset < length; i++) {
                offset = skipName(query, offset, length);
                if (offset < 0 || offset + 10 > length) return 512;
                int type = ((query[offset] & 0xFF) << 8) | (query[offset + 1] & 0xFF);
                int cls = ((query[offset + 2] & 0xFF) << 8) | (query[offset + 3] & 0xFF);
                int rdLen = ((query[offset + 8] & 0xFF) << 8) | (query[offset + 9] & 0xFF);
                if (type == TYPE_OPT) {
                    return Math.max(512, cls);
                }
                offset += 10 + rdLen;
            }
        } catch (Exception ignored) {
        }
        return 512;
    }

    /** Header + question only, TC bit set: tells the client to retry over TCP. */
    public static byte[] buildTruncated(byte[] response) {
        DnsQuestion q = parseQuestion(response, response.length);
        if (q == null) return response;
        int end = Math.min(response.length, 12 + q.questionSectionLength);
        byte[] out = new byte[end];
        System.arraycopy(response, 0, out, 0, end);
        out[2] |= 0x02; // TC
        out[6] = out[7] = out[8] = out[9] = out[10] = out[11] = 0; // AN/NS/AR = 0
        return out;
    }

    /** SERVFAIL reply (RCODE 2) so clients fail fast instead of waiting out their timeout. */
    public static byte[] buildServFail(byte[] query, int queryLen) {
        DnsQuestion q = parseQuestion(query, queryLen);
        if (q == null) return null;
        int end = Math.min(queryLen, 12 + q.questionSectionLength);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeHeader(out, query, 0x8182, 0); // QR, RD, RA, RCODE=2
        out.write(query, 12, end - 12);
        return out.toByteArray();
    }

    public static byte[] buildBlockedResponse(byte[] query, int queryLen, String action) {
        DnsQuestion q = parseQuestion(query, queryLen);
        if (q == null) return null;

        boolean isNxDomain = "NXDOMAIN".equalsIgnoreCase(action);
        boolean synthesize = !isNxDomain && (q.qType == TYPE_A || q.qType == TYPE_AAAA);

        int flags = 0x8580; // QR=1, AA=1, RD=1, RA=1
        if (isNxDomain) {
            flags |= 0x0003; // RCODE = 3 (Name Error)
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeHeader(out, query, flags, synthesize ? 1 : 0);
        int questionEnd = Math.min(queryLen, 12 + q.questionSectionLength);
        out.write(query, 12, questionEnd - 12);

        if (synthesize) {
            boolean v6 = q.qType == TYPE_AAAA;
            out.write(0xC0);
            out.write(0x0C); // pointer to QNAME
            out.write(0x00);
            out.write(v6 ? 0x1C : 0x01); // TYPE
            out.write(0x00);
            out.write(0x01); // CLASS IN
            out.write(new byte[]{0x00, 0x00, 0x00, 0x3C}, 0, 4); // TTL 60s
            out.write(0x00);
            out.write(v6 ? 0x10 : 0x04); // RDLENGTH
            out.write(new byte[v6 ? 16 : 4], 0, v6 ? 16 : 4); // :: or 0.0.0.0
        }
        return out.toByteArray();
    }

    public static byte[] buildCustomMappingResponse(byte[] query, int queryLen, String targetIp) {
        DnsQuestion q = parseQuestion(query, queryLen);
        if (q == null) return null;

        try {
            InetAddress addr = InetAddress.getByName(targetIp);
            byte[] ipBytes = addr.getAddress();
            boolean v6 = addr instanceof Inet6Address;
            boolean typeMatches = (v6 && q.qType == TYPE_AAAA) || (!v6 && q.qType == TYPE_A);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            writeHeader(out, query, 0x8580, typeMatches ? 1 : 0);
            int questionEnd = Math.min(queryLen, 12 + q.questionSectionLength);
            out.write(query, 12, questionEnd - 12);

            if (typeMatches) {
                out.write(0xC0);
                out.write(0x0C);
                out.write(0x00);
                out.write(v6 ? 0x1C : 0x01);
                out.write(0x00);
                out.write(0x01); // CLASS IN
                out.write(new byte[]{0x00, 0x00, 0x01, 0x2C}, 0, 4); // TTL 300s
                out.write((ipBytes.length >> 8) & 0xFF);
                out.write(ipBytes.length & 0xFF);
                out.write(ipBytes, 0, ipBytes.length);
            }
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private static void writeHeader(ByteArrayOutputStream out, byte[] query, int flags, int anCount) {
        out.write(query[0]); // ID
        out.write(query[1]);
        out.write((flags >> 8) & 0xFF);
        out.write(flags & 0xFF);
        out.write(0x00);
        out.write(0x01); // QDCOUNT = 1
        out.write((anCount >> 8) & 0xFF);
        out.write(anCount & 0xFF);
        out.write(0x00);
        out.write(0x00); // NSCOUNT
        out.write(0x00);
        out.write(0x00); // ARCOUNT
    }
}
