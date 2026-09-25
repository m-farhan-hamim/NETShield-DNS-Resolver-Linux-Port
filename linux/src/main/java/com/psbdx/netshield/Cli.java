package com.psbdx.netshield;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/** The {@code netshield} command: talks to the running daemon over its control socket. */
public final class Cli {
    private Cli() {}

    private static final String USAGE =
            "usage: netshield [--socket PATH] <command> [args]\n"
            + "\n"
            + "commands:\n"
            + "  status            show state, upstream, rule counts and query statistics\n"
            + "  pause [TIME]      stop blocking for TIME (e.g. 90, 10m, 1h; default 5m)\n"
            + "  resume            resume blocking now\n"
            + "  sync              download/refresh the blocklists in sources.list now\n"
            + "  reload            re-read netshield.conf, rules.conf, trusted.list and cached lists\n"
            + "  flush             clear the response cache\n"
            + "  check DOMAIN      explain how a domain would be handled\n"
            + "  logs [N]          show the last N queries (default 20)\n"
            + "  version           print the version\n";

    public static void main(String[] args) {
        String socket = System.getenv("NETSHIELD_SOCKET");
        int i = 0;
        while (i < args.length && args[i].startsWith("--")) {
            if (args[i].equals("--socket") && i + 1 < args.length) {
                socket = args[i + 1];
                i += 2;
            } else if (args[i].equals("--help")) {
                System.out.print(USAGE);
                return;
            } else {
                System.err.println("unknown option " + args[i]);
                System.exit(2);
            }
        }
        if (i >= args.length || args[i].equals("help") || args[i].equals("-h")) {
            System.out.print(USAGE);
            System.exit(i >= args.length ? 2 : 0);
        }
        String[] rest = Arrays.copyOfRange(args, i, args.length);
        String cmd = rest[0].toLowerCase();

        if (cmd.equals("version")) {
            System.out.println("netshield-dns " + Version.get());
            return;
        }
        if (cmd.equals("pause") && rest.length > 1) {
            long secs = parseDuration(rest[1]);
            if (secs <= 0) {
                System.err.println("netshield: invalid duration '" + rest[1] + "' (try 90, 10m or 1h)");
                System.exit(2);
            }
            rest = new String[]{"pause", Long.toString(secs)};
        }

        Path path = Paths.get(socket != null ? socket : "/run/netshield/control.sock");
        String line = String.join(" ", rest);
        try {
            String reply = send(path, line);
            System.out.print(reply.endsWith("\n") ? reply : reply + "\n");
            System.exit(reply.startsWith("error:") ? 1 : 0);
        } catch (Exception e) {
            System.err.println("netshield: cannot reach the daemon at " + path + " (" + e.getMessage() + ")");
            if (!Files.exists(path)) {
                System.err.println("  is the service running?  systemctl status netshield-dns");
            } else {
                System.err.println("  permission problem?  run with sudo, or add yourself to the 'netshield' group");
            }
            System.exit(1);
        }
    }

    static String send(Path socketPath, String command) throws Exception {
        try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            ch.connect(UnixDomainSocketAddress.of(socketPath));
            OutputStream out = Channels.newOutputStream(ch);
            out.write((command + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            InputStream in = Channels.newInputStream(ch);
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int n;
            while ((n = in.read(chunk)) != -1) buf.write(chunk, 0, n);
            return new String(buf.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    /** "90" (seconds), "10m", "2h", "1d" -> seconds; -1 if invalid. */
    static long parseDuration(String s) {
        try {
            String t = s.trim().toLowerCase();
            long mult = 1;
            if (t.endsWith("s")) {
                t = t.substring(0, t.length() - 1);
            } else if (t.endsWith("m")) {
                mult = 60;
                t = t.substring(0, t.length() - 1);
            } else if (t.endsWith("h")) {
                mult = 3600;
                t = t.substring(0, t.length() - 1);
            } else if (t.endsWith("d")) {
                mult = 86400;
                t = t.substring(0, t.length() - 1);
            }
            return Long.parseLong(t) * mult;
        } catch (Exception e) {
            return -1;
        }
    }
}
