package com.psbdx.netshield;

/** Minimal stdout logger; systemd/journald adds timestamps and captures the output. */
final class Log {
    private Log() {}

    static void info(String msg) {
        System.out.println("[netshield] " + msg);
        System.out.flush();
    }

    static void warn(String msg) {
        System.err.println("[netshield] WARN: " + msg);
        System.err.flush();
    }
}
