package com.psbdx.netshield;

/** Version comes from the jar manifest (Implementation-Version), written by packaging/build-deb.sh. */
final class Version {
    private Version() {}

    static String get() {
        String v = Version.class.getPackage() != null ? Version.class.getPackage().getImplementationVersion() : null;
        return v != null ? v : "dev";
    }
}
