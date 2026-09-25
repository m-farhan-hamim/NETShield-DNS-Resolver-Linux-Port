package com.psbdx.netshield;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/** DNS-over-HTTPS (RFC 8484, POST) upstream client. */
public final class DoHClient {
    private DoHClient() {}

    private static final int TIMEOUT_MS = 5000;
    private static final int MAX_RESPONSE = 65535;

    public static byte[] query(String dohUrl, byte[] queryPacket, int length) {
        HttpURLConnection conn = null;
        try {
            URL url = java.net.URI.create(dohUrl).toURL();
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setUseCaches(false);
            conn.setRequestProperty("Content-Type", "application/dns-message");
            conn.setRequestProperty("Accept", "application/dns-message");
            conn.setRequestProperty("User-Agent", "NetShield-DNS-Linux/" + Version.get());

            try (OutputStream os = conn.getOutputStream()) {
                os.write(queryPacket, 0, length);
                os.flush();
            }

            if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                try (InputStream is = conn.getInputStream()) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[2048];
                    int n;
                    while ((n = is.read(buffer)) != -1) {
                        baos.write(buffer, 0, n);
                        if (baos.size() > MAX_RESPONSE) return null;
                    }
                    return baos.toByteArray();
                }
            }
        } catch (Exception ignored) {
        } finally {
            if (conn != null) {
                try {
                    conn.disconnect();
                } catch (Exception ignored) {
                }
            }
        }
        return null;
    }
}
