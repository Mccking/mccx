package com.xehn.warp;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Answers one question the engine logs cannot: is the MASQUE endpoint blocked
 * before TLS (DPI reset on the SNI), or does the handshake work and the failure
 * is somewhere else?
 *
 * <p>It connects to the endpoint twice — once with the MASQUE SNI and once with
 * an ordinary Cloudflare SNI — so a difference between them points at SNI-based
 * filtering rather than a dead address.
 */
public final class TlsProbe {

    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 8000;

    private TlsProbe() {
    }

    public static String run(String host, int port, String sni) {
        StringBuilder report = new StringBuilder();
        report.append(host).append(':').append(port).append(" sni=").append(sni).append('\n');
        long started = System.nanoTime();
        Socket raw = new Socket();
        try {
            raw.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            report.append("TCP 连接成功 ").append((System.nanoTime() - started) / 1000000L).append(" ms\n");

            SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                    .createSocket(raw, sni, port, true);
            SSLParameters params = ssl.getSSLParameters();
            params.setServerNames(Collections.singletonList(new SNIHostName(sni)));
            params.setApplicationProtocols(new String[]{"h2", "http/1.1"});
            ssl.setSSLParameters(params);
            ssl.setSoTimeout(READ_TIMEOUT_MS);

            ssl.startHandshake();
            SSLSession session = ssl.getSession();
            report.append("TLS 握手成功 · ").append(session.getProtocol())
                    .append(" · ALPN=").append(ssl.getApplicationProtocol()).append('\n');
            Certificate[] chain = session.getPeerCertificates();
            if (chain.length > 0 && chain[0] instanceof X509Certificate) {
                X509Certificate cert = (X509Certificate) chain[0];
                report.append("证书 CN=").append(cert.getSubjectX500Principal().getName()).append('\n');
            }
            ssl.close();
        } catch (Exception e) {
            report.append("失败：").append(e.getClass().getSimpleName())
                    .append(' ').append(e.getMessage() == null ? "" : e.getMessage()).append('\n');
            report.append("（TCP 成功但 TLS 失败 = 大概率按 SNI 阻断；TCP 就失败 = 地址/端口不可达）\n");
        } finally {
            try {
                raw.close();
            } catch (Exception ignored) {
            }
        }
        return report.toString();
    }
}
