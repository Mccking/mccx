package com.xehn.warp;

/**
 * Renders the mihomo configuration for the tunnel.
 *
 * <p>The proxy shape is copied from the desktop client's mihomo renderer
 * (single peer inside a {@code peers:} list — the top-level peer keys are
 * mihomo's legacy syntax). The TUN block feeds mihomo the descriptor the
 * launcher placed at 3, and leaves routing to Android's VpnService.
 */
public final class MihomoConfig {

    private static final int MIXED_PORT = 7890;
    private static final int DNS_PORT = 1053;

    private MihomoConfig() {
    }

    private static void appendBase(StringBuilder b) {
        b.append("# MccX · mihomo profile\n");
        b.append("mixed-port: ").append(MIXED_PORT).append('\n');
        b.append("allow-lan: false\n");
        b.append("mode: rule\n");
        b.append("log-level: info\n");
        b.append("ipv6: true\n");
        b.append("external-controller: 127.0.0.1:9090\n");

        b.append("dns:\n");
        b.append("  enable: true\n");
        b.append("  ipv6: true\n");
        b.append("  listen: 0.0.0.0:").append(DNS_PORT).append('\n');
        b.append("  enhanced-mode: fake-ip\n");
        b.append("  fake-ip-range: 198.18.0.1/16\n");
        b.append("  nameserver:\n");
        b.append("    - 1.1.1.1\n");
        b.append("    - 1.0.0.1\n");

        b.append("tun:\n");
        b.append("  enable: true\n");
        b.append("  stack: gvisor\n");
        b.append("  file-descriptor: 3\n");
        b.append("  auto-route: false\n");
        b.append("  auto-detect-interface: false\n");
        b.append("  dns-hijack:\n");
        b.append("    - any:53\n");
        b.append("  mtu: 1280\n");
    }

    /** MASQUE profile: same shell, an EC-keyed masque outbound instead of wireguard. */
    public static String buildMasque(Masque.Account account, String host, int port) {
        StringBuilder b = new StringBuilder();
        appendBase(b);
        b.append("proxies:\n");
        b.append("  - name: warp\n");
        b.append("    type: masque\n");
        b.append("    server: ").append(host).append('\n');
        b.append("    port: ").append(port).append('\n');
        b.append("    sni: ").append(Masque.SNI).append('\n');
        b.append("    private-key: ").append(account.privateKey).append('\n');
        b.append("    public-key: ").append(account.peerPublicKey).append('\n');
        b.append("    ip: ").append(account.ipv4).append('\n');
        if (account.ipv6 != null && !account.ipv6.isEmpty()) {
            b.append("    ipv6: ").append(account.ipv6).append('\n');
        }
        b.append("    udp: true\n");
        b.append("    mtu: 1280\n");
        b.append("    congestion-controller: bbr\n");
        b.append("    ip-stack:\n");
        b.append("      mode: gvisor\n");
        b.append("    handshake-timeout: 5\n");
        b.append("proxy-groups:\n");
        b.append("  - name: PROXY\n");
        b.append("    type: select\n");
        b.append("    proxies:\n");
        b.append("      - warp\n");
        b.append("rules:\n");
        b.append("  - MATCH,PROXY\n");
        return b.toString();
    }
    /**
     * @param host   endpoint IP or hostname
     * @param port   endpoint port
     * @param awg    true renders the AmneziaWG junk-packet options
     * @param bypass true routes Chinese destinations direct (rule provider free)
     */
    public static String build(Warp.Account account, String host, int port, boolean awg, boolean bypass) {
        StringBuilder b = new StringBuilder();
        appendBase(b);

        b.append("proxies:\n");
        b.append("  - name: warp\n");
        b.append("    type: wireguard\n");
        b.append("    private-key: ").append(account.privateKey).append('\n');
        b.append("    ip: ").append(account.ipv4).append('\n');
        if (account.ipv6 != null && !account.ipv6.isEmpty()) {
            b.append("    ipv6: ").append(account.ipv6).append('\n');
        }
        b.append("    udp: true\n");
        b.append("    mtu: 1280\n");
        b.append("    remote-dns-resolve: true\n");
        b.append("    dns:\n");
        b.append("      - 1.1.1.1\n");
        b.append("    peers:\n");
        b.append("      - server: ").append(host).append('\n');
        b.append("        port: ").append(port).append('\n');
        b.append("        public-key: ").append(account.peerPublicKey).append('\n');
        b.append("        allowed-ips:\n");
        b.append("          - 0.0.0.0/0\n");
        b.append("          - ::/0\n");
        b.append("        persistent-keepalive: ").append(UpstreamDefaults.KEEPALIVE).append('\n');
        if (awg) {
            b.append("    amnezia-wg-option:\n");
            b.append("      jc: ").append(UpstreamDefaults.AWG_JC).append('\n');
            b.append("      jmin: ").append(UpstreamDefaults.AWG_JMIN).append('\n');
            b.append("      jmax: ").append(UpstreamDefaults.AWG_JMAX).append('\n');
            b.append("      s1: 0\n");
            b.append("      s2: 0\n");
            b.append("      h1: 1\n");
            b.append("      h2: 2\n");
            b.append("      h3: 3\n");
            b.append("      h4: 4\n");
        }

        b.append("proxy-groups:\n");
        b.append("  - name: PROXY\n");
        b.append("    type: select\n");
        b.append("    proxies:\n");
        b.append("      - warp\n");

        b.append("rules:\n");
        if (bypass) {
            // GEOIP/GEOSITE would make mihomo download geoip.metadb at startup,
            // and a failed download fails the whole config — on a phone that is
            // a real risk, so only suffix rules (no external data) are used.
            b.append("  - DOMAIN-SUFFIX,cn,DIRECT\n");
        }
        b.append("  - MATCH,PROXY\n");
        return b.toString();
    }
}


