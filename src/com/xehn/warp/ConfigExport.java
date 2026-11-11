package com.xehn.warp;

/**
 * Exports the current device as profiles other clients can import.
 *
 * <p>CFPilot's idea, adapted: the device that tested best is the one worth
 * exporting, and the exported profile must be the exact one that just worked —
 * not a re-rendered approximation. The WireGuard body therefore comes straight
 * from the generated profile; the Clash profile is rebuilt from the same
 * account data, including the WARP {@code reserved} bytes when the API returned
 * a client id.
 */
public final class ConfigExport {

    private ConfigExport() {
    }

    public static String fileName(boolean clash) {
        return clash ? "mccx-warp.yaml" : "mccx-warp.conf";
    }

    /** The wg-quick profile the built-in engine just used. */
    public static String wireGuard(Warp.Result result) {
        if (result == null || result.config == null) {
            return "";
        }
        return result.config;
    }

    /** mihomo / Clash profile with one WireGuard proxy and a catch-all rule. */
    public static String clash(Warp.Result result) {
        if (result == null || result.account == null) {
            return "";
        }
        Warp.Account account = result.account;
        String host = result.endpoint;
        int port = 2408;
        int split = result.endpoint.lastIndexOf(':');
        if (split > 0) {
            host = result.endpoint.substring(0, split);
            try {
                port = Integer.parseInt(result.endpoint.substring(split + 1));
            } catch (NumberFormatException ignored) {
            }
        }

        StringBuilder b = new StringBuilder();
        b.append("# MccX 导出 · mihomo / Clash 客户端导入\n");
        b.append("proxies:\n");
        b.append("  - name: MccX-WARP\n");
        b.append("    type: wireguard\n");
        b.append("    server: ").append(host).append('\n');
        b.append("    port: ").append(port).append('\n');
        b.append("    private-key: ").append(account.privateKey).append('\n');
        b.append("    public-key: ").append(account.peerPublicKey).append('\n');
        b.append("    ip: ").append(account.ipv4).append('\n');
        if (account.ipv6 != null && account.ipv6.length() > 0) {
            b.append("    ipv6: ").append(account.ipv6).append('\n');
        }
        String reserved = reserved(account.clientId);
        if (!reserved.isEmpty()) {
            b.append("    reserved: ").append(reserved).append('\n');
        }
        b.append("    udp: true\n");
        b.append("    mtu: ").append(UpstreamDefaults.TUNNEL_MTU).append('\n');
        b.append('\n');
        b.append("proxy-groups:\n");
        b.append("  - name: PROXY\n");
        b.append("    type: select\n");
        b.append("    proxies:\n");
        b.append("      - MccX-WARP\n");
        b.append('\n');
        b.append("rules:\n");
        b.append("  - MATCH,PROXY\n");
        return b.toString();
    }

    /** WARP's client id is base64 of the three reserved header bytes. */
    static String reserved(String clientId) {
        if (clientId == null || clientId.isEmpty()) {
            return "";
        }
        try {
            byte[] raw = android.util.Base64.decode(clientId, android.util.Base64.DEFAULT);
            if (raw.length != 3) {
                return "";
            }
            return "[" + (raw[0] & 0xFF) + ", " + (raw[1] & 0xFF) + ", " + (raw[2] & 0xFF) + "]";
        } catch (Throwable t) {
            return "";
        }
    }
}
