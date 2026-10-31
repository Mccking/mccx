import com.wireguard.config.Config;

import java.io.BufferedReader;
import java.io.StringReader;

/**
 * Desktop check of the exact config parser the tunnel backend uses: if this
 * accepts the generated profile and renders a sane wg-userspace string, the
 * WireGuard half of the app is wired correctly. Not part of the APK.
 */
public final class ConfigCheck {

    public static void main(String[] args) throws Exception {
        String text = args.length > 0 ? readArg(args[0]) : sample();

        System.out.println("--- parsing " + text.length() + " chars ---");
        Config config = Config.parse(new BufferedReader(new StringReader(text)));

        System.out.println("interface addresses : " + config.getInterface().getAddresses());
        System.out.println("interface dns       : " + config.getInterface().getDnsServers());
        System.out.println("interface mtu       : " + config.getInterface().getMtu());
        System.out.println("peers               : " + config.getPeers().size());
        for (com.wireguard.config.Peer peer : config.getPeers()) {
            System.out.println("  endpoint          : " + peer.getEndpoint());
            System.out.println("  allowed ips       : " + peer.getAllowedIps());
            System.out.println("  keepalive         : " + peer.getPersistentKeepalive());
            System.out.println("  public key        : " + peer.getPublicKey().toBase64());
        }

        System.out.println("--- wg-userspace (handed to libwg-go) ---");
        System.out.println(config.toWgUserspaceString());

        boolean ok = config.getPeers().size() == 1
                && !config.getInterface().getAddresses().isEmpty()
                && config.getPeers().get(0).getEndpoint().isPresent();
        System.out.println(ok ? "CONFIG OK" : "CONFIG INCOMPLETE");
        System.exit(ok ? 0 : 1);
    }

    private static String readArg(String path) throws Exception {
        return new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path)), "UTF-8");
    }

    private static String sample() {
        return "[Interface]\n"
                + "PrivateKey = WJUN8K0ttHY0d1btowq8GmRi/0zac6qU5hvs3qTx2k4=\n"
                + "Address = 172.16.0.2/32, 2606:4700:110:8030:1b67:c6fe:8699:949a/128\n"
                + "DNS = 1.1.1.1, 1.0.0.1\n"
                + "MTU = 1280\n"
                + "\n[Peer]\n"
                + "PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n"
                + "Endpoint = 162.159.192.1:2408\n"
                + "AllowedIPs = 0.0.0.0/0, ::/0\n"
                + "PersistentKeepalive = 25\n";
    }
}
