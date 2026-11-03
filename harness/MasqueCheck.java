import com.xehn.warp.Masque;
import com.xehn.warp.MihomoConfig;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Desktop check: register a MASQUE device and render the mihomo profile for it. */
public final class MasqueCheck {

    public static void main(String[] args) throws Exception {
        System.out.println("--- registering ---");
        Masque.Account account = Masque.register();
        System.out.println("id           : " + account.id);
        System.out.println("ipv4 / ipv6  : " + account.ipv4 + " / " + account.ipv6);
        System.out.println("private len  : " + account.privateKey.length());
        System.out.println("peer key len : " + account.peerPublicKey.length());

        String yaml = MihomoConfig.buildMasque(account, Masque.DEFAULT_SERVER, Masque.DEFAULT_PORT);
        Files.write(Paths.get("harness/masque-test.yaml"), yaml.getBytes(StandardCharsets.UTF_8));
        System.out.println("--- config written ---");
        System.out.println("MASQUE OK");
        System.exit(0);
    }
}
