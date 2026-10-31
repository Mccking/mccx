import com.xehn.warp.MihomoConfig;
import com.xehn.warp.Warp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Prints the generated mihomo profile so `mihomo -t` can validate it. */
public final class ConfigDump {

    public static void main(String[] args) throws Exception {
        Warp.Account account = new Warp.Account();
        account.privateKey = args.length > 0 ? args[0] : "WJUN8K0ttHY0d1btowq8GmRi/0zac6qU5hvs3qTx2k4=";
        account.peerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
        account.ipv4 = "172.16.0.2";
        account.ipv6 = "2606:4700:110:8030:1b67:c6fe:8699:949a";

        boolean awg = args.length > 1 && "awg".equals(args[1]);
        boolean bypass = args.length > 2 && "bypass".equals(args[2]);
        String yaml = MihomoConfig.build(account, "162.159.204.1", 2408, awg, bypass);

        Files.write(Paths.get("harness/mihomo-test.yaml"), yaml.getBytes(StandardCharsets.UTF_8));
        System.out.println(yaml);
    }
}
