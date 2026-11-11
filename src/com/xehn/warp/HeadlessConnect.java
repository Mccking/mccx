package com.xehn.warp;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.VpnService;

/**
 * Connect path used by the quick-settings tile: no activity, no UI.
 *
 * <p>The tile can only do this once VPN consent exists (the consent dialog needs
 * an Activity), so the tile falls back to opening the app on the very first run.
 * Settings are read from the same preferences the settings screen writes.
 */
public final class HeadlessConnect {

    private static final String[] PROTOS = {"wg", "awg", "masque", "masque-h2", "wwarp"};
    private static final int[] MTUS = {1280, 1400, 1420, 1500};
    private static final int[] TIMEOUTS = {3, 5, 8};
    private static final String[] DNS = {"auto", "1.1.1.1", "8.8.8.8", "223.5.5.5", "119.29.29.29"};

    public static volatile String lastError = "";
    public static volatile boolean connecting;

    private HeadlessConnect() {
    }

    public static boolean consentGranted(Context context) {
        try {
            return VpnService.prepare(context) == null;
        } catch (Throwable t) {
            return false;
        }
    }

    public static void connect(Context context) {
        if (connecting) {
            return;
        }
        connecting = true;
        lastError = "";
        final Context app = context.getApplicationContext();
        final SharedPreferences prefs = app.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE);
        if (prefs.getInt(MainActivity.KEY_ENGINE, 0) == 1) {
            startUpstream(app, prefs);
            return;
        }
        new Thread(new Runnable() {
            public void run() {
                try {
                    Warp.Account existing = Warp.Account.fromJson(prefs.getString(MainActivity.KEY_ACCOUNT, ""));
                    int portIndex = prefs.getInt(MainActivity.KEY_PORT, 2);
                    int port = MainActivity.PORTS[Math.max(0, Math.min(portIndex, MainActivity.PORTS.length - 1))];
                    Warp.Result result = Warp.generate("wg", port, true, existing, LOGGER);
                    prefs.edit().putString(MainActivity.KEY_ACCOUNT, result.account.toJson()).apply();
                    TunnelManager.attach(app, null);
                    TunnelManager.up(result.config);
                    LogStore.append("快捷连接：隧道已建立 " + result.endpoint);
                } catch (Throwable t) {
                    lastError = t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage();
                    LogStore.append("快捷连接失败：" + lastError);
                } finally {
                    connecting = false;
                }
            }
        }, "headless-connect").start();
    }

    private static void startUpstream(Context context, SharedPreferences prefs) {
        try {
            int protoIndex = clamp(prefs.getInt(MainActivity.KEY_PROTO, 0), PROTOS.length);
            int policyIndex = prefs.getInt(MainActivity.KEY_POLICY, 0);
            String policy = policyIndex == 1 ? "bypass-cn" : (policyIndex == 2 ? "blacklist" : "global");
            int dnsIndex = clamp(prefs.getInt(MainActivity.KEY_DNS, 0), DNS.length);
            String dns = DNS[dnsIndex];
            if ("auto".equals(dns)) {
                dns = "global".equals(policy) ? "1.1.1.1" : "223.5.5.5";
            }
            int mtu = MTUS[clamp(prefs.getInt(MainActivity.KEY_MTU, 0), MTUS.length)];
            int timeout = TIMEOUTS[clamp(prefs.getInt(MainActivity.KEY_TIMEOUT, 1), TIMEOUTS.length)];
            String exitIds = prefs.getString(MainActivity.KEY_EXIT_CANDIDATES, "");
            if (exitIds.isEmpty()) {
                exitIds = prefs.getString(MainActivity.KEY_EXIT_IDS, "");
            }
            EngineService.start(context, PROTOS[protoIndex], policy, dns,
                    prefs.getBoolean(MainActivity.KEY_IPV6, false), mtu,
                    prefs.getString(MainActivity.KEY_RULES, ""),
                    exitIds,
                    prefs.getString(MainActivity.KEY_EXIT_LABEL, ""),
                    prefs.getString(MainActivity.KEY_EXIT_COUNTRY, ""),
                    timeout);
            LogStore.append("快捷连接：上游引擎 " + PROTOS[protoIndex]);
        } catch (Throwable t) {
            lastError = t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage();
            LogStore.append("快捷连接失败：" + lastError);
        } finally {
            connecting = false;
        }
    }

    private static int clamp(int index, int size) {
        return index < 0 || index >= size ? 0 : index;
    }

    private static final Warp.Log LOGGER = new Warp.Log() {
        public void log(String line) {
            LogStore.append(line);
        }
    };
}
