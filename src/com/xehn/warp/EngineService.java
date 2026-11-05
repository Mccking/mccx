package com.xehn.warp;

import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import com.xiaohe.engine.Engine;
import com.xiaohe.engine.Engine_;
import com.xiaohe.engine.LogSink;
import com.xiaohe.engine.Protector;

import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/**
 * Runs the upstream XEHN engine (the Go library compiled into engine.aar).
 *
 * <p>The contract mirrors the upstream app: establish a TUN, hand the descriptor
 * over with {@code setTunFD}, let the engine protect its own sockets through
 * {@link VpnService#protect}, then {@code connect(proto, "", psiphon, ipv6, mtu)}.
 * {@code Connect} returns at once and reports progress through
 * {@code statusJSON()}, so the service polls it once per second.
 */
public final class EngineService extends VpnService {

    public static final String ACTION_START = "com.xehn.warp.ENGINE_START";
    public static final String ACTION_STOP = "com.xehn.warp.ENGINE_STOP";

    public static final String EXTRA_PROTO = "proto";
    public static final String EXTRA_POLICY = "policy";
    public static final String EXTRA_DNS = "dns";
    public static final String EXTRA_IPV6 = "ipv6";
    public static final String EXTRA_MTU = "mtu";
    public static final String EXTRA_RULES = "rules";

    private static final int DEFAULT_MTU = 1280;
    private static final long POLL_MS = 1000;

    public static volatile boolean running;
    public static volatile String state = "";
    public static volatile String lastLog = "";
    public static volatile String proto = "";
    public static volatile String endpoint = "";
    public static volatile String exitIP = "";
    public static volatile String country = "";
    public static volatile String message = "";
    public static volatile String egress = "";
    public static volatile long latencyMs = -1;
    public static volatile long upBps;
    public static volatile long downBps;
    public static volatile long upBytes;
    public static volatile long downBytes;
    public static volatile long uptimeMs;

    private static final ArrayDeque<String> RECENT = new ArrayDeque<String>();

    public static boolean connected() {
        return "connected".equals(state);
    }

    public static String recentLog() {
        synchronized (RECENT) {
            StringBuilder builder = new StringBuilder();
            for (String line : RECENT) {
                if (builder.length() > 0) {
                    builder.append('\n');
                }
                builder.append(line);
            }
            return builder.toString();
        }
    }

    private static void remember(String line) {
        synchronized (RECENT) {
            RECENT.addLast(line);
            while (RECENT.size() > 30) {
                RECENT.removeFirst();
            }
        }
    }

    private ParcelFileDescriptor tun;
    private Engine_ engine;
    private Thread poller;
    private volatile boolean stopped;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (action == null || ACTION_STOP.equals(action)) {
            stopTunnel();
            return START_NOT_STICKY;
        }
        String proto = intent.getStringExtra(EXTRA_PROTO);
        String policy = intent.getStringExtra(EXTRA_POLICY);
        startTunnel(proto == null || proto.isEmpty() ? "wg" : proto,
                policy == null || policy.isEmpty() ? "global" : policy,
                intent.getStringExtra(EXTRA_DNS),
                intent.getBooleanExtra(EXTRA_IPV6, false),
                intent.getIntExtra(EXTRA_MTU, DEFAULT_MTU),
                intent.getStringExtra(EXTRA_RULES));
        return START_NOT_STICKY;
    }

    private void startTunnel(String protoName, String policy, String dns, boolean ipv6, int mtu,
                             String rules) {
        try {
            File dir = new File(getFilesDir(), "engine");
            if (!dir.exists() && !dir.mkdirs()) {
                throw new IOException("无法创建引擎目录");
            }
            engine = Engine.newEngine(dir.getAbsolutePath());
            engine.setLogSink(new LogSink() {
                public void onLog(String line) {
                    lastLog = line;
                    remember(line);
                }
            });
            engine.setProtector(new Protector() {
                public boolean protect(long fd) {
                    return EngineService.this.protect((int) fd);
                }
            });
            engine.setTimeout(5);
            engine.setSocksListen("");

            Builder builder = new Builder();
            builder.setSession("MccX");
            builder.setMtu(mtu);
            builder.addAddress("172.16.0.2", 32);
            if (ipv6) {
                builder.addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 128);
            }
            applyRoutes(builder, policy, rules);
            if (ipv6) {
                builder.addRoute("::", 0);
            }
            for (String server : resolveDns(dns)) {
                try {
                    builder.addDnsServer(server);
                } catch (Throwable ignored) {
                }
            }
            builder.setBlocking(true);
            tun = builder.establish();
            if (tun == null) {
                throw new IOException("establish() 返回 null（VPN 未授权）");
            }

            engine.setTunFD(tun.getFd());
            engine.setVPNState(true);
            remember("engine: " + engine.versionString() + "，协议 " + protoName
                    + "，MTU " + mtu + (ipv6 ? "，IPv6 开" : ""));
            engine.setRules(policy, rules == null ? "" : rules);
            engine.connect(protoName, "", false, ipv6, mtu);
            running = true;
            refreshCnRoutesIfStale(policy);
            startPoller();
        } catch (Throwable t) {
            lastLog = "启动失败：" + (t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage());
            remember(lastLog);
            stopTunnel();
        }
    }

    private static List<String> resolveDns(String csv) {
        List<String> out = new ArrayList<String>();
        if (csv != null) {
            for (String part : csv.split(",")) {
                String value = part.trim();
                if (!value.isEmpty()) {
                    out.add(value);
                }
            }
        }
        if (out.isEmpty()) {
            out.add("1.1.1.1");
        }
        return out;
    }

    /**
     * Route policy. "bypass-cn" needs the mainland table the engine downloads;
     * until that exists the only honest option is global with a note in the log.
     */
    private void applyRoutes(Builder builder, String policy, String rules) {
        if ("blacklist".equals(policy)) {
            List<String[]> proxied = SplitRoute.parseProxyCidrs(rules);
            if (proxied.isEmpty()) {
                remember("分流：黑名单，但规则里没有 proxy 网段，本次不抓任何流量");
            } else {
                for (String[] route : proxied) {
                    try {
                        builder.addRoute(route[0], Integer.parseInt(route[1]));
                    } catch (Throwable ignored) {
                    }
                }
                remember("分流：黑名单，只抓 " + proxied.size() + " 个网段");
            }
            return;
        }
        if (!"bypass-cn".equals(policy)) {
            builder.addRoute("0.0.0.0", 0);
            remember("分流：全局");
            return;
        }
        List<int[]> cn = SplitRoute.loadCnRoutes(this);
        if (cn.isEmpty()) {
            builder.addRoute("0.0.0.0", 0);
            remember("分流：大陆路由表未就绪，本次按全局（连上后会下载）");
            return;
        }
        if (Build.VERSION.SDK_INT >= 33) {
            builder.addRoute("0.0.0.0", 0);
            int excluded = 0;
            for (int[] route : cn) {
                try {
                    builder.excludeRoute(new android.net.IpPrefix(
                            InetAddress.getByAddress(SplitRoute.intToBytes(route[0])), route[1]));
                    excluded++;
                } catch (Throwable ignored) {
                }
            }
            remember("分流：绕过大陆（全局 + 排除 " + excluded + " 个网段）");
        } else {
            List<int[]> gaps = SplitRoute.complementV4(cn);
            for (int[] route : gaps) {
                builder.addRoute(SplitRoute.intToIp(route[0]), route[1]);
            }
            remember("分流：绕过大陆（" + gaps.size() + " 条补集路由，API<33 无 excludeRoute）");
        }
    }

    private void refreshCnRoutesIfStale(final String policy) {
        if (!"bypass-cn".equals(policy) || SplitRoute.cacheFresh(this)) {
            return;
        }
        new Thread(new Runnable() {
            public void run() {
                try {
                    Engine_ current = engine;
                    if (current == null) {
                        return;
                    }
                    String info = current.refreshCNRoutes();
                    remember("大陆路由表已更新：" + (info == null ? "" : info));
                } catch (Throwable t) {
                    remember("大陆路由表更新失败：" + t.getMessage());
                }
            }
        }, "cn-routes").start();
    }

    private void startPoller() {
        poller = new Thread(new Runnable() {
            public void run() {
                String previous = "";
                while (!stopped) {
                    try {
                        Thread.sleep(POLL_MS);
                    } catch (InterruptedException e) {
                        return;
                    }
                    if (engine == null) {
                        return;
                    }
                    try {
                        applyStatus(engine.statusJSON());
                        if (!state.equals(previous)) {
                            previous = state;
                            remember("状态：" + state
                                    + (message.isEmpty() ? "" : "（" + message + "）"));
                            if ("connected".equals(state)) {
                                running = true;
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        }, "engine-poll");
        poller.start();
    }

    /** Mirrors the engine snapshot into the static fields the UI reads. */
    private static void applyStatus(String json) {
        try {
            JSONObject o = new JSONObject(json);
            state = o.optString("state", state);
            proto = o.optString("proto", proto);
            endpoint = o.optString("endpoint", endpoint);
            exitIP = o.optString("exitIP", exitIP);
            country = o.optString("country", country);
            message = o.optString("message", "");
            egress = o.optString("egress", "");
            latencyMs = o.optLong("latencyMS", latencyMs);
            upBps = o.optLong("upBps", upBps);
            downBps = o.optLong("downBps", downBps);
            upBytes = o.optLong("upBytes", upBytes);
            downBytes = o.optLong("downBytes", downBytes);
            uptimeMs = o.optLong("uptimeMS", uptimeMs);
        } catch (Throwable ignored) {
        }
    }

    private void stopTunnel() {
        stopped = true;
        running = false;
        state = "";
        try {
            if (engine != null) {
                engine.setVPNState(false);
                engine.disconnect();
            }
        } catch (Throwable ignored) {
        }
        engine = null;
        if (tun != null) {
            try {
                tun.close();
            } catch (IOException ignored) {
            }
            tun = null;
        }
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopTunnel();
        super.onDestroy();
    }

    public static void start(Context context, String proto, String policy,
                             String dns, boolean ipv6, int mtu, String rules) {
        Intent intent = new Intent(context, EngineService.class)
                .setAction(ACTION_START)
                .putExtra(EXTRA_PROTO, proto)
                .putExtra(EXTRA_POLICY, policy)
                .putExtra(EXTRA_DNS, dns)
                .putExtra(EXTRA_IPV6, ipv6)
                .putExtra(EXTRA_MTU, mtu)
                .putExtra(EXTRA_RULES, rules);
        context.startService(intent);
    }

    public static void stop(Context context) {
        context.startService(new Intent(context, EngineService.class).setAction(ACTION_STOP));
    }
}
