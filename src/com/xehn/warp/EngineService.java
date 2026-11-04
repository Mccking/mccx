package com.xehn.warp;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import com.xiaohe.engine.Engine;
import com.xiaohe.engine.Engine_;
import com.xiaohe.engine.LogSink;
import com.xiaohe.engine.Protector;

import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.util.ArrayDeque;

/**
 * Runs the upstream XEHN engine (the Go library compiled into engine.aar).
 *
 * <p>This is the grafted half of the project: instead of spawning mihomo, the
 * engine is called in-process. The contract mirrors the upstream app exactly —
 * establish a TUN, hand the descriptor over with {@code setTunFD}, let the
 * engine protect its own sockets through {@link VpnService#protect}, then
 * {@code connect(proto, "", false, ipv6, mtu)}. {@code Connect} returns at once
 * and reports progress through {@code statusJSON()}, so the service polls it.
 */
public final class EngineService extends VpnService {

    public static final String ACTION_START = "com.xehn.warp.ENGINE_START";
    public static final String ACTION_STOP = "com.xehn.warp.ENGINE_STOP";
    public static final String EXTRA_PROTO = "proto";

    private static final int MTU = 1280;
    private static final long POLL_MS = 1000;

    public static volatile boolean running;
    public static volatile String state = "";
    public static volatile String lastLog = "";

    private static final ArrayDeque<String> RECENT = new ArrayDeque<String>();

    public static String recentLog() {
        synchronized (RECENT) {
            StringBuilder b = new StringBuilder();
            for (String line : RECENT) {
                if (b.length() > 0) {
                    b.append('\n');
                }
                b.append(line);
            }
            return b.toString();
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
    public int onStartCommand(android.content.Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (action == null || ACTION_STOP.equals(action)) {
            stopTunnel();
            return START_NOT_STICKY;
        }
        String proto = intent.getStringExtra(EXTRA_PROTO);
        startTunnel(proto == null || proto.isEmpty() ? "wg" : proto);
        return START_NOT_STICKY;
    }

    private void startTunnel(String proto) {
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
            builder.setMtu(MTU);
            builder.addAddress("172.16.0.2", 32);
            builder.addRoute("0.0.0.0", 0);
            builder.addDnsServer("1.1.1.1");
            builder.setBlocking(true);
            tun = builder.establish();
            if (tun == null) {
                throw new IOException("establish() 返回 null（VPN 未授权）");
            }

            engine.setTunFD(tun.getFd());
            engine.setVPNState(true);
            remember("engine: " + engine.versionString() + "，协议 " + proto);
            engine.connect(proto, "", false, false, MTU);
            running = true;
            startPoller();
        } catch (Throwable t) {
            lastLog = "启动失败：" + (t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage());
            remember(lastLog);
            stopTunnel();
        }
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
                        String raw = engine.statusJSON();
                        String current = parseState(raw);
                        if (current != null && !current.equals(previous)) {
                            previous = current;
                            state = current;
                            remember("状态：" + current);
                            if ("connected".equals(current)) {
                                running = true;
                            } else if ("error".equals(current)) {
                                running = false;
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        }, "engine-poll");
        poller.start();
    }

    private static String parseState(String json) {
        try {
            JSONObject o = new JSONObject(json);
            String value = o.optString("state", "");
            return value.isEmpty() ? null : value;
        } catch (Exception e) {
            return null;
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

    public static void start(android.content.Context context, String proto) {
        android.content.Intent intent = new android.content.Intent(context, EngineService.class)
                .setAction(ACTION_START)
                .putExtra(EXTRA_PROTO, proto);
        context.startService(intent);
    }

    public static void stop(android.content.Context context) {
        context.startService(new android.content.Intent(context, EngineService.class)
                .setAction(ACTION_STOP));
    }
}
