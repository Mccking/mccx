package com.xehn.warp;

import android.content.Context;
import android.content.Intent;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;

/**
 * Runs mihomo behind a VpnService TUN.
 *
 * <p>The engine lives in a different process, so the descriptor has to travel:
 * this service creates the TUN, starts {@code libmccxcore.so}, and hands the fd
 * over an abstract unix socket. The launcher re-execs mihomo with that fd at 3,
 * which is what the generated config points {@code tun.file-descriptor} at.
 *
 * <p>Our own UID is excluded from the tunnel ({@code addDisallowedApplication}),
 * so mihomo's outbound WireGuard packets leave over the real network instead of
 * looping back into the TUN — the subprocess equivalent of {@code protect()}.
 */
public final class MihomoVpnService extends android.net.VpnService {

    public static final String ACTION_START = "com.xehn.warp.MIHOMO_START";
    public static final String ACTION_STOP = "com.xehn.warp.MIHOMO_STOP";
    public static final String EXTRA_CONFIG = "config";

    private static final String TAG = "MccX/mihomo";
    private static final Charset UTF8 = Charset.forName("UTF-8");

    /** Read by the UI; the service is the only writer. */
    public static volatile boolean running;
    public static volatile String lastLog = "";

    /**
     * Last lines of the engine's own output. A sticky service restart is silent,
     * so the only way to explain a failure to the user is to keep its log tail.
     */
    private static final java.util.ArrayDeque<String> RECENT = new java.util.ArrayDeque<String>();

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
            while (RECENT.size() > 20) {
                RECENT.removeFirst();
            }
        }
    }

    private ParcelFileDescriptor tun;
    private Process core;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (action == null || ACTION_STOP.equals(action)) {
            stopTunnel();
            return START_NOT_STICKY;
        }
        String config = intent.getStringExtra(EXTRA_CONFIG);
        if (config == null) {
            lastLog = "缺少配置路径";
            stopTunnel();
            return START_NOT_STICKY;
        }
        startTunnel(config);
        // NOT_STICKY on purpose: a sticky service is restarted by the system with
        // a null intent, which used to look like "it reconnected after I stopped it".
        return START_NOT_STICKY;
    }

    private void startTunnel(String configPath) {
        try {
            Builder builder = new Builder();
            builder.setSession("MccX");
            builder.addAddress("172.19.0.1", 30);
            builder.addAddress("fd00::1", 126);
            builder.addRoute("0.0.0.0", 0);
            builder.addRoute("::", 0);
            builder.addDnsServer("1.1.1.1");
            builder.setMtu(1280);
            // The engine shares our UID; keeping that UID outside the tunnel is
            // what stops its own WireGuard packets from re-entering the TUN.
            builder.addDisallowedApplication(getPackageName());
            tun = builder.establish();
            if (tun == null) {
                throw new IOException("establish() 返回 null（VPN 未授权）");
            }

            File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
            File launcher = new File(nativeDir, "libmccxcore.so");
            File mihomo = new File(nativeDir, "libmihomo.so");
            if (!launcher.canExecute()) {
                launcher.setExecutable(true);
            }
            if (!mihomo.canExecute()) {
                mihomo.setExecutable(true);
            }
            File home = new File(getFilesDir(), "mihomo");
            if (!home.exists() && !home.mkdirs()) {
                throw new IOException("无法创建 mihomo 数据目录");
            }

            ProcessBuilder pb = new ProcessBuilder(
                    launcher.getAbsolutePath(),
                    "-mihomo", mihomo.getAbsolutePath(),
                    "-config", configPath,
                    "-home", home.getAbsolutePath());
            pb.redirectErrorStream(true);
            core = pb.start();
            startLogPump(core);
            watchExit(core);

            if (!handOverFd(tun.getFileDescriptor())) {
                throw new IOException("启动器没有接收 tun fd");
            }
            running = true;
            lastLog = "mihomo 已接管隧道";
            remember("mihomo 已接管隧道");
            Log.i(TAG, "tunnel handed to mihomo");
        } catch (Exception e) {
            lastLog = "启动失败：" + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            Log.e(TAG, "start failed", e);
            stopTunnel();
        }
    }

    /** Retries because the launcher binds its socket a moment after exec. */
    private boolean handOverFd(FileDescriptor fd) {
        for (int attempt = 0; attempt < 50; attempt++) {
            LocalSocket socket = new LocalSocket();
            try {
                socket.connect(new LocalSocketAddress("mccx-core", LocalSocketAddress.Namespace.ABSTRACT));
                socket.setFileDescriptorsForSend(new FileDescriptor[]{fd});
                socket.getOutputStream().write(1);
                socket.getOutputStream().flush();
                return true;
            } catch (IOException e) {
                sleep(100);
            } finally {
                try {
                    socket.close();
                } catch (IOException ignored) {
                }
            }
        }
        return false;
    }

    private void startLogPump(final Process process) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(process.getInputStream(), UTF8));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        lastLog = line;
                        remember(line);
                        Log.i(TAG, line);
                    }
                } catch (Exception ignored) {
                }
            }
        }, "mihomo-log").start();
    }

    /** Reports an engine that died on its own instead of silently dropping the tunnel. */
    private void watchExit(final Process process) {
        new Thread(new Runnable() {
            public void run() {
                int code;
                try {
                    code = process.waitFor();
                } catch (InterruptedException e) {
                    return;
                }
                if (core != process) {
                    return;
                }
                lastLog = "mihomo 退出，code=" + code;
                remember(lastLog);
                if (running) {
                    running = false;
                    stopTunnel();
                }
            }
        }, "mihomo-exit").start();
    }

    private void stopTunnel() {
        running = false;
        if (core != null) {
            // destroy() only signals the launcher; the launcher is what kills
            // mihomo, so give it a moment and then make sure nothing survives.
            final Process dying = core;
            core = null;
            dying.destroy();
            new Thread(new Runnable() {
                public void run() {
                    sleep(900);
                    if (dying.isAlive()) {
                        dying.destroyForcibly();
                    }
                }
            }, "mihomo-kill").start();
        }
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

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    /** Writes the rendered profile next to mihomo's data and starts the engine. */
    public static void start(Context context, String configText) throws Exception {
        File dir = new File(context.getFilesDir(), "mihomo");
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("无法创建配置目录");
        }
        File config = new File(dir, "config.yaml");
        try (FileOutputStream out = new FileOutputStream(config)) {
            out.write(configText.getBytes(UTF8));
        }
        Intent intent = new Intent(context, MihomoVpnService.class)
                .setAction(ACTION_START)
                .putExtra(EXTRA_CONFIG, config.getAbsolutePath());
        context.startService(intent);
    }

    public static void stop(Context context) {
        context.startService(new Intent(context, MihomoVpnService.class).setAction(ACTION_STOP));
    }
}


