package com.xehn.warp;

import android.content.Context;

import com.wireguard.android.backend.GoBackend;
import com.wireguard.android.backend.Statistics;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.crypto.Key;
import com.wireguard.config.Config;

import java.io.BufferedReader;
import java.io.StringReader;

/**
 * Holds the single WireGuard backend for the process.
 *
 * <p>Constructing {@link GoBackend} loads {@code libwg-go.so}, and
 * {@code setState} blocks until Android has handed out the TUN interface, so both
 * must stay off the UI thread.
 */
public final class TunnelManager {

    private static GoBackend backend;
    private static WarpTunnel tunnel;

    private TunnelManager() {
    }

    /** Creates (once) and returns the tunnel, re-pointing its state listener. */
    public static synchronized WarpTunnel attach(Context context, WarpTunnel.Listener listener) {
        if (backend == null) {
            backend = new GoBackend(context.getApplicationContext());
        }
        if (tunnel == null) {
            tunnel = new WarpTunnel(listener);
        } else {
            tunnel.setListener(listener);
        }
        return tunnel;
    }

    public static synchronized Tunnel.State state() {
        return tunnel == null ? Tunnel.State.DOWN : tunnel.getState();
    }

    public static synchronized boolean isUp() {
        return tunnel != null && tunnel.getState() == Tunnel.State.UP;
    }

    /** Brings the tunnel up from a wg-quick configuration body. Blocking. */
    public static synchronized void up(String configText) throws Exception {
        requireReady();
        Config config = Config.parse(new BufferedReader(new StringReader(configText)));
        backend.setState(tunnel, Tunnel.State.UP, config);
    }

    /** Tears the tunnel down. Blocking. */
    public static synchronized void down() throws Exception {
        requireReady();
        backend.setState(tunnel, Tunnel.State.DOWN, null);
    }

    /** A snapshot of the WireGuard counters; {@code available} is false if the read failed. */
    public static final class Snapshot {
        public boolean available;
        public long rx;
        public long tx;
        public long handshakeMs;
    }

    public static synchronized Snapshot snapshot() {
        Snapshot snapshot = new Snapshot();
        if (backend == null || tunnel == null) {
            return snapshot;
        }
        try {
            Statistics stats = backend.getStatistics(tunnel);
            if (stats == null) {
                return snapshot;
            }
            snapshot.available = true;
            snapshot.rx = stats.totalRx();
            snapshot.tx = stats.totalTx();
            for (Key peer : stats.peers()) {
                Statistics.PeerStats ps = stats.peer(peer);
                if (ps != null && ps.latestHandshakeEpochMillis() > snapshot.handshakeMs) {
                    snapshot.handshakeMs = ps.latestHandshakeEpochMillis();
                }
            }
        } catch (Throwable ignored) {
            // Counters are a diagnostic, never a control path.
            snapshot.available = false;
        }
        return snapshot;
    }

    /** One line of counters, the cheapest way to tell a blocked UDP path from a working tunnel. */
    public static synchronized String statsLine() {
        Snapshot s = snapshot();
        if (!s.available) {
            return "统计不可用";
        }
        String handshake = s.handshakeMs == 0
                ? "未握手"
                : ((System.currentTimeMillis() - s.handshakeMs) / 1000) + "s 前";
        return "握手 " + handshake + " · rx " + s.rx + "B / tx " + s.tx + "B";
    }

    private static void requireReady() {
        if (backend == null || tunnel == null) {
            throw new IllegalStateException("隧道路由尚未初始化");
        }
    }
}
