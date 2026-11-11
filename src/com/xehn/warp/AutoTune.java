package com.xehn.warp;

import android.content.Context;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Automatic best-configuration test.
 *
 * <p>Ports 2408/500/1701/443 carry WireGuard over UDP, so a TCP probe says
 * nothing about them — the only honest test is a real handshake. This walks the
 * candidate ports, tries a few endpoint IPs per port, and scores each by
 * handshake time and received traffic before tearing the tunnel down again.
 *
 * <p>The winner is stored and reused for the next connections; a stale or
 * failing choice falls back to the normal scan.
 */
public final class AutoTune {

    /** How long a saved choice is trusted before the next test. */
    public static final long TTL_MS = 12L * 60 * 60 * 1000;
    private static final long HANDSHAKE_WAIT_MS = 5000;
    private static final int IPS_PER_PORT = 3;
    private static final int CANDIDATE_IPS = 5;

    public static final class Choice {
        public String ip = "";
        public int port;
        public long handshakeMs = -1;
        public long rxBytes;
        public long ts;

        public String label() {
            return ip + ":" + port;
        }

        public String toJson() {
            try {
                JSONObject o = new JSONObject();
                o.put("ip", ip);
                o.put("port", port);
                o.put("handshakeMs", handshakeMs);
                o.put("rxBytes", rxBytes);
                o.put("ts", ts);
                return o.toString();
            } catch (Exception e) {
                return "";
            }
        }

        public static Choice fromJson(String json) {
            if (json == null || json.isEmpty()) {
                return null;
            }
            try {
                JSONObject o = new JSONObject(json);
                Choice choice = new Choice();
                choice.ip = o.optString("ip", "");
                choice.port = o.optInt("port", 0);
                choice.handshakeMs = o.optLong("handshakeMs", -1);
                choice.rxBytes = o.optLong("rxBytes", 0);
                choice.ts = o.optLong("ts", 0);
                return choice.ip.isEmpty() || choice.port == 0 ? null : choice;
            } catch (Exception e) {
                return null;
            }
        }

        public boolean fresh() {
            return ts > 0 && System.currentTimeMillis() - ts < TTL_MS;
        }
    }

    private AutoTune() {
    }

    /**
     * Runs the test. Blocking; must be called off the UI thread and only while
     * no tunnel is up (it brings the backend up and down several times).
     */
    public static Choice run(Context context, Warp.Account account, int[] ports, Warp.Log log) {
        if (account == null || !account.usable()) {
            log.log("自动优选：还没有可用设备，先连接一次再试");
            return null;
        }
        log.log("自动优选：测量 " + ports.length + " 个端口的真实握手…");

        List<String> ips = candidateIps(log);
        if (ips.isEmpty()) {
            log.log("自动优选：没有可用候选 IP");
            return null;
        }

        List<Choice> results = new ArrayList<Choice>();
        for (int port : ports) {
            Choice best = null;
            int tried = 0;
            for (String ip : ips) {
                if (tried >= IPS_PER_PORT) {
                    break;
                }
                tried++;
                Choice choice = handshakeTest(context, account, ip, port);
                if (choice == null) {
                    continue;
                }
                if (best == null || score(choice) > score(best)) {
                    best = choice;
                }
                // one working handshake for this port is enough to rate it
                break;
            }
            if (best != null) {
                results.add(best);
                log.log(String.format(java.util.Locale.US, "端口 %d：%s 握手 %d ms，收到 %d B",
                        port, best.ip, best.handshakeMs, best.rxBytes));
            } else {
                log.log("端口 " + port + "：握手失败");
            }
        }

        if (results.isEmpty()) {
            log.log("自动优选：所有端口都没握手成功，保留原配置");
            return null;
        }
        Collections.sort(results, new Comparator<Choice>() {
            public int compare(Choice a, Choice b) {
                return Long.compare(score(b), score(a));
            }
        });
        Choice winner = results.get(0);
        winner.ts = System.currentTimeMillis();
        log.log("自动优选：最佳 " + winner.label() + "（握手 " + winner.handshakeMs + " ms，"
                + winner.rxBytes + " B）");
        return winner;
    }

    /** Traffic decides; handshake time breaks ties. */
    private static long score(Choice choice) {
        return choice.rxBytes * 1000L - Math.max(1, choice.handshakeMs);
    }

    /** Top endpoints from the normal TCP ranking; enough to test without a long scan. */
    private static List<String> candidateIps(Warp.Log log) {
        List<String> ips = new ArrayList<String>();
        try {
            Warp.Probe probe = Warp.rankEndpoints(new Warp.Log() {
                public void log(String line) {
                }
            });
            if (probe != null) {
                ips.add(probe.ip);
            }
        } catch (Throwable ignored) {
        }
        if (ips.isEmpty()) {
            for (int i = 0; i < Math.min(CANDIDATE_IPS, UpstreamDefaults.SCAN_IPS.length); i++) {
                ips.add(UpstreamDefaults.SCAN_IPS[i]);
            }
        } else {
            for (int i = 0; i < Math.min(CANDIDATE_IPS - ips.size(), UpstreamDefaults.SCAN_IPS.length); i++) {
                String ip = UpstreamDefaults.SCAN_IPS[i];
                if (!ips.contains(ip)) {
                    ips.add(ip);
                }
            }
        }
        log.log("自动优选：候选 IP " + ips.size() + " 个");
        return ips;
    }

    /** Brings the tunnel up against one (ip, port) pair and watches the counters. */
    private static Choice handshakeTest(Context context, Warp.Account account, String ip, int port) {
        String endpoint = ip + ":" + port;
        try {
            Warp.Result result = Warp.generateFixed("wg", endpoint, account, new Warp.Log() {
                public void log(String line) {
                }
            });
            TunnelManager.attach(context, null);
            TunnelManager.up(result.config);
            long started = System.currentTimeMillis();
            long handshakeMs = -1;
            long rx = 0;
            while (System.currentTimeMillis() - started < HANDSHAKE_WAIT_MS) {
                TunnelManager.Snapshot snapshot = TunnelManager.snapshot();
                if (snapshot.available) {
                    if (snapshot.handshakeMs > 0 && handshakeMs < 0) {
                        handshakeMs = System.currentTimeMillis() - snapshot.handshakeMs;
                        if (handshakeMs < 0) {
                            handshakeMs = 0;
                        }
                    }
                    rx = snapshot.rx;
                    if (rx > 0) {
                        break;
                    }
                }
                try {
                    Thread.sleep(250);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            TunnelManager.down();
            if (handshakeMs < 0 && rx <= 0) {
                return null;
            }
            Choice choice = new Choice();
            choice.ip = ip;
            choice.port = port;
            choice.handshakeMs = handshakeMs < 0 ? -1 : handshakeMs;
            choice.rxBytes = rx;
            return choice;
        } catch (Throwable t) {
            try {
                TunnelManager.down();
            } catch (Throwable ignored) {
            }
            return null;
        }
    }
}
