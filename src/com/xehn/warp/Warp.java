package com.xehn.warp;

import org.json.JSONArray;

import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import okhttp3.Dns;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * The WARP half of XEHN, reduced to what a configuration generator needs:
 * register a device with Cloudflare, rank the edge endpoints, render a
 * WireGuard / AmneziaWG profile.
 *
 * <p>HTTP goes through OkHttp on purpose: enabling WARP needs a {@code PATCH},
 * and the platform {@code HttpURLConnection} rejects that method outright.
 *
 * <p>The endpoint ranking mirrors warpscout's TCP-handshake probe: WARP itself
 * speaks UDP, but a TCP connect to 443 on the same anycast address measures the
 * round trip to the edge that will carry the tunnel, and it survives the DPI
 * that would eat an ICMP probe.
 */
public final class Warp {

    public static final String REG_URL = UpstreamDefaults.REG_URL;
    private static final String USER_AGENT = UpstreamDefaults.USER_AGENT;
    private static final String CF_CLIENT_VERSION = UpstreamDefaults.CF_CLIENT_VERSION;
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private static final int CONNECT_TIMEOUT_MS = 12000;
    private static final int READ_TIMEOUT_MS = 20000;
    private static final int PROBE_TIMEOUT_MS = 900;
    private static final int PROBE_THREADS = 16;
    /** Finalists that get a real download before the endpoint is chosen. */
    private static final int SPEED_PROBE_COUNT = 4;
    private static final int SPEED_PROBE_BYTES = 512 * 1024;
    private static final long SPEED_PROBE_DEADLINE_MS = 2500;

    private static final OkHttpClient CLIENT = new OkHttpClient.Builder()
            .connectTimeout(CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .readTimeout(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .writeTimeout(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .build();

    /**
     * Upstream's WARP pools (synced by tools/sync_upstream.ps1) plus two edges
     * this device has measured well but upstream does not list.
     */
    private static final String[] EXTRA_ENDPOINTS = {
            "162.159.204.1", "162.159.204.2",
    };

    private static final String[] SCAN_IPS = mergeScanList();

    private static String[] mergeScanList() {
        String[] upstream = UpstreamDefaults.SCAN_IPS;
        String[] merged = new String[upstream.length + EXTRA_ENDPOINTS.length];
        System.arraycopy(upstream, 0, merged, 0, upstream.length);
        System.arraycopy(EXTRA_ENDPOINTS, 0, merged, upstream.length, EXTRA_ENDPOINTS.length);
        return merged;
    }

    public static final String DEFAULT_ENDPOINT = "engage.cloudflareclient.com:2408";

    /** AmneziaWG junk-packet defaults, synced from the desktop client. */
    private static final int AWG_JC = UpstreamDefaults.AWG_JC;
    private static final int AWG_JMIN = UpstreamDefaults.AWG_JMIN;
    private static final int AWG_JMAX = UpstreamDefaults.AWG_JMAX;

    private Warp() {
    }

    // ---------------------------------------------------------------- model

    /** One WARP device registration. */
    public static final class Account {
        public String id = "";
        public String token = "";
        public String privateKey = "";
        public String peerPublicKey = "";
        public String ipv4 = "";
        public String ipv6 = "";
        public String clientId = "";
        public boolean warpEnabled;

        public boolean usable() {
            return id.length() > 0 && token.length() > 0 && peerPublicKey.length() > 0;
        }

        public String toJson() {
            try {
                JSONObject o = new JSONObject();
                o.put("id", id);
                o.put("token", token);
                o.put("private_key", privateKey);
                o.put("peer_public_key", peerPublicKey);
                o.put("ipv4", ipv4);
                o.put("ipv6", ipv6);
                o.put("client_id", clientId);
                o.put("warp_enabled", warpEnabled);
                return o.toString();
            } catch (Exception e) {
                return "";
            }
        }

        public static Account fromJson(String json) {
            if (json == null || json.length() == 0) {
                return null;
            }
            try {
                JSONObject o = new JSONObject(json);
                Account a = new Account();
                a.id = o.optString("id", "");
                a.token = o.optString("token", "");
                a.privateKey = o.optString("private_key", "");
                a.peerPublicKey = o.optString("peer_public_key", "");
                a.ipv4 = o.optString("ipv4", "");
                a.ipv6 = o.optString("ipv6", "");
                a.clientId = o.optString("client_id", "");
                a.warpEnabled = o.optBoolean("warp_enabled", false);
                return a.usable() ? a : null;
            } catch (Exception e) {
                return null;
            }
        }
    }

    /** What the UI shows once a generation run finished. */
    public static final class Result {
        public String config = "";
        public String endpoint = "";
        public long latencyMs = -1;
        public Account account;
    }

    public interface Log {
        void log(String line);
    }

    // ------------------------------------------------------------- pipeline

    /**
     * Registers (or reuses) a device, optionally ranks the endpoints, and
     * renders the profile. Blocking: call it off the UI thread.
     */
    public static Result generate(String protocol, int port, boolean scan,
                                  Account existing, Log log) throws Exception {
        Account account = ensureAccount(existing, log);

        String endpoint = DEFAULT_ENDPOINT;
        long latency = -1;
        if (scan) {
            log.log("扫描优选端点（" + SCAN_IPS.length + " 个候选）…");
            Probe best = rankEndpoints(log);
            if (best != null) {
                endpoint = best.ip + ":" + port;
                latency = best.millis;
                log.log(String.format(java.util.Locale.US, "最优端点：%s  %d ms  %.1f MB/s", best.ip, best.millis, best.bytesPerSecond / 1048576.0));
            } else {
                log.log("扫描无结果，退回默认端点 " + DEFAULT_ENDPOINT);
            }
        }
        return build(protocol, endpoint, latency, account, log);
    }

    /** Same device, fixed endpoint: the fallback when the scanned IP never handshakes. */
    public static Result generateFixed(String protocol, String endpoint,
                                       Account existing, Log log) throws Exception {
        Account account = ensureAccount(existing, log);
        log.log("改用固定端点 " + endpoint);
        return build(protocol, endpoint, -1, account, log);
    }

    private static Account ensureAccount(Account existing, Log log) throws Exception {
        Account account;
        if (existing != null && existing.usable() && existing.warpEnabled) {
            // The device is already on the WARP service: a new endpoint or port
            // only changes the rendered profile, not the registration, and the
            // API offers no working key rotation anyway.
            log.log("复用已注册设备：" + existing.ipv4);
            account = existing;
        } else {
            log.log("向 Cloudflare 注册 WARP 设备…");
            account = register();
        }
        log.log("设备就绪：" + account.ipv4 + (account.ipv6.isEmpty() ? "" : " / " + account.ipv6));
        log.log(account.warpEnabled ? "WARP 已在设备上启用" : "警告：设备未确认启用 WARP，隧道可能不通");
        log.log("引擎基线 xehn@" + shortCommit());
        return account;
    }

    private static Result build(String protocol, String endpoint, long latency,
                                Account account, Log log) {
        Result result = new Result();
        result.account = account;
        result.endpoint = endpoint;
        result.latencyMs = latency;
        result.config = render(protocol, endpoint, account);
        log.log("配置已生成（" + protocol.toUpperCase() + "）");
        return result;
    }

    // --------------------------------------------------------- registration

    private static Account register() throws Exception {
        byte[] priv = Curve25519.randomPrivateKey();
        byte[] pub = Curve25519.publicKey(priv);

        JSONObject body = new JSONObject();
        body.put("key", base64(pub));

        String response = request("POST", REG_URL, body.toString(), null);
        Account account = parse(response);
        account.privateKey = base64(priv);

        // warp_enabled is what actually puts the device on the WARP service.
        try {
            JSONObject patch = new JSONObject();
            patch.put("warp_enabled", true);
            String patched = request("PATCH", REG_URL + "/" + account.id, patch.toString(), account.token);
            account.warpEnabled = new JSONObject(patched).optBoolean("warp_enabled", true);
        } catch (Exception e) {
            account.warpEnabled = false;
        }
        return account;
    }

    private static Account parse(String response) throws Exception {
        JSONObject root = new JSONObject(response);
        Account account = new Account();
        account.id = root.optString("id", "");
        account.token = root.optString("token", "");
        account.warpEnabled = root.optBoolean("warp_enabled", false);

        JSONObject config = root.optJSONObject("config");
        if (config != null) {
            account.clientId = config.optString("client_id", "");
            JSONObject iface = config.optJSONObject("interface");
            if (iface != null) {
                JSONObject addresses = iface.optJSONObject("addresses");
                if (addresses != null) {
                    account.ipv4 = addresses.optString("v4", "");
                    account.ipv6 = addresses.optString("v6", "");
                }
            }
            JSONArray peers = config.optJSONArray("peers");
            if (peers != null && peers.length() > 0) {
                JSONObject peer = peers.getJSONObject(0);
                account.peerPublicKey = peer.optString("public_key", "");
            }
        }
        if (!account.usable()) {
            throw new IOException("注册响应缺少 peer 公钥或设备凭据");
        }
        return account;
    }

    private static String request(String method, String url, String body, String token) throws IOException {
        return requestAs(method, url, body, token, USER_AGENT, CF_CLIENT_VERSION);
    }

    /** Same call with an explicit client identity (the MASQUE API wants its own). */
    static String requestAs(String method, String url, String body, String token,
                            String userAgent, String clientVersion) throws IOException {
        RequestBody payload = body == null ? null : RequestBody.create(JSON, body);
        Request.Builder builder = new Request.Builder()
                .url(url)
                .header("User-Agent", userAgent)
                .header("CF-Client-Version", clientVersion)
                .header("Accept", "application/json")
                .method(method, payload);
        if (token != null && token.length() > 0) {
            builder.header("Authorization", "Bearer " + token);
        }

        Response response = CLIENT.newCall(builder.build()).execute();
        try {
            String text = response.body() == null ? "" : response.body().string();
            if (!response.isSuccessful()) {
                throw new IOException("HTTP " + response.code() + ": " + text.trim());
            }
            return text;
        } finally {
            response.close();
        }
    }

    // -------------------------------------------------------------- ranking

    public static final class Probe {
        final String ip;
        final long millis;
        long bytesPerSecond;

        Probe(String ip, long millis) {
            this.ip = ip;
            this.millis = millis;
        }
    }

    /**
     * Ranks edges the way CloudflareSpeedTest does: latency first to cut the
     * list down, then a real download through each finalist. A 20 ms edge that
     * pushes 200 KB/s is worse than a 60 ms edge that pushes 8 MB/s.
     */
    public static Probe rankEndpoints(Log log) throws InterruptedException {
        List<Probe> alive = new ArrayList<Probe>();
        ExecutorService pool = Executors.newFixedThreadPool(PROBE_THREADS);
        List<Future<Probe>> futures = new ArrayList<Future<Probe>>();
        try {
            for (final String ip : SCAN_IPS) {
                futures.add(pool.submit(new Callable<Probe>() {
                    public Probe call() {
                        return probe(ip);
                    }
                }));
            }
            pool.shutdown();
            pool.awaitTermination(PROBE_TIMEOUT_MS * 4L, TimeUnit.MILLISECONDS);

            for (Future<Probe> f : futures) {
                if (!f.isDone() || f.isCancelled()) {
                    continue;
                }
                try {
                    Probe p = f.get();
                    if (p != null) {
                        alive.add(p);
                    }
                } catch (Exception ignored) {
                }
            }
        } finally {
            pool.shutdownNow();
        }
        if (alive.isEmpty()) {
            return null;
        }

        Collections.sort(alive, new Comparator<Probe>() {
            public int compare(Probe a, Probe b) {
                return a.millis < b.millis ? -1 : (a.millis > b.millis ? 1 : 0);
            }
        });

        // Measure the finalists in parallel: four sequential 2.5 s samples turned
        // a 6 s connect into a 12 s connect.
        int finalists = Math.min(SPEED_PROBE_COUNT, alive.size());
        List<Probe> shortlist = new ArrayList<Probe>(alive.subList(0, finalists));
        ExecutorService speedPool = Executors.newFixedThreadPool(finalists);
        List<Future<Long>> speedFutures = new ArrayList<Future<Long>>();
        try {
            for (final Probe candidate : shortlist) {
                speedFutures.add(speedPool.submit(new Callable<Long>() {
                    public Long call() {
                        return measureThroughput(candidate.ip);
                    }
                }));
            }
            speedPool.shutdown();
            speedPool.awaitTermination(SPEED_PROBE_DEADLINE_MS * 2L, TimeUnit.MILLISECONDS);
        } finally {
            speedPool.shutdownNow();
        }

        Probe best = null;
        for (int i = 0; i < shortlist.size(); i++) {
            Probe candidate = shortlist.get(i);
            try {
                Future<Long> future = speedFutures.get(i);
                if (future.isDone() && !future.isCancelled()) {
                    Long value = future.get();
                    candidate.bytesPerSecond = value == null ? 0 : value;
                }
            } catch (Exception ignored) {
            }
            log.log(String.format(java.util.Locale.US, "候选 %s  %d ms  %.1f MB/s",
                    candidate.ip, candidate.millis, candidate.bytesPerSecond / 1048576.0));
            if (best == null || candidate.bytesPerSecond > best.bytesPerSecond) {
                best = candidate;
            }
        }
        // Nothing measurable (small quota, captive portal): latency decides.
        if (best == null || best.bytesPerSecond == 0) {
            return alive.get(0);
        }
        return best;
    }

    /** One download through a pinned edge, so the measurement is real traffic. */
    public static long measureThroughput(final String ip) {
        Dns pinned = new Dns() {
            public List<InetAddress> lookup(String hostname) throws UnknownHostException {
                return Collections.singletonList(InetAddress.getByName(ip));
            }
        };
        OkHttpClient client = CLIENT.newBuilder()
                .dns(pinned)
                .readTimeout(6, TimeUnit.SECONDS)
                .build();
        Request request = new Request.Builder()
                .url("https://speed.cloudflare.com/__down?bytes=" + SPEED_PROBE_BYTES)
                .header("User-Agent", USER_AGENT)
                .build();
        long started = System.nanoTime();
        long bytes = 0;
        Response response = null;
        try {
            response = client.newCall(request).execute();
            if (!response.isSuccessful() || response.body() == null) {
                return 0;
            }
            InputStream in = response.body().byteStream();
            byte[] buffer = new byte[32 * 1024];
            int read;
            while (bytes < SPEED_PROBE_BYTES && (read = in.read(buffer)) > 0) {
                if ((System.nanoTime() - started) / 1000000L > SPEED_PROBE_DEADLINE_MS) {
                    break;
                }
                bytes += read;
            }
        } catch (Exception e) {
            return 0;
        } finally {
            if (response != null) {
                response.close();
            }
        }
        long millis = Math.max(1L, (System.nanoTime() - started) / 1000000L);
        return bytes * 1000L / millis;
    }
    private static Probe probe(String ip) {
        Socket socket = new Socket();
        long started = System.nanoTime();
        try {
            socket.connect(new InetSocketAddress(ip, 443), PROBE_TIMEOUT_MS);
            return new Probe(ip, (System.nanoTime() - started) / 1000000L);
        } catch (IOException e) {
            return null;
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    // ------------------------------------------------------------- rendering

    private static String render(String protocol, String endpoint, Account account) {
        boolean awg = "awg".equalsIgnoreCase(protocol);
        StringBuilder b = new StringBuilder();
        b.append("# XEHN for Android — WARP profile\n");
        b.append("# 由 xehn 引擎逻辑生成 · 导入 WireGuard").append(awg ? " / AmneziaWG" : "").append(" 客户端使用\n\n");

        b.append("[Interface]\n");
        b.append("PrivateKey = ").append(account.privateKey).append('\n');
        b.append("Address = ").append(account.ipv4).append("/32");
        if (account.ipv6 != null && account.ipv6.length() > 0) {
            b.append(", ").append(account.ipv6).append("/128");
        }
        b.append('\n');
        b.append("DNS = 1.1.1.1, 1.0.0.1\n");
        b.append("MTU = ").append(UpstreamDefaults.TUNNEL_MTU).append('\n');
        if (awg) {
            // Junk packets only: the handshake headers stay at the standard
            // WireGuard values (H1..H4 = 1..4), which is what makes an
            // AmneziaWG profile usable against Cloudflare's plain-WG edges.
            b.append("Jc = ").append(AWG_JC).append('\n');
            b.append("Jmin = ").append(AWG_JMIN).append('\n');
            b.append("Jmax = ").append(AWG_JMAX).append('\n');
            b.append("S1 = 0\n");
            b.append("S2 = 0\n");
            b.append("H1 = 1\n");
            b.append("H2 = 2\n");
            b.append("H3 = 3\n");
            b.append("H4 = 4\n");
        }

        b.append("\n[Peer]\n");
        b.append("PublicKey = ").append(account.peerPublicKey).append('\n');
        b.append("Endpoint = ").append(endpoint).append('\n');
        b.append("AllowedIPs = 0.0.0.0/0, ::/0\n");
        b.append("PersistentKeepalive = ").append(UpstreamDefaults.KEEPALIVE).append('\n');
        return b.toString();
    }

    // ---------------------------------------------------------------- util

    /** First 7 chars of the upstream commit this build's constants came from. */
    static String shortCommit() {
        String sha = UpstreamDefaults.UPSTREAM_COMMIT;
        return sha.length() >= 7 ? sha.substring(0, 7) : sha;
    }

    public static String base64(byte[] data) {
        final char[] table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
        StringBuilder out = new StringBuilder((data.length + 2) / 3 * 4);
        int i = 0;
        while (i + 2 < data.length) {
            int n = ((data[i] & 0xff) << 16) | ((data[i + 1] & 0xff) << 8) | (data[i + 2] & 0xff);
            out.append(table[(n >> 18) & 63]).append(table[(n >> 12) & 63])
                    .append(table[(n >> 6) & 63]).append(table[n & 63]);
            i += 3;
        }
        int rest = data.length - i;
        if (rest == 1) {
            int n = (data[i] & 0xff) << 16;
            out.append(table[(n >> 18) & 63]).append(table[(n >> 12) & 63]).append("==");
        } else if (rest == 2) {
            int n = ((data[i] & 0xff) << 16) | ((data[i + 1] & 0xff) << 8);
            out.append(table[(n >> 18) & 63]).append(table[(n >> 12) & 63])
                    .append(table[(n >> 6) & 63]).append('=');
        }
        return out.toString();
    }
}










