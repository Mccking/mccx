package com.xehn.warp;

import org.json.JSONObject;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Minimal client for mihomo's external controller.
 *
 * <p>The engine's delay probe is the only honest way to tell whether the tunnel
 * carries traffic: it asks mihomo to fetch a URL <em>through the proxy</em>, so a
 * positive number means the whole chain (tun → wireguard → WARP) works, while
 * "已接管隧道" only means the descriptor was handed over.
 */
public final class MihomoApi {

    private static final String BASE = "http://127.0.0.1:9090";
    private static final String PROBE_URL = "http://www.gstatic.com/generate_204";

    private static final OkHttpClient CLIENT = new OkHttpClient.Builder()
            .connectTimeout(3, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build();

    private MihomoApi() {
    }

    /** Milliseconds the proxy took, or throws with the engine's own reason. */
    public static int delay(String proxyName, int timeoutMs) throws IOException {
        String url;
        try {
            url = BASE + "/proxies/" + proxyName + "/delay?timeout=" + timeoutMs
                    + "&url=" + URLEncoder.encode(PROBE_URL, "UTF-8");
        } catch (Exception e) {
            throw new IOException("URL 编码失败");
        }
        Request request = new Request.Builder().url(url).build();
        Response response = null;
        try {
            response = CLIENT.newCall(request).execute();
            String body = response.body() == null ? "" : response.body().string();
            if (!response.isSuccessful()) {
                throw new IOException("HTTP " + response.code() + " " + body.trim());
            }
            JSONObject json = new JSONObject(body);
            int delay = json.optInt("delay", 0);
            if (delay <= 0) {
                throw new IOException(json.optString("message", "delay=0"));
            }
            return delay;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }
}
