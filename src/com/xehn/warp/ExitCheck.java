package com.xehn.warp;

import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Exit inspection: what the internet actually sees once the tunnel is up.
 *
 * <p>Inspired by CFPilot's "真连接" idea — numbers that come from a real HTTPS
 * request through the tunnel, never from a cached or self-reported field. Each
 * probe reports its own round trip, and a failed probe says so instead of
 * printing a misleading zero.
 */
public final class ExitCheck {

    private static final OkHttpClient CLIENT = new OkHttpClient.Builder()
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build();

    private ExitCheck() {
    }

    private static final class Probe {
        int code;
        long ms;
        String body = "";
        String error = "";
    }

    public static String run() {
        StringBuilder out = new StringBuilder();

        Probe trace = probe("https://www.cloudflare.com/cdn-cgi/trace");
        if (!trace.error.isEmpty()) {
            out.append("Cloudflare：失败（").append(trace.error).append("）\n");
        } else {
            String ip = field(trace.body, "ip");
            String loc = field(trace.body, "loc");
            String warp = field(trace.body, "warp");
            out.append("出口 IP：").append(ip.isEmpty() ? "未知" : ip);
            if (!loc.isEmpty()) {
                out.append("  ·  ").append(loc);
            }
            if (!warp.isEmpty()) {
                out.append("  ·  warp=").append(warp);
            }
            out.append("  ·  ").append(trace.ms).append(" ms\n");
        }

        out.append(check("YouTube", "https://www.youtube.com/generate_204", 204));
        out.append(check("Google", "https://www.google.com/generate_204", 204));
        out.append(check("ChatGPT", "https://chatgpt.com/cdn-cgi/trace", 200));
        out.append(check("GitHub", "https://github.com/", 200));
        return out.toString();
    }

    private static String check(String name, String url, int expected) {
        Probe probe = probe(url);
        if (!probe.error.isEmpty()) {
            return name + "：不可达（" + probe.error + "）\n";
        }
        boolean ok = probe.code == expected;
        return name + "：" + (ok ? "可访问" : "异常") + "（HTTP " + probe.code
                + "，" + probe.ms + " ms）\n";
    }

    private static Probe probe(String url) {
        Probe probe = new Probe();
        Request request = new Request.Builder()
                .url(url)
                .header("User-Agent", "Mozilla/5.0 (Linux; Android 13) MccX")
                .build();
        long started = System.nanoTime();
        Response response = null;
        try {
            response = CLIENT.newCall(request).execute();
            probe.code = response.code();
            probe.body = response.body() == null ? "" : response.body().string();
        } catch (Exception e) {
            probe.error = e.getClass().getSimpleName()
                    + (e.getMessage() == null ? "" : ": " + e.getMessage());
        } finally {
            probe.ms = (System.nanoTime() - started) / 1000000L;
            if (response != null) {
                try {
                    response.close();
                } catch (Exception ignored) {
                }
            }
        }
        return probe;
    }

    private static String field(String body, String key) {
        for (String line : body.split("\n")) {
            int eq = line.indexOf('=');
            if (eq > 0 && line.substring(0, eq).equals(key)) {
                return line.substring(eq + 1).trim();
            }
        }
        return "";
    }
}
