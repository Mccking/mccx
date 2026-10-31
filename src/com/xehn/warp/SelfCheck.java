package com.xehn.warp;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Post-connect self check: asks Cloudflare's trace endpoint who we look like now.
 *
 * <p>This request goes through the tunnel like any other app traffic (the app
 * never calls {@code protect()} on its own sockets), so a reply with
 * {@code warp=on} is direct evidence that traffic is really exiting through
 * WARP rather than leaking over the mobile network.
 */
public final class SelfCheck {

    private static final String[] TRACE_URLS = {
            "https://www.cloudflare.com/cdn-cgi/trace",
            "https://1.1.1.1/cdn-cgi/trace",
    };

    private static final OkHttpClient CLIENT = new OkHttpClient.Builder()
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(8, TimeUnit.SECONDS)
            .build();

    public static final class Info {
        public String exitIp = "";
        public String warp = "";
        public String colo = "";
        public String location = "";
        public String error = "";

        public boolean throughWarp() {
            return "on".equals(warp);
        }

        public String describe() {
            if (!error.isEmpty()) {
                return "自检失败：" + error;
            }
            StringBuilder b = new StringBuilder();
            b.append("出口 ").append(exitIp.isEmpty() ? "?" : exitIp);
            b.append(" · WARP ").append(warp.isEmpty() ? "?" : warp);
            if (!colo.isEmpty()) {
                b.append(" · ").append(colo);
            }
            if (!location.isEmpty()) {
                b.append(" (").append(location).append(')');
            }
            return b.toString();
        }
    }

    private SelfCheck() {
    }

    public static Info run() {
        Info last = new Info();
        for (String url : TRACE_URLS) {
            Info info = fetch(url);
            if (info.error.isEmpty()) {
                return info;
            }
            last = info;
        }
        return last;
    }

    private static Info fetch(String url) {
        Info info = new Info();
        Request request = new Request.Builder()
                .url(url)
                .header("User-Agent", "xehn-android/2.2")
                .build();
        Response response = null;
        try {
            response = CLIENT.newCall(request).execute();
            if (!response.isSuccessful() || response.body() == null) {
                info.error = "HTTP " + response.code();
                return info;
            }
            String body = response.body().string();
            for (String line : body.split("\n")) {
                int eq = line.indexOf('=');
                if (eq <= 0) {
                    continue;
                }
                String key = line.substring(0, eq).trim();
                String value = line.substring(eq + 1).trim();
                if ("ip".equals(key)) {
                    info.exitIp = value;
                } else if ("warp".equals(key)) {
                    info.warp = value;
                } else if ("colo".equals(key)) {
                    info.colo = value;
                } else if ("loc".equals(key)) {
                    info.location = value;
                }
            }
            if (info.exitIp.isEmpty() && info.warp.isEmpty()) {
                info.error = "trace 响应缺少字段";
            }
            return info;
        } catch (IOException e) {
            info.error = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            return info;
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }
}
