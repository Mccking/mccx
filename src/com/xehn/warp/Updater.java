package com.xehn.warp;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.os.Build;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Self-update: reads a small manifest, downloads the APK, checks its SHA-256 and
 * hands it to the system installer through a {@link PackageInstaller} session.
 *
 * <p>No FileProvider and no storage permission: the session API writes the bytes
 * through the installer itself. The user still sees the system install prompt —
 * that is the platform's rule, not something an app can skip.
 */
public final class Updater {

    /**
     * Where the build publishes its manifest, e.g.
     * {@code https://github.com/<owner>/<repo>/releases/latest/download/update.json}.
     * Empty disables the whole feature.
     */
    public static final String MANIFEST_URL = "";

    public interface Log {
        void log(String line);
    }

    public static final class Info {
        public int versionCode;
        public String versionName = "";
        public String url = "";
        public String sha256 = "";
        public String notes = "";
        public String error = "";

        public boolean isNewerThan(int current) {
            return error.isEmpty() && versionCode > current && !url.isEmpty();
        }

        public String describe() {
            if (!error.isEmpty()) {
                return "更新检查失败：" + error;
            }
            return "新版本 " + versionName + "（" + versionCode + "）"
                    + (notes.isEmpty() ? "" : " · " + notes);
        }
    }

    private static final OkHttpClient CLIENT = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(120, TimeUnit.SECONDS)
            .build();

    private Updater() {
    }

    public static int currentVersionCode(Context context) {
        try {
            return context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionCode;
        } catch (Exception e) {
            return 0;
        }
    }

    /** Blocking: reads the manifest and decides whether an update is offered. */
    public static Info check() {
        Info info = new Info();
        if (MANIFEST_URL.isEmpty()) {
            info.error = "未配置更新源";
            return info;
        }
        Response response = null;
        try {
            Request request = new Request.Builder().url(MANIFEST_URL)
                    .header("User-Agent", "mccx-updater")
                    .build();
            response = CLIENT.newCall(request).execute();
            if (!response.isSuccessful() || response.body() == null) {
                info.error = "HTTP " + response.code();
                return info;
            }
            JSONObject json = new JSONObject(response.body().string());
            info.versionCode = json.optInt("versionCode", 0);
            info.versionName = json.optString("versionName", "");
            info.url = json.optString("url", "");
            info.sha256 = json.optString("sha256", "");
            info.notes = json.optString("notes", "");
        } catch (Exception e) {
            info.error = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        } finally {
            if (response != null) {
                response.close();
            }
        }
        return info;
    }

    /** Blocking: downloads, verifies, and opens the system installer. */
    public static void downloadAndInstall(Context context, Info info, Log log) throws Exception {
        if (!info.isNewerThan(currentVersionCode(context))) {
            throw new IOException("没有可安装的新版本");
        }
        File apk = new File(context.getCacheDir(), "update.apk");
        log.log("下载 " + info.versionName + "…");
        download(info.url, apk);
        log.log("下载完成 " + (apk.length() / 1024 / 1024) + " MB");

        if (!info.sha256.isEmpty()) {
            String actual = sha256(apk);
            if (!actual.equalsIgnoreCase(info.sha256)) {
                apk.delete();
                throw new IOException("校验失败：期望 " + info.sha256 + "，实际 " + actual);
            }
            log.log("SHA-256 校验通过");
        }

        PackageInstaller installer = context.getPackageManager().getPackageInstaller();
        PackageInstaller.SessionParams params =
                new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        int sessionId = installer.createSession(params);

        Intent result = new Intent(context, InstallReceiver.class);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            flags |= PendingIntent.FLAG_MUTABLE;
        }
        PendingIntent pending = PendingIntent.getBroadcast(context, sessionId, result, flags);

        try (PackageInstaller.Session session = installer.openSession(sessionId)) {
            try (OutputStream out = session.openWrite("mccx.apk", 0, apk.length());
                 InputStream in = new FileInputStream(apk)) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = in.read(buffer)) > 0) {
                    out.write(buffer, 0, read);
                }
                session.fsync(out);
            }
            session.commit(pending.getIntentSender());
        }

        log.log("已交给系统安装器，请在弹窗里确认");
    }

    private static void download(String url, File target) throws IOException {
        Request request = new Request.Builder().url(url)
                .header("User-Agent", "mccx-updater")
                .build();
        Response response = CLIENT.newCall(request).execute();
        try {
            if (!response.isSuccessful() || response.body() == null) {
                throw new IOException("下载失败：HTTP " + response.code());
            }
            try (InputStream in = response.body().byteStream();
                 FileOutputStream out = new FileOutputStream(target)) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = in.read(buffer)) > 0) {
                    out.write(buffer, 0, read);
                }
            }
        } finally {
            response.close();
        }
    }

    private static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new FileInputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                digest.update(buffer, 0, read);
            }
        }
        StringBuilder hex = new StringBuilder();
        for (byte b : digest.digest()) {
            hex.append(String.format("%02x", b & 0xff));
        }
        return hex.toString();
    }
}
