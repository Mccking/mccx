package com.xehn.warp;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Keeps a copy of the run log on disk.
 *
 * <p>The in-memory view is gone as soon as the process dies, which is exactly
 * when a failure needs explaining. The file lives in the app's external files
 * directory so it can be pulled with a file manager without any permission;
 * it rotates once at half a megabyte so it cannot grow without bound.
 */
public final class LogStore {

    private static final long MAX_BYTES = 512 * 1024;
    private static final Object LOCK = new Object();
    private static final ExecutorService WRITER = Executors.newSingleThreadExecutor();
    private static final SimpleDateFormat TIME =
            new SimpleDateFormat("MM-dd HH:mm:ss", Locale.US);

    private static File current;

    private LogStore() {
    }

    public static void init(Context context) {
        File dir = context.getExternalFilesDir("logs");
        if (dir == null) {
            dir = new File(context.getFilesDir(), "logs");
        }
        if (!dir.exists() && !dir.mkdirs()) {
            return;
        }
        current = new File(dir, "mccx.log");
    }

    public static File file() {
        return current;
    }

    public static void append(final String line) {
        if (current == null) {
            return;
        }
        WRITER.execute(new Runnable() {
            public void run() {
                write(line);
            }
        });
    }

    private static void write(String line) {
        synchronized (LOCK) {
            try {
                if (current.length() > MAX_BYTES) {
                    File previous = new File(current.getParentFile(), "mccx.prev.log");
                    if (previous.exists() && !previous.delete()) {
                        // keep going; appending is still better than losing the line
                    }
                    if (!current.renameTo(previous)) {
                        // fall through and keep appending
                    }
                }
                FileOutputStream out = new FileOutputStream(current, true);
                try {
                    OutputStreamWriter writer = new OutputStreamWriter(out, "UTF-8");
                    writer.write(TIME.format(new Date()));
                    writer.write(' ');
                    writer.write(line);
                    writer.write('\n');
                    writer.flush();
                } finally {
                    out.close();
                }
            } catch (Exception ignored) {
            }
        }
    }

    /** Last part of the file, for sharing without blowing up an intent. */
    public static String tail(int maxChars) {
        if (current == null || !current.exists()) {
            return "";
        }
        try {
            java.io.RandomAccessFile raf = new java.io.RandomAccessFile(current, "r");
            try {
                long length = raf.length();
                long start = Math.max(0, length - maxChars);
                raf.seek(start);
                byte[] buffer = new byte[(int) (length - start)];
                raf.readFully(buffer);
                return new String(buffer, "UTF-8");
            } finally {
                raf.close();
            }
        } catch (Exception e) {
            return "";
        }
    }
}
