package com.xehn.warp;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Route-level split: the engine downloads the mainland CIDR table, and this
 * turns it into route entries.
 *
 * <p>Android 13+ can subtract prefixes with {@code excludeRoute}. Older
 * releases only accept routes, so the table has to be inverted into the
 * complement prefixes — that is what {@link #complementV4} does.
 */
public final class SplitRoute {

    /** Longest a downloaded table is trusted, in milliseconds (7 days). */
    public static final long CACHE_TTL_MS = 7L * 24 * 60 * 60 * 1000;

    private SplitRoute() {
    }

    public static File cnFile(Context context) {
        return new File(new File(context.getFilesDir(), "engine"), "cn-cidrs.txt");
    }

    public static boolean cacheFresh(Context context) {
        File file = cnFile(context);
        return file.isFile() && file.length() > 0
                && System.currentTimeMillis() - file.lastModified() < CACHE_TTL_MS;
    }

    /** Reads {@code cn-cidrs.txt}; entries are {@code network, prefixLen}. */
    public static List<int[]> loadCnRoutes(Context context) {
        List<int[]> routes = new ArrayList<int[]>();
        File file = cnFile(context);
        if (!file.isFile()) {
            return routes;
        }
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), "UTF-8"));
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                int slash = line.indexOf('/');
                if (slash <= 0) {
                    continue;
                }
                int network = ipToInt(line.substring(0, slash));
                if (network == Integer.MIN_VALUE) {
                    continue;
                }
                int prefix;
                try {
                    prefix = Integer.parseInt(line.substring(slash + 1));
                } catch (NumberFormatException e) {
                    continue;
                }
                if (prefix < 0 || prefix > 32) {
                    continue;
                }
                routes.add(new int[]{network, prefix});
            }
        } catch (Exception ignored) {
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (Exception ignored) {
                }
            }
        }
        return routes;
    }

    /** Everything outside the given prefixes, as the fewest possible CIDRs. */
    public static List<int[]> complementV4(List<int[]> cn) {
        List<long[]> ranges = new ArrayList<long[]>();
        for (int[] route : cn) {
            long start = route[0] & 0xFFFFFFFFL;
            long size = route[1] == 0 ? 0x100000000L : 1L << (32 - route[1]);
            ranges.add(new long[]{start, start + size - 1});
        }
        Collections.sort(ranges, new Comparator<long[]>() {
            public int compare(long[] a, long[] b) {
                return Long.compare(a[0], b[0]);
            }
        });

        List<long[]> merged = new ArrayList<long[]>();
        for (long[] range : ranges) {
            long[] last = merged.isEmpty() ? null : merged.get(merged.size() - 1);
            if (last != null && range[0] <= last[1] + 1) {
                if (range[1] > last[1]) {
                    last[1] = range[1];
                }
            } else {
                merged.add(new long[]{range[0], range[1]});
            }
        }

        List<int[]> out = new ArrayList<int[]>();
        long cursor = 0;
        long end = 0xFFFFFFFFL;
        for (long[] range : merged) {
            if (range[0] > cursor) {
                out.addAll(rangeToCidrs(cursor, range[0] - 1));
            }
            if (range[1] + 1 > cursor) {
                cursor = range[1] + 1;
            }
            if (cursor > end) {
                return out;
            }
        }
        if (cursor <= end) {
            out.addAll(rangeToCidrs(cursor, end));
        }
        return out;
    }

    /** Splits a closed range into CIDRs, biggest aligned block first. */
    static List<int[]> rangeToCidrs(long startIn, long endIn) {
        List<int[]> out = new ArrayList<int[]>();
        long start = startIn;
        while (start <= endIn) {
            int alignBits = 0;
            while (alignBits < 32 && (start & (1L << alignBits)) == 0L) {
                alignBits++;
            }
            long size = 1L << alignBits;
            while (size > endIn - start + 1) {
                size >>= 1;
            }
            int prefix = 32;
            long value = size;
            while (value > 1) {
                value >>= 1;
                prefix--;
            }
            out.add(new int[]{(int) start, prefix});
            start += size;
        }
        return out;
    }

    /**
     * Parses custom rules for the blacklist policy: one {@code proxy,<cidr>} per
     * line. Anything malformed is skipped — a typo must never block connecting.
     */
    public static List<String[]> parseProxyCidrs(String text) {
        List<String[]> out = new ArrayList<String[]>();
        if (text == null) {
            return out;
        }
        for (String raw : text.split("\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int comma = line.indexOf(',');
            if (comma <= 0) {
                continue;
            }
            String action = line.substring(0, comma).trim();
            if (!"proxy".equalsIgnoreCase(action)) {
                continue;
            }
            String cidr = line.substring(comma + 1).trim();
            int slash = cidr.indexOf('/');
            if (slash <= 0) {
                continue;
            }
            int network = ipToInt(cidr.substring(0, slash));
            if (network == Integer.MIN_VALUE) {
                continue;
            }
            int prefix;
            try {
                prefix = Integer.parseInt(cidr.substring(slash + 1));
            } catch (NumberFormatException e) {
                continue;
            }
            if (prefix < 0 || prefix > 32) {
                continue;
            }
            out.add(new String[]{intToIp(network), String.valueOf(prefix)});
        }
        return out;
    }
    public static String intToIp(int value) {
        return ((value >>> 24) & 0xFF) + "." + ((value >>> 16) & 0xFF) + "."
                + ((value >>> 8) & 0xFF) + "." + (value & 0xFF);
    }

    public static byte[] intToBytes(int value) {
        return new byte[]{
                (byte) ((value >>> 24) & 0xFF),
                (byte) ((value >>> 16) & 0xFF),
                (byte) ((value >>> 8) & 0xFF),
                (byte) (value & 0xFF),
        };
    }

    /** @return the address as a signed int, or {@code Integer.MIN_VALUE} on error. */
    public static int ipToInt(String text) {
        String[] parts = text.trim().split("\\.");
        if (parts.length != 4) {
            return Integer.MIN_VALUE;
        }
        int value = 0;
        for (String part : parts) {
            int number;
            try {
                number = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                return Integer.MIN_VALUE;
            }
            if (number < 0 || number > 255) {
                return Integer.MIN_VALUE;
            }
            value = (value << 8) | number;
        }
        return value;
    }
}

