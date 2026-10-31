package com.xehn.warp;

// GENERATED FILE - do not edit by hand.
// Source: github.com/hezhanleiok/xehn @ c319e7c709aa54d9da3036338287e3b8fcd94c83
// Commit date: 10/30/2026 13:47:35
// Regenerate: pwsh tools/sync_upstream.ps1
//
// Only the data the Android port consumes is copied here. The Go code itself
// (connect pipeline, mihomo rendering, Windows GUI) has no Android counterpart.
public final class UpstreamDefaults {

    private UpstreamDefaults() {
    }

    public static final String UPSTREAM_COMMIT = "c319e7c709aa54d9da3036338287e3b8fcd94c83";
    public static final String UPSTREAM_DATE = "10/30/2026 13:47:35";

    public static final String REG_URL = "https://api.cloudflareclient.com/v0a4005/reg";
    public static final String CF_CLIENT_VERSION = "a-6.11-2223";
    public static final String USER_AGENT = "okhttp/3.12.1";

    public static final int TUNNEL_MTU = 1280;
    public static final int KEEPALIVE = 25;
    public static final int AWG_JC = 6;
    public static final int AWG_JMIN = 10;
    public static final int AWG_JMAX = 50;

    /** WARP edge pools from the upstream scanner, four hosts per prefix. */
    public static final String[] SCAN_IPS = {
            "8.6.112.1", "8.6.112.2", "8.6.112.3", "8.6.112.4",
            "8.34.70.1", "8.34.70.2", "8.34.70.3", "8.34.70.4",
            "8.34.146.1", "8.34.146.2", "8.34.146.3", "8.34.146.4",
            "8.35.211.1", "8.35.211.2", "8.35.211.3", "8.35.211.4",
            "8.39.125.1", "8.39.125.2", "8.39.125.3", "8.39.125.4",
            "8.39.204.1", "8.39.204.2", "8.39.204.3", "8.39.204.4",
            "8.39.214.1", "8.39.214.2", "8.39.214.3", "8.39.214.4",
            "8.47.69.1", "8.47.69.2", "8.47.69.3", "8.47.69.4",
            "162.159.192.1", "162.159.192.2", "162.159.192.3", "162.159.192.4",
            "162.159.195.1", "162.159.195.2", "162.159.195.3", "162.159.195.4",
            "188.114.96.1", "188.114.96.2", "188.114.96.3", "188.114.96.4",
            "188.114.97.1", "188.114.97.2", "188.114.97.3", "188.114.97.4",
            "188.114.98.1", "188.114.98.2", "188.114.98.3", "188.114.98.4",
            "188.114.99.1", "188.114.99.2", "188.114.99.3", "188.114.99.4",
    };
}
