package com.xehn.warp;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.graphics.Typeface;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.provider.Settings;
import android.os.Looper;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Switch;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

import com.wireguard.android.backend.Tunnel;

/**
 * One screen, one button: press connect and the app registers a WARP device,
 * picks the fastest edge, and brings up a WireGuard tunnel through the bundled
 * wireguard-go backend. No second app, no root.
 *
 * <p>After the tunnel is up it watches the WireGuard counters, because "UP" only
 * means the TUN exists: a handshake that never completes is a dead tunnel, and
 * the counters are what tell the two apart.
 */
public final class MainActivity extends Activity implements WarpTunnel.Listener {

    private static final int REQ_VPN = 1001;

    /** Launcher shortcut / quick-settings tile entry points. */
    public static final String ACTION_CONNECT = "com.xehn.warp.CONNECT";
    public static final String ACTION_DISCONNECT = "com.xehn.warp.DISCONNECT";
    static final String PREFS = "xehn";
    static final String KEY_ACCOUNT = "account";
    static final String KEY_ENDPOINT_CACHE = "endpoint_cache";
    static final String KEY_PORT = "port_index";
    private static final String KEY_MASQUE = "masque_account";
    private static final String KEY_MASQUE_ENDPOINT = "masque_endpoint";
    static final String KEY_ENGINE = "engine_index";
    static final String KEY_PROTO = "upstream_proto";
    static final String KEY_POLICY = "route_policy";
    static final String KEY_DNS = "dns_index";
    static final String KEY_IPV6 = "ipv6_enabled";
    static final String KEY_MTU = "mtu_index";
    static final String KEY_RULES = "custom_rules";
    static final String KEY_TIMEOUT = "handshake_timeout_sec";
    static final String KEY_EXIT_CANDIDATES = "exit_candidates";
    static final String KEY_EXIT_IDS = "exit_ids";
    static final String KEY_EXIT_LABEL = "exit_label";
    static final String KEY_EXIT_COUNTRY = "exit_country";

    /** Upstream engine protocols, mirrors the desktop flags. */
    private static final String[][] UPSTREAM_PROTOS = {
            {"wg", "WireGuard"},
            {"awg", "AmneziaWG"},
            {"masque", "MASQUE"},
            {"masque-h2", "MASQUE (HTTP/2)"},
            {"wwarp", "WARP-in-WARP"},
    };
    static final int[] PORTS = {2408, 500, 1701, 443};
    private static final int LOG_LINES = 12;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final StringBuilder logLines = new StringBuilder();

    private TextView statusView;
    private TextView statusDot;
    private TextView detailView;
    private TextView logView;
    private Button connectButton;
    private Spinner portSpinner;
    private Spinner protoSpinner;
    private Spinner policySpinner;
    private Spinner dnsSpinner;
    private Spinner mtuSpinner;
    private Switch ipv6Switch;
    private EditText rulesInput;
    private Spinner timeoutSpinner;
    private final java.util.Map<String, long[]> probeResults = new java.util.HashMap<String, long[]>();
    private TextView exitValue;
    private TextView chipLatency;
    private TextView chipExit;
    private TextView chipUptime;
    private long connectStartAt;
    private Spinner engineSpinner;
    private Warp.Result pendingResult;
    private int pendingEngine;

    private volatile boolean busy;
    private String pendingConfig;
    private String lastEndpoint = "";
    private long lastLatency = -1;
    private volatile String exitInfo = "";
    private Tunnel.State lastState = Tunnel.State.DOWN;
    private volatile boolean retriedFixed;
    /** Ports to try in order; the first entry is what the user picked. */
    private volatile int[] portPlan = {0};
    private volatile int portAttempt;
    private volatile String endpointHost = "";
    /** Bumped on every user disconnect so in-flight retries cannot resurrect the tunnel. */
    private volatile int stopToken;
    /** True between a user disconnect and the next explicit connect. */
    private volatile boolean userDown;
    /** True once the tunnel actually carries traffic (handshake or engine probe). */
    private volatile boolean connectionReady;
    /** The engine started but its probe never succeeded; the UI must say so. */
    private volatile boolean connectionFailed;

    // Watchdog: the tunnel can die silently (network change, engine exit), so a
    // cheap health check runs every few seconds and reconnects at most 3 times
    // in 5 minutes before giving up.
    private volatile boolean watchdogRunning;
    private Thread watchdogThread;
    private int reconnectCount;
    private long reconnectWindowStart;
    private long lastRxBytes;
    private int lastEngine;
    private String lastWgConfig = "";
    private Warp.Result lastWgResult;
    private volatile String[] lastUpstreamArgs;
    private volatile boolean engineRestartPending;
    private volatile long upstreamConnectStart;
    private volatile boolean upstreamFallbackTried;
    private ConnectivityManager.NetworkCallback networkCallback;
    private boolean networkCallbackWarm;
    private volatile long lastTransitionAt;
    private int recloseCount;

    private final Warp.Log logger = new Warp.Log() {
        public void log(String line) {
            appendLog(line);
        }
    };

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        applyPalette();
        LogStore.init(this);
        migratePrefs();
        registerNetworkCallback();
        try {
            getWindow().setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(C_BG));
        } catch (Exception ignored) {
        }
        setContentView(buildUi());
        engineSpinner.setSelection(prefs().getInt(KEY_ENGINE, 0));
        // The backend is constructed on the connect worker: loading libwg-go.so
        // on the UI thread would make the first frame stutter.
        render();
        autoCheckUpdate();
        handleLaunchIntent(getIntent());
        prewarmEndpoint();
    }

    /** Silent launch-time check; only logs when there is something newer. */
    private void autoCheckUpdate() {
        if (Updater.MANIFEST_URL.isEmpty()) {
            return;
        }
        new Thread(new Runnable() {
            public void run() {
                final Updater.Info info = Updater.check();
                if (info.isNewerThan(Updater.currentVersionCode(MainActivity.this))) {
                    ui.post(new Runnable() {
                        public void run() {
                            log("发现新版本 " + info.versionName + "，点「检查更新」升级");
                        }
                    });
                }
            }
        }, "xehn-update-auto").start();
    }

    @Override
    public void onConfigurationChanged(android.content.res.Configuration config) {
        super.onConfigurationChanged(config);
        // Rebuild with the other palette instead of mutating every view.
        recreate();
    }

    @Override
    protected void onDestroy() {
        try {
            ConnectivityManager manager =
                    (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (manager != null && networkCallback != null) {
                manager.unregisterNetworkCallback(networkCallback);
            }
        } catch (Throwable ignored) {
        }
        if (ui != null) {
            ui.removeCallbacksAndMessages(null);
        }
        super.onDestroy();
    }

    @Override
    protected void onNewIntent(android.content.Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleLaunchIntent(intent);
    }

    /** Runs 连接 / 断开 when the app was opened from a shortcut or the tile. */
    private void handleLaunchIntent(android.content.Intent intent) {
        if (intent == null) {
            return;
        }
        String action = intent.getAction();
        if (!ACTION_CONNECT.equals(action) && !ACTION_DISCONNECT.equals(action)) {
            return;
        }
        intent.setAction(null);
        final boolean wantConnect = ACTION_CONNECT.equals(action);
        ui.postDelayed(new Runnable() {
            public void run() {
                if (wantConnect) {
                    if (isTunnelUp()) {
                        toast("已经连接");
                    } else {
                        onConnectClicked();
                    }
                } else {
                    if (isTunnelUp()) {
                        onConnectClicked();
                    } else {
                        toast("当前未连接");
                    }
                }
            }
        }, 450);
    }

    private boolean isTunnelUp() {
        return EngineService.running || TunnelManager.state() == Tunnel.State.UP;
    }

    @Override
    protected void onResume() {
        super.onResume();
        render();
    }

    // ------------------------------------------------------------------ ui

    // ------------------------------------------------------------- design

    // Palette is per-instance so the screen can follow the system light/dark
    // setting without pulling in AppCompat.
    private int C_BG;
    private int C_CARD;
    private int C_BORDER;
    private int C_TEXT;
    private int C_MUTED;
    private int C_ACCENT;
    private int C_OK;
    private int C_WARN;
    private int C_DANGER;
    private int C_LOG;

    private static final int PREFS_SCHEMA = 2;

    /** One-time defaults for keys added after the first release. */
    private void migratePrefs() {
        int schema = prefs().getInt("prefs_schema", 1);
        if (schema >= PREFS_SCHEMA) {
            return;
        }
        if (!prefs().contains(KEY_TIMEOUT)) {
            prefs().edit().putInt(KEY_TIMEOUT, 1).apply();
        }
        if (!prefs().contains(KEY_ENGINE)) {
            prefs().edit().putInt(KEY_ENGINE, 0).apply();
        }
        prefs().edit().putInt("prefs_schema", PREFS_SCHEMA).apply();
        LogStore.append("设置已迁移到 schema " + PREFS_SCHEMA);
    }

    private void applyPalette() {
        boolean dark = (getResources().getConfiguration().uiMode
                & android.content.res.Configuration.UI_MODE_NIGHT_MASK)
                == android.content.res.Configuration.UI_MODE_NIGHT_YES;
        if (dark) {
            C_BG = 0xFF0B1120;
            C_CARD = 0xFF111827;
            C_BORDER = 0xFF1F2937;
            C_TEXT = 0xFFE5E7EB;
            C_MUTED = 0xFF94A3B8;
            C_ACCENT = 0xFF60A5FA;
            C_OK = 0xFF4ADE80;
            C_WARN = 0xFFFBBF24;
            C_DANGER = 0xFFF87171;
            C_LOG = 0xFFCBD5E1;
        } else {
            C_BG = 0xFFF1F5F9;
            C_CARD = 0xFFFFFFFF;
            C_BORDER = 0xFFE2E8F0;
            C_TEXT = 0xFF0F172A;
            C_MUTED = 0xFF64748B;
            C_ACCENT = 0xFF2563EB;
            C_OK = 0xFF15803D;
            C_WARN = 0xFFB45309;
            C_DANGER = 0xFFB91C1C;
            C_LOG = 0xFF334155;
        }
    }

    private View buildUi() {
        ScrollView root = new ScrollView(this);
        root.setBackgroundColor(C_BG);
        root.setFillViewport(true);

        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        column.setPadding(dp(16), dp(20), dp(16), dp(24));
        root.addView(column, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        column.addView(buildHeader());
        column.addView(buildConnectCard());
        column.addView(buildSettingsCard());
        column.addView(buildLogCard());
        column.addView(buildActionGrid());

        return root;
    }

    private View buildHeader() {
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(android.view.Gravity.CENTER_VERTICAL);
        header.setPadding(dp(4), 0, dp(4), dp(16));

        TextView title = new TextView(this);
        title.setText("MccX");
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 24);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextColor(C_TEXT);
        header.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView version = new TextView(this);
        version.setText("v" + appVersionName());
        version.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        version.setTextColor(C_MUTED);
        header.addView(version);
        return header;
    }

    private View buildConnectCard() {
        LinearLayout card = card();

        LinearLayout stateRow = new LinearLayout(this);
        stateRow.setOrientation(LinearLayout.HORIZONTAL);
        stateRow.setGravity(android.view.Gravity.CENTER_VERTICAL);

        statusDot = new TextView(this);
        statusDot.setText("●");
        statusDot.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        stateRow.addView(statusDot);

        statusView = new TextView(this);
        statusView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 24);
        statusView.setTypeface(Typeface.DEFAULT_BOLD);
        statusView.setPadding(dp(8), 0, 0, 0);
        stateRow.addView(statusView, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        card.addView(stateRow);

        detailView = new TextView(this);
        detailView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        detailView.setTextColor(C_MUTED);
        detailView.setLineSpacing(dp(2), 1f);
        LinearLayout.LayoutParams detailLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        detailLp.topMargin = dp(6);
        card.addView(detailView, detailLp);

        LinearLayout chips = new LinearLayout(this);
        chips.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams chipsLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        chipsLp.topMargin = dp(14);
        chipLatency = statChip("延迟 —");
        chipExit = statChip("出口 —");
        chipUptime = statChip("时长 00:00:00");
        chips.addView(chipLatency, chipParams());
        chips.addView(chipExit, chipParams());
        chips.addView(chipUptime, chipParams());
        card.addView(chips, chipsLp);

        connectButton = new Button(this);
        connectButton.setAllCaps(false);
        connectButton.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        connectButton.setTypeface(Typeface.DEFAULT_BOLD);
        connectButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                onConnectClicked();
            }
        });
        LinearLayout.LayoutParams buttonLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(52));
        buttonLp.topMargin = dp(16);
        card.addView(connectButton, buttonLp);
        return card;
    }

    private TextView statChip(String text) {
        TextView chip = new TextView(this);
        chip.setText(text);
        chip.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        chip.setTextColor(C_MUTED);
        chip.setGravity(android.view.Gravity.CENTER);
        chip.setPadding(dp(8), dp(8), dp(8), dp(8));
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(C_BG);
        bg.setCornerRadius(dp(10));
        bg.setStroke(dp(1), C_BORDER);
        chip.setBackground(bg);
        return chip;
    }

    private LinearLayout.LayoutParams chipParams() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMargins(dp(3), 0, dp(3), 0);
        return lp;
    }

    private View buildSettingsCard() {
        LinearLayout card = card();
        card.addView(cardTitle("设置"));

        card.addView(sectionLabel("连接"));
        engineSpinner = new Spinner(this);
        engineSpinner.setAdapter(spinnerAdapter(new String[]{
                "内置 WireGuard", "上游引擎（实验）"
        }));
        engineSpinner.setSelection(prefs().getInt(KEY_ENGINE, 0));
        card.addView(settingsRow("隧道引擎", engineSpinner));
        card.addView(divider());

        protoSpinner = new Spinner(this);
        String[] protoLabels = new String[UPSTREAM_PROTOS.length];
        for (int i = 0; i < UPSTREAM_PROTOS.length; i++) {
            protoLabels[i] = UPSTREAM_PROTOS[i][1];
        }
        protoSpinner.setAdapter(spinnerAdapter(protoLabels));
        protoSpinner.setSelection(prefs().getInt(KEY_PROTO, 0));
        card.addView(settingsRow("上游协议", protoSpinner));
        card.addView(divider());

        mtuSpinner = new Spinner(this);
        mtuSpinner.setAdapter(spinnerAdapter(new String[]{"1280", "1400", "1420", "1500"}));
        mtuSpinner.setSelection(prefs().getInt(KEY_MTU, 0));
        card.addView(settingsRow("MTU", mtuSpinner));
        card.addView(divider());

        timeoutSpinner = new Spinner(this);
        timeoutSpinner.setAdapter(spinnerAdapter(new String[]{"3 秒", "5 秒", "8 秒"}));
        timeoutSpinner.setSelection(prefs().getInt(KEY_TIMEOUT, 1));
        card.addView(settingsRow("握手超时", timeoutSpinner));
        card.addView(divider());

        portSpinner = new Spinner(this);
        String[] portLabels = new String[PORTS.length];
        for (int i = 0; i < PORTS.length; i++) {
            portLabels[i] = String.valueOf(PORTS[i]);
        }
        portSpinner.setAdapter(spinnerAdapter(portLabels));
        portSpinner.setSelection(prefs().getInt(KEY_PORT, 2));
        card.addView(settingsRow("端点端口", portSpinner));

        card.addView(sectionLabel("网络"));
        dnsSpinner = new Spinner(this);
        dnsSpinner.setAdapter(spinnerAdapter(new String[]{
                "自动", "1.1.1.1", "8.8.8.8", "223.5.5.5", "119.29.29.29"
        }));
        dnsSpinner.setSelection(prefs().getInt(KEY_DNS, 0));
        card.addView(settingsRow("DNS", dnsSpinner));
        card.addView(divider());

        ipv6Switch = new Switch(this);
        ipv6Switch.setChecked(prefs().getBoolean(KEY_IPV6, false));
        card.addView(settingsRow("IPv6", ipv6Switch));

        card.addView(sectionLabel("路由"));
        policySpinner = new Spinner(this);
        policySpinner.setAdapter(spinnerAdapter(new String[]{"全局", "绕过大陆", "黑名单"}));
        policySpinner.setSelection(prefs().getInt(KEY_POLICY, 0));
        card.addView(settingsRow("分流", policySpinner));
        card.addView(divider());

        exitValue = new TextView(this);
        exitValue.setText(exitLabelText());
        exitValue.setTextColor(C_ACCENT);
        exitValue.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        exitValue.setPadding(0, dp(4), 0, dp(4));
        exitValue.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showExitDialog();
            }
        });
        card.addView(settingsRow("第二跳出口", exitValue));
        card.addView(divider());

        rulesInput = new EditText(this);
        rulesInput.setText(prefs().getString(KEY_RULES, ""));
        rulesInput.setHint("proxy,1.2.3.0/24（每行一条）");
        rulesInput.setHintTextColor(C_MUTED);
        rulesInput.setTextColor(C_TEXT);
        rulesInput.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        rulesInput.setBackgroundColor(0x00000000);
        rulesInput.setMinLines(2);
        rulesInput.setMaxLines(4);
        rulesInput.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        card.addView(rulesInput);
        return card;
    }

    /** Everything the upstream engine needs, snapshotted from the settings UI. */
    private void connectUpstream() {
        int engineIndex = engineSpinner == null ? 0 : engineSpinner.getSelectedItemPosition();
        prefs().edit().putInt(KEY_ENGINE, engineIndex).apply();
        lastEngine = 3;
        upstreamConnectStart = System.currentTimeMillis();
        upstreamFallbackTried = false;
        log("上游引擎启动中…");
        lastUpstreamArgs = new String[]{
                upstreamProto(), upstreamPolicy(), upstreamDns(),
                upstreamIpv6() ? "1" : "0", String.valueOf(upstreamMtu()), upstreamRules(),
                prefs().getString(KEY_EXIT_IDS, ""),
                prefs().getString(KEY_EXIT_LABEL, ""),
                prefs().getString(KEY_EXIT_COUNTRY, ""),
                String.valueOf(handshakeTimeout())
        };
        EngineService.start(this, lastUpstreamArgs[0], lastUpstreamArgs[1], lastUpstreamArgs[2],
                "1".equals(lastUpstreamArgs[3]), Integer.parseInt(lastUpstreamArgs[4]), lastUpstreamArgs[5],
                exitIdsForConnect(), lastUpstreamArgs[7], lastUpstreamArgs[8],
                Integer.parseInt(lastUpstreamArgs[9]));
        scheduleEngineCheck();
    }

    /**
     * DNS picker. "自动" follows the split policy: bypass-CN wants a domestic
     * resolver so mainland domains do not pay a round trip through the tunnel,
     * while global mode uses Cloudflare so nothing gets poisoned locally.
     */
    private String upstreamDns() {
        String[] servers = {null, "1.1.1.1", "8.8.8.8", "223.5.5.5", "119.29.29.29"};
        int index = dnsSpinner == null ? prefs().getInt(KEY_DNS, 0) : dnsSpinner.getSelectedItemPosition();
        if (index < 0 || index >= servers.length) {
            index = 0;
        }
        prefs().edit().putInt(KEY_DNS, index).apply();
        if (servers[index] != null) {
            return servers[index];
        }
        boolean domestic = "bypass-cn".equals(upstreamPolicy()) || "blacklist".equals(upstreamPolicy());
        return domestic ? "223.5.5.5" : "1.1.1.1";
    }

    private boolean upstreamIpv6() {
        boolean value = ipv6Switch == null ? prefs().getBoolean(KEY_IPV6, false) : ipv6Switch.isChecked();
        prefs().edit().putBoolean(KEY_IPV6, value).apply();
        return value;
    }

    private int upstreamMtu() {
        int[] values = {1280, 1400, 1420, 1500};
        int index = mtuSpinner == null ? prefs().getInt(KEY_MTU, 0) : mtuSpinner.getSelectedItemPosition();
        if (index < 0 || index >= values.length) {
            index = 0;
        }
        prefs().edit().putInt(KEY_MTU, index).apply();
        return values[index];
    }

    private String upstreamRules() {
        String text = rulesInput == null ? prefs().getString(KEY_RULES, "") : rulesInput.getText().toString();
        prefs().edit().putString(KEY_RULES, text).apply();
        return text;
    }
    /** Spinners live outside our palette, so their text has to be painted. */
    private ArrayAdapter<String> spinnerAdapter(final String[] items) {
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, items) {
            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                TextView view = (TextView) super.getView(position, convertView, parent);
                view.setTextColor(C_TEXT);
                view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
                return view;
            }

            @Override
            public View getDropDownView(int position, View convertView, ViewGroup parent) {
                TextView view = (TextView) super.getDropDownView(position, convertView, parent);
                view.setTextColor(C_TEXT);
                view.setBackgroundColor(C_CARD);
                view.setPadding(dp(14), dp(10), dp(14), dp(10));
                return view;
            }
        };
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        return adapter;
    }

    private TextView sectionLabel(String text) {
        TextView label = new TextView(this);
        label.setText(text);
        label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        label.setTextColor(C_MUTED);
        label.setPadding(0, dp(10), 0, dp(2));
        return label;
    }
    private View buildLogCard() {
        LinearLayout card = card();

        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(android.view.Gravity.CENTER_VERTICAL);
        TextView title = cardTitle("运行日志");
        title.setPadding(0, 0, 0, 0);
        head.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView share = new TextView(this);
        share.setText("分享");
        share.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        share.setTextColor(C_ACCENT);
        share.setPadding(dp(12), dp(4), dp(4), dp(4));
        share.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                shareLog();
            }
        });
        head.addView(share);

        TextView clear = new TextView(this);
        clear.setText("清空");
        clear.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        clear.setTextColor(C_MUTED);
        clear.setPadding(dp(12), dp(4), dp(4), dp(4));
        clear.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                logLines.setLength(0);
                LogStore.clear();
                if (logView != null) {
                    logView.setText("");
                }
            }
        });
        head.addView(clear);

        TextView copy = new TextView(this);
        copy.setText("复制");
        copy.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        copy.setTextColor(C_ACCENT);
        copy.setPadding(dp(12), dp(4), dp(4), dp(4));
        copy.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                copyLog();
            }
        });
        head.addView(copy);
        card.addView(head);

        logView = new TextView(this);
        logView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextColor(C_LOG);
        logView.setLineSpacing(dp(2), 1f);
        logView.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(logView, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        LinearLayout.LayoutParams logLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(168));
        logLp.topMargin = dp(10);
        card.addView(scroll, logLp);
        return card;
    }

    private View buildActionGrid() {
        LinearLayout grid = new LinearLayout(this);
        grid.setOrientation(LinearLayout.VERTICAL);

        grid.addView(actionRow(
                actionButton("重新自检", new View.OnClickListener() {
                    public void onClick(View v) {
                        if (isTunnelUp()) {
                            startSelfCheck();
                        } else {
                            toast("请先连接");
                        }
                    }
                }),
                actionButton("出口体检", new View.OnClickListener() {
                    public void onClick(View v) {
                        runExitCheck();
                    }
                })));

        LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rowLp.topMargin = dp(8);

        LinearLayout second = actionRow(
                actionButton("测试内核", new View.OnClickListener() {
                    public void onClick(View v) {
                        probeDiagnostics();
                    }
                }),
                actionButton("检查更新", new View.OnClickListener() {
                    public void onClick(View v) {
                        checkUpdate();
                    }
                }));
        grid.addView(second, rowLp);

        LinearLayout third = actionRow(
                actionButton("重置设备", new View.OnClickListener() {
                    public void onClick(View v) {
                        resetDevice();
                    }
                }),
                actionButton("导出配置", new View.OnClickListener() {
                    public void onClick(View v) {
                        exportConfig();
                    }
                }));
        LinearLayout.LayoutParams thirdLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        thirdLp.topMargin = dp(8);
        grid.addView(third, thirdLp);
        return grid;
    }

    private LinearLayout actionRow(Button left, Button right) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(44), 1f);
        lp.setMargins(0, 0, dp(6), 0);
        row.addView(left, lp);
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(0, dp(44), 1f);
        rp.setMargins(dp(6), 0, 0, 0);
        row.addView(right, rp);
        return row;
    }

    private LinearLayout card() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(16), dp(16), dp(16));
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(C_CARD);
        bg.setCornerRadius(dp(18));
        bg.setStroke(dp(1), C_BORDER);
        card.setBackground(bg);
        card.setElevation(dp(1));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(14);
        card.setLayoutParams(lp);
        return card;
    }

    private TextView cardTitle(String text) {
        TextView title = new TextView(this);
        title.setText(text);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        title.setTextColor(C_MUTED);
        title.setLetterSpacing(0.12f);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setPadding(0, 0, 0, dp(8));
        return title;
    }

    private View settingsRow(String label, View control) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(android.view.Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(6), 0, dp(6));
        row.setMinimumHeight(dp(46));

        TextView name = new TextView(this);
        name.setText(label);
        name.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        name.setTextColor(C_TEXT);
        row.addView(name, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(control, new LinearLayout.LayoutParams(dp(156), dp(40)));
        return row;
    }

    private View divider() {
        View line = new View(this);
        line.setBackgroundColor(C_BORDER);
        line.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(1)));
        return line;
    }

    private Button actionButton(String text, View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(text);
        button.setAllCaps(false);
        button.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        button.setTextColor(C_TEXT);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(C_CARD);
        bg.setCornerRadius(dp(12));
        bg.setStroke(dp(1), C_BORDER);
        button.setBackground(bg);
        button.setOnClickListener(listener);
        return button;
    }

    private void styleConnectButton(boolean up, boolean connecting) {
        int color;
        if (connecting) {
            color = C_WARN;
        } else if (up) {
            color = C_DANGER;
        } else {
            color = C_ACCENT;
        }
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(color);
        bg.setCornerRadius(dp(26));
        connectButton.setBackground(bg);
        connectButton.setTextColor(0xFFFFFFFF);
    }

    private String appVersionName() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception e) {
            return "?";
        }
    }
    private void render() {
        boolean up = EngineService.running || TunnelManager.state() == Tunnel.State.UP;
        boolean upstream = lastEngine == 3 && EngineService.running;
        if (!busy && upstream && EngineService.connected()) {
            statusView.setText("已连接");
            statusView.setTextColor(C_OK);
            statusDot.setTextColor(C_OK);
            connectButton.setText("断开");
            connectButton.setEnabled(true);
            styleConnectButton(true, false);
        } else if (!busy && upstream && "error".equals(EngineService.state)) {
            statusView.setText("连接异常");
            statusView.setTextColor(C_DANGER);
            statusDot.setTextColor(C_DANGER);
            connectButton.setText("断开");
            connectButton.setEnabled(true);
            styleConnectButton(true, false);
        } else if (!busy && upstream) {
            statusView.setText("连接中…");
            statusView.setTextColor(C_WARN);
            statusDot.setTextColor(C_WARN);
            connectButton.setText("断开");
            connectButton.setEnabled(true);
            styleConnectButton(true, true);
        } else if (busy) {
            statusView.setText("连接中…");
            statusView.setTextColor(C_WARN);
            statusDot.setTextColor(C_WARN);
            connectButton.setText("请稍候");
            connectButton.setEnabled(false);
            styleConnectButton(false, true);
        } else if (up && connectionFailed) {
            statusView.setText("连接异常");
            statusView.setTextColor(C_DANGER);
            statusDot.setTextColor(C_DANGER);
            connectButton.setText("断开");
            connectButton.setEnabled(true);
            styleConnectButton(true, false);
        } else if (up && !connectionReady) {
            // The TUN exists but no handshake yet: saying "connected" here is
            // what made the app look connected while nothing loaded.
            statusView.setText("等待握手…");
            statusView.setTextColor(C_WARN);
            statusDot.setTextColor(C_WARN);
            connectButton.setText("断开");
            connectButton.setEnabled(true);
            styleConnectButton(true, true);
        } else if (up) {
            statusView.setText("已连接");
            statusView.setTextColor(C_OK);
            statusDot.setTextColor(C_OK);
            connectButton.setText("断开");
            connectButton.setEnabled(true);
            styleConnectButton(true, false);
        } else {
            statusView.setText("未连接");
            statusView.setTextColor(C_MUTED);
            statusDot.setTextColor(C_MUTED);
            connectButton.setText("连接");
            connectButton.setEnabled(true);
            styleConnectButton(false, false);
        }

        StringBuilder detail = new StringBuilder();
        if (upstream) {
            detail.append(upstreamDetail());
        } else if (up || (!lastEndpoint.isEmpty() && !busy)) {
            if (!lastEndpoint.isEmpty()) {
                detail.append(lastEndpoint);
            }
            if (lastLatency >= 0) {
                detail.append("  ·  ").append(lastLatency).append(" ms");
            }
            if (up && !exitInfo.isEmpty()) {
                detail.append('\n').append(exitInfo);
            }
        } else {
            detail.append("点击连接：自动注册 WARP、优选节点、建立隧道");
        }
        detailView.setText(detail.toString());
        updateStatChips(upstream);
        scheduleUiTick(upstream);

        logView.setText(logLines.toString());
    }

    // ------------------------------------------------------------- actions

    private void onConnectClicked() {
        if (busy) {
            return;
        }
        // Must use the same definition of "up" the status line uses: in the
        // engine modes the tunnel is not registered in the WireGuard backend,
        // so checking TunnelManager alone made "断开" start a new connection.
        boolean up = EngineService.running || TunnelManager.state() == Tunnel.State.UP;
        if (up) {
            startDisconnect();
        } else {
            startConnect();
        }
    }

    /** Selected port first, then 1701/2408/443/500 — the order this device found usable. */
    private static int[] orderPorts(int selected) {
        int[] order = new int[PORTS.length];
        int n = 0;
        order[n++] = selected;
        int[] preferred = {2, 0, 3, 1};
        for (int idx : preferred) {
            boolean seen = false;
            for (int i = 0; i < n; i++) {
                if (order[i] == idx) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                order[n++] = idx;
            }
        }
        return order;
    }

    /** Shares the working profile so other devices/clients can import it. */
    private void exportConfig() {
        if (lastWgResult == null || lastWgConfig.isEmpty()) {
            toast("先用内置 WireGuard 连接一次，成功后才能导出");
            return;
        }
        final String endpoint = lastWgResult.endpoint;
        new AlertDialog.Builder(this)
                .setTitle("导出配置")
                .setMessage("当前优选端点：" + endpoint
                        + "\n\n可以导出为 WireGuard 配置（任何 WG 客户端都能导入），"
                        + "或 mihomo / Clash 配置。")
                .setPositiveButton("WireGuard", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        shareConfig(false);
                    }
                })
                .setNeutralButton("Clash", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        shareConfig(true);
                    }
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void shareConfig(boolean clash) {
        String body = clash
                ? ConfigExport.clash(lastWgResult)
                : ConfigExport.wireGuard(lastWgResult);
        if (body.isEmpty()) {
            toast("配置为空，请重新连接后导出");
            return;
        }
        String name = ConfigExport.fileName(clash);
        String path = "";
        try {
            java.io.File dir = getExternalFilesDir("export");
            if (dir != null) {
                if (!dir.exists() && !dir.mkdirs()) {
                    dir = null;
                }
            }
            if (dir != null) {
                java.io.File file = new java.io.File(dir, name);
                java.io.FileWriter writer = new java.io.FileWriter(file);
                try {
                    writer.write(body);
                } finally {
                    writer.close();
                }
                path = file.getAbsolutePath();
            }
        } catch (Exception ignored) {
        }
        log("已导出 " + name + (path.isEmpty() ? "" : " → " + path));
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_SUBJECT, name);
        intent.putExtra(Intent.EXTRA_TEXT, body);
        startActivity(Intent.createChooser(intent, "分享 " + name));
    }

    /** Real requests through the tunnel: exit IP, reachability and round trips. */
    private static final String MASQUE_SNI = "consumer-masque.cloudflareclient.com";
    private static final String MASQUE_HOST = "162.159.198.2";
    private static final int MASQUE_PORT = 443;

    /** Everything needed to explain a failure: versions, state, TLS reachability. */
    private void probeDiagnostics() {
        log("诊断信息…");
        new Thread(new Runnable() {
            public void run() {
                StringBuilder report = new StringBuilder();
                report.append("App ").append(versionName()).append("（").append(Updater.currentVersionCode(MainActivity.this)).append("）\n");
                report.append("引擎：").append(lastEngine == 3 ? "上游引擎" : "内置 WireGuard").append('\n');
                report.append("状态：").append(lastEngine == 3 ? EngineService.state : String.valueOf(TunnelManager.state())).append('\n');
                report.append("端点：").append(lastEndpoint.isEmpty() ? "未连接" : lastEndpoint).append('\n');
                report.append("\n—— MASQUE 端点 TLS 探测（对照）——\n");
                report.append(TlsProbe.run(MASQUE_HOST, MASQUE_PORT, MASQUE_SNI));
                report.append('\n');
                report.append(TlsProbe.run(MASQUE_HOST, MASQUE_PORT, "cloudflare.com"));
                postDiagnostics(report.toString());
            }
        }, "probe-diagnostics").start();
    }

    private String versionName() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception e) {
            return "?";
        }
    }

    private void postDiagnostics(final String report) {
        ui.post(new Runnable() {
            public void run() {
                log(report.trim());
                new AlertDialog.Builder(MainActivity.this)
                        .setTitle("诊断信息")
                        .setMessage(report)
                        .setPositiveButton("好", null)
                        .show();
            }
        });
    }

    private void runExitCheck() {
        if (!isTunnelUp()) {
            toast("请先连接");
            return;
        }
        log("出口体检…");
        new Thread(new Runnable() {
            public void run() {
                final String report = ExitCheck.run();
                ui.post(new Runnable() {
                    public void run() {
                        log(report.trim());
                        new AlertDialog.Builder(MainActivity.this)
                                .setTitle("出口体检")
                                .setMessage(report)
                                .setPositiveButton("好", null)
                                .show();
                    }
                });
            }
        }, "exit-check").start();
    }

    private static final long ENDPOINT_CACHE_MS = 10 * 60 * 1000L;

    /** Background endpoint scan, cached so "连接" can skip the scan entirely. */
    private static String endpointHostOf(Warp.Result result) {
        if (result == null || result.endpoint == null) {
            return "";
        }
        int split = result.endpoint.lastIndexOf(':');
        return split > 0 ? result.endpoint.substring(0, split) : result.endpoint;
    }

    private void prewarmEndpoint() {
        new Thread(new Runnable() {
            public void run() {
                try {
                    if (cachedEndpointFresh()) {
                        return;
                    }
                    Warp.Probe best = Warp.rankEndpoints(new Warp.Log() {
                        public void log(String line) {
                            LogStore.append(line);
                        }
                    });
                    if (best != null && best.bytesPerSecond > 0) {
                        cacheEndpoint(best.ip, best.millis, best.bytesPerSecond);
                        ui.post(new Runnable() {
                            public void run() {
                                log("已预热端点（下次连接直接使用）");
                            }
                        });
                    }
                } catch (Throwable ignored) {
                }
            }
        }, "prewarm-endpoint").start();
    }

    private boolean cachedEndpointFresh() {
        String raw = prefs().getString(KEY_ENDPOINT_CACHE, "");
        if (raw.isEmpty()) {
            return false;
        }
        try {
            org.json.JSONObject o = new org.json.JSONObject(raw);
            return System.currentTimeMillis() - o.optLong("ts", 0) < ENDPOINT_CACHE_MS
                    && !o.optString("ip", "").isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    private String cachedEndpoint() {
        try {
            org.json.JSONObject o = new org.json.JSONObject(prefs().getString(KEY_ENDPOINT_CACHE, ""));
            String ip = o.optString("ip", "");
            return ip.isEmpty() ? "" : ip;
        } catch (Exception e) {
            return "";
        }
    }

    private void cacheEndpoint(String ip, long latencyMs, long bytesPerSecond) {
        try {
            org.json.JSONObject o = new org.json.JSONObject();
            o.put("ip", ip);
            o.put("latency", latencyMs);
            o.put("bps", bytesPerSecond);
            o.put("ts", System.currentTimeMillis());
            prefs().edit().putString(KEY_ENDPOINT_CACHE, o.toString()).apply();
        } catch (Exception ignored) {
        }
    }

    private void startConnect() {
        userDown = false;
        connectionFailed = false;
        recloseCount = 0;
        busy = true;
        exitInfo = "";
        retriedFixed = false;
        lastState = Tunnel.State.DOWN;
        logLines.setLength(0);
        render();
        log("开始连接");

        final int portIndex = Math.max(0, portSpinner.getSelectedItemPosition());
        final int port = PORTS[portIndex];
        final int engine = engineSpinner.getSelectedItemPosition() == 0 ? 0 : 3;
        prefs().edit().putInt(KEY_ENGINE, engineSpinner.getSelectedItemPosition()).apply();
        portPlan = orderPorts(portIndex);
        portAttempt = 0;

        new Thread(new Runnable() {
            public void run() {
                try {
                    Warp.Account existing = Warp.Account.fromJson(prefs().getString(KEY_ACCOUNT, ""));
                    Warp.Result result = null;
                    String cached = cachedEndpointFresh() ? cachedEndpoint() : "";
                    if (!cached.isEmpty()) {
                        log("使用预热端点 " + cached);
                        try {
                            result = Warp.generateFixed("wg", cached + ":" + port, existing, logger);
                        } catch (Exception e) {
                            log("预热端点失败，改为全量扫描");
                            result = null;
                        }
                    }
                    if (result == null) {
                        result = Warp.generate("wg", port, true, existing, logger);
                        cacheEndpoint(endpointHostOf(result), result.latencyMs, 0);
                    }
                    prefs().edit()
                            .putString(KEY_ACCOUNT, result.account.toJson())
                            .putInt(KEY_PORT, portIndex)
                            .apply();
                    lastEndpoint = result.endpoint;
                    lastLatency = result.latencyMs;
                    lastWgResult = result;
                    int split = result.endpoint.lastIndexOf(':');
                    endpointHost = split > 0 ? result.endpoint.substring(0, split) : result.endpoint;

                    final String configText = result.config;
                    final Warp.Result finalResult = result;
                    ui.post(new Runnable() {
                        public void run() {
                            Intent consent = VpnService.prepare(MainActivity.this);
                            if (consent != null) {
                                pendingConfig = configText;
                                pendingEngine = engine;
                                pendingResult = finalResult;
                                startActivityForResult(consent, REQ_VPN);
                            } else {
                                launch(engine, configText, finalResult);
                            }
                        }
                    });
                } catch (final Exception e) {
                    fail(e);
                }
            }
        }, "xehn-connect").start();
    }

    /** Starts the selected engine; mihomo runs in its own VpnService process. */
    /**
     * Starts the engine the user picked: 0 = built-in WireGuard, 1 = mihomo with
     * a wireguard outbound, 2 = mihomo with a MASQUE outbound (EC keys, port 443).
     */
    /**
     * Candidate ids in try order. VPN Gate nodes mostly fail the handshake, so
     * several are offered and the engine walks the list.
     */
    private String exitIdsForConnect() {
        String candidates = prefs().getString(KEY_EXIT_CANDIDATES, "");
        if (!candidates.isEmpty()) {
            return candidates;
        }
        return prefs().getString(KEY_EXIT_IDS, "");
    }

    private String exitLabelText() {
        String label = prefs().getString(KEY_EXIT_LABEL, "");
        return label.isEmpty() ? "未启用（点此选择）" : label;
    }

    private java.util.List<VpnGate.Node> lastExitNodes = new java.util.ArrayList<VpnGate.Node>();

    /** Node picker for the VPN Gate second hop. */
    private void showExitDialog() {
        if (EngineService.running) {
            toast("请先断开连接，再切换第二跳出口");
            return;
        }
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(16), dp(8), dp(16), dp(8));

        final LinearLayout list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        final TextView status = new TextView(this);
        status.setText("加载节点列表…");
        status.setTextColor(C_MUTED);
        status.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);

        TextView probe = new TextView(this);
        probe.setText("测延迟（真做一次 OpenVPN 握手）");
        probe.setTextColor(C_ACCENT);
        probe.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        probe.setPadding(0, dp(8), 0, dp(4));

        content.addView(status);
        content.addView(probe);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(list);
        content.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(340)));

        final android.app.AlertDialog dialog = new android.app.AlertDialog.Builder(this)
                .setTitle("第二跳出口（VPN Gate）")
                .setView(content)
                .setNegativeButton("关闭", null)
                .setNeutralButton("清除", null)
                .create();
        dialog.setOnShowListener(new android.content.DialogInterface.OnShowListener() {
            public void onShow(android.content.DialogInterface d) {
                if (dialog.getButton(android.app.AlertDialog.BUTTON_NEUTRAL) != null) {
                    dialog.getButton(android.app.AlertDialog.BUTTON_NEUTRAL)
                            .setOnClickListener(new View.OnClickListener() {
                                public void onClick(View v) {
                                    prefs().edit()
                                            .remove(KEY_EXIT_IDS)
                                            .remove(KEY_EXIT_LABEL)
                                            .remove(KEY_EXIT_COUNTRY)
                                            .remove(KEY_EXIT_CANDIDATES).apply();
                                    exitValue.setText(exitLabelText());
                                    dialog.dismiss();
                                }
                            });
                }
            }
        });
        probe.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                probeNodes(list, status);
            }
        });
        dialog.show();
        loadExitNodes(list, status);
    }

    private void loadExitNodes(final LinearLayout list, final TextView status) {
        new Thread(new Runnable() {
            public void run() {
                final java.util.List<VpnGate.Node> nodes = EngineService.loadVpnGateNodes(MainActivity.this, true);
                ui.post(new Runnable() {
                    public void run() {
                        lastExitNodes = nodes;
                        renderExitList(list, status);
                    }
                });
            }
        }, "vpn-gate-nodes").start();
    }

    private void renderExitList(final LinearLayout list, final TextView status) {
        list.removeAllViews();
        if (lastExitNodes.isEmpty()) {
            status.setText("没有拿到节点：检查网络后重开此窗口");
            return;
        }
        int ok = 0;
        for (long[] result : probeResults.values()) {
            if (result[0] == 1) {
                ok++;
            }
        }
        status.setText("共 " + lastExitNodes.size() + " 个节点"
                + (probeResults.isEmpty() ? "（家宽优先，点一个即选定）"
                : "，实测可握手 " + ok + " 个"));
        int shown = Math.min(lastExitNodes.size(), 40);
        for (int i = 0; i < shown; i++) {
            final VpnGate.Node node = lastExitNodes.get(i);
            StringBuilder text = new StringBuilder(node.label());
            text.append('\n').append(node.host).append(':').append(node.port);
            long[] probe = probeResults.get(node.id);
            if (probe != null) {
                text.append(probe[0] == 1 ? "   ✓ 握手 " + probe[1] + " ms" : "   ✗ 握手失败");
            } else if (node.latencyMs > 0) {
                text.append("   ·  ").append(node.latencyMs).append(" ms");
            }
            TextView row = new TextView(MainActivity.this);
            row.setText(text.toString());
            row.setTextColor(probe != null && probe[0] != 1 ? C_DANGER : C_TEXT);
            row.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
            row.setPadding(dp(4), dp(10), dp(4), dp(10));
            row.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    selectExit(node);
                }
            });
            list.addView(row);
        }
    }

    private void selectExit(VpnGate.Node node) {
        StringBuilder candidates = new StringBuilder(node.id);
        int extra = 0;
        for (VpnGate.Node other : lastExitNodes) {
            if (extra >= 2) {
                break;
            }
            if (other.id.equals(node.id)) {
                continue;
            }
            long[] probe = probeResults.get(other.id);
            if (probe != null && probe[0] == 1) {
                candidates.append(',').append(other.id);
                extra++;
            }
        }
        prefs().edit()
                .putString(KEY_EXIT_IDS, node.id)
                .putString(KEY_EXIT_LABEL, node.country + " · " + node.classLabel())
                .putString(KEY_EXIT_COUNTRY, node.cc)
                .putString(KEY_EXIT_CANDIDATES, candidates.toString()).apply();
        exitValue.setText(exitLabelText());
        log("第二跳出口选定：" + node.country + " " + node.host + "（候选 " + candidates + "）");
        toast("已选：" + node.country);
    }

    /** Real handshake test on the first candidates; re-sorts the list by result. */
    private void probeNodes(final LinearLayout list, final TextView status) {
        if (lastExitNodes.isEmpty()) {
            toast("节点列表还没加载完");
            return;
        }
        final java.util.List<VpnGate.Node> batch = new java.util.ArrayList<VpnGate.Node>();
        for (int i = 0; i < Math.min(lastExitNodes.size(), 12); i++) {
            batch.add(lastExitNodes.get(i));
        }
        StringBuilder ids = new StringBuilder();
        for (VpnGate.Node node : batch) {
            if (ids.length() > 0) {
                ids.append(',');
            }
            ids.append(node.id);
        }
        status.setText("正在对 " + batch.size() + " 个节点做 OpenVPN 握手…");
        new Thread(new Runnable() {
            public void run() {
                final String raw = EngineService.testVpnGateNodes(MainActivity.this, ids.toString());
                ui.post(new Runnable() {
                    public void run() {
                        parseProbeResults(raw);
                        // reachable nodes first, then the rest
                        java.util.Collections.sort(lastExitNodes, new java.util.Comparator<VpnGate.Node>() {
                            public int compare(VpnGate.Node a, VpnGate.Node b) {
                                long[] pa = probeResults.get(a.id);
                                long[] pb = probeResults.get(b.id);
                                int sa = pa == null ? 1 : (pa[0] == 1 ? 0 : 2);
                                int sb = pb == null ? 1 : (pb[0] == 1 ? 0 : 2);
                                if (sa != sb) {
                                    return sa - sb;
                                }
                                long ma = pa == null ? Long.MAX_VALUE : pa[1];
                                long mb = pb == null ? Long.MAX_VALUE : pb[1];
                                return Long.compare(ma, mb);
                            }
                        });
                        renderExitList(list, status);
                    }
                });
            }
        }, "vpn-gate-probe").start();
    }

    private void parseProbeResults(String raw) {
        try {
            org.json.JSONObject root = new org.json.JSONObject(raw);
            org.json.JSONArray results = root.optJSONArray("results");
            if (results == null) {
                return;
            }
            for (int i = 0; i < results.length(); i++) {
                org.json.JSONObject item = results.optJSONObject(i);
                if (item == null) {
                    continue;
                }
                String id = item.optString("id", "");
                boolean reachable = item.optBoolean("ok", false);
                probeResults.put(id, new long[]{reachable ? 1 : 0, item.optInt("ms", 0)});
            }
        } catch (Exception ignored) {
        }
    }
    private int handshakeTimeout() {
        int[] values = {3, 5, 8};
        int index = timeoutSpinner == null ? prefs().getInt(KEY_TIMEOUT, 1)
                : timeoutSpinner.getSelectedItemPosition();
        if (index < 0 || index >= values.length) {
            index = 1;
        }
        prefs().edit().putInt(KEY_TIMEOUT, index).apply();
        return values[index];
    }

    private String upstreamProto() {
        int index = protoSpinner == null ? prefs().getInt(KEY_PROTO, 0) : protoSpinner.getSelectedItemPosition();
        if (index < 0 || index >= UPSTREAM_PROTOS.length) {
            index = 0;
        }
        prefs().edit().putInt(KEY_PROTO, index).apply();
        return UPSTREAM_PROTOS[index][0];
    }

    private String upstreamPolicy() {
        int index = policySpinner == null ? prefs().getInt(KEY_POLICY, 0) : policySpinner.getSelectedItemPosition();
        prefs().edit().putInt(KEY_POLICY, index).apply();
        if (index == 1) {
            return "bypass-cn";
        }
        return index == 2 ? "blacklist" : "global";
    }
    private void launch(int engine, String configText, Warp.Result result) {
        lastEngine = engine;
        if (engine == 0) {
            lastWgConfig = configText;
            applyUp(configText);
            return;
        }
        if (engine == 3) {
            connectUpstream();
            return;
        }
    }

        /** MASQUE does not use the WireGuard device; it registers its own EC identity. */
        private void scheduleEngineCheck() {
        ui.postDelayed(new Runnable() {
            public void run() {
                busy = false;
                if (lastEngine == 3) {
                    log(EngineService.running ? "上游引擎已接管" : "上游引擎未启动：" + EngineService.lastLog);
                    String tail = EngineService.recentLog();
                    if (!tail.isEmpty()) {
                        log("—— 引擎输出 ——");
                        log(tail);
                    }
                    if (EngineService.running) {
                        markReady();
                    }
                }
                render();
            }
        }, 3000);
    }
    /** Keeps the exit/throughput line live while the upstream engine runs. */
    private void scheduleUiTick(boolean active) {
        ui.removeCallbacks(uiTick);
        if (active) {
            ui.postDelayed(uiTick, 1000);
        }
    }

    private final Runnable uiTick = new Runnable() {
        public void run() {
            render();
        }
    };

    private String upstreamDetail() {
        StringBuilder b = new StringBuilder();
        String proto = EngineService.proto.isEmpty() ? "wg" : EngineService.proto;
        if (!EngineService.exitIP.isEmpty()) {
            b.append("出口 ");
            if (!EngineService.country.isEmpty()) {
                b.append(EngineService.country).append(' ');
            }
            b.append(EngineService.exitIP);
            b.append("  ·  ").append(proto);
            if (EngineService.latencyMs > 0) {
                b.append("  ·  ").append(EngineService.latencyMs).append(" ms");
            }
        } else if (!EngineService.endpoint.isEmpty()) {
            b.append("端点 ").append(EngineService.endpoint).append("  ·  ").append(proto);
        } else {
            b.append("上游引擎  ·  ").append(proto);
        }
        if (!EngineService.egress.isEmpty()) {
            b.append("  ·  出口 ").append(EngineService.egress);
        }
        if (EngineService.connected()) {
            b.append('\n').append("↑ ").append(speed(EngineService.upBps))
                    .append("   ↓ ").append(speed(EngineService.downBps))
                    .append("   ·   共 ").append(bytes(EngineService.upBytes + EngineService.downBytes))
                    .append("   ·   ").append(clock(EngineService.uptimeMs));
        }
        return b.toString();
    }

    private static String speed(long bps) {
        if (bps < 1024) {
            return bps + " B/s";
        }
        if (bps < 1024 * 1024) {
            return (bps / 1024) + " KB/s";
        }
        return String.format(java.util.Locale.US, "%.1f MB/s", bps / 1048576.0);
    }

    private static String bytes(long value) {
        if (value < 1024) {
            return value + " B";
        }
        if (value < 1024 * 1024) {
            return (value / 1024) + " KB";
        }
        return String.format(java.util.Locale.US, "%.1f MB", value / 1048576.0);
    }

    private static String clock(long ms) {
        long seconds = ms / 1000;
        return String.format(java.util.Locale.US, "%02d:%02d:%02d",
                seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    }
    /**
     * Mobile networks switch under the tunnel all the time (Wi-Fi to cellular,
     * cell handover). Waiting for the watchdog costs up to 45 seconds; reacting
     * to the connectivity callback cuts that to a couple of seconds.
     */
    private void registerNetworkCallback() {
        try {
            ConnectivityManager manager =
                    (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (manager == null) {
                return;
            }
            networkCallback = new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(Network network) {
                    if (!networkCallbackWarm) {
                        networkCallbackWarm = true;
                        return;
                    }
                    // Bringing the tunnel up changes the default network to the
                    // VPN itself; treating that as "network switched" tore down
                    // the tunnel we had just built.
                    try {
                        android.net.NetworkCapabilities caps = manager.getNetworkCapabilities(network);
                        if (caps != null && caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) {
                            return;
                        }
                    } catch (Throwable ignored) {
                    }
                    if (busy || engineRestartPending || lastTransitionAt > 0
                            && System.currentTimeMillis() - lastTransitionAt < 5000) {
                        return;
                    }
                    ui.removeCallbacks(networkReconnect);
                    ui.postDelayed(networkReconnect, 2500);
                }
            };
            manager.registerDefaultNetworkCallback(networkCallback);
        } catch (Throwable ignored) {
        }
    }

    private final Runnable networkReconnect = new Runnable() {
        public void run() {
            boolean up = EngineService.running || TunnelManager.state() == Tunnel.State.UP;
            if (!up || busy || userDown || engineRestartPending) {
                return;
            }
            log("网络已切换，自动重连…");
            connectionReady = false;
            lastTransitionAt = System.currentTimeMillis();
            reconnectForNetwork();
        }
    };

    private void reconnectForNetwork() {
        if (lastEngine == 3 && lastUpstreamArgs != null) {
            restartUpstreamEngine();
        } else if (lastEngine == 0 && !lastWgConfig.isEmpty()) {
            // The old tunnel is usually still up; up() on a live backend throws
            // BackendException, so always drop it first.
            new Thread(new Runnable() {
                public void run() {
                    try {
                        TunnelManager.down();
                    } catch (Throwable ignored) {
                    }
                    ui.post(new Runnable() {
                        public void run() {
                            applyUp(lastWgConfig);
                        }
                    });
                }
            }, "xehn-teardown").start();
        }
    }

    private void restartUpstreamEngine() {
        lastTransitionAt = System.currentTimeMillis();
        final String[] args = lastUpstreamArgs;
        if (args == null) {
            return;
        }
        upstreamConnectStart = System.currentTimeMillis();
        engineRestartPending = true;
        EngineService.stop(this);
        ui.postDelayed(new Runnable() {
            public void run() {
                EngineService.start(MainActivity.this, args[0], args[1], args[2],
                        "1".equals(args[3]), Integer.parseInt(args[4]), args[5],
                        exitIdsForConnect(), args[7], args[8], Integer.parseInt(args[9]));
                engineRestartPending = false;
            }
        }, 800);
    }
    /**
     * A protocol that cannot dial (e.g. MASQUE on a network that resets TCP 500)
     * would otherwise sit in "connecting" forever. After 30 seconds: fall back to
     * plain WireGuard once, then give up honestly.
     */
    private void checkUpstreamConnectStall() {
        if (lastEngine != 3 || !EngineService.running || EngineService.connected()) {
            return;
        }
        if (upstreamConnectStart == 0) {
            upstreamConnectStart = System.currentTimeMillis();
            return;
        }
        long waitedMs = System.currentTimeMillis() - upstreamConnectStart;
        if (waitedMs < 30000L) {
            return;
        }
        if (!upstreamFallbackTried && lastUpstreamArgs != null
                && !"wg".equals(lastUpstreamArgs[0])) {
            upstreamFallbackTried = true;
            final String failedProto = lastUpstreamArgs[0];
            lastUpstreamArgs[0] = "wg";
            upstreamConnectStart = System.currentTimeMillis();
            log("连接超时：" + failedProto + " 30 秒未建立隧道，自动回退到 wg");
            ui.post(new Runnable() {
                public void run() {
                    restartUpstreamEngine();
                }
            });
            return;
        }
        log("连接超时：30 秒内未能建立隧道，已停止尝试（见上方引擎日志）");
        connectionFailed = true;
        ui.post(new Runnable() {
            public void run() {
                EngineService.stop(MainActivity.this);
                render();
            }
        });
    }
    /** Honest numbers only: an unknown value shows as a dash, never as zero. */
    private void updateStatChips(boolean upstream) {
        if (chipLatency == null) {
            return;
        }
        long latency = lastLatency;
        if (upstream && EngineService.latencyMs > 0) {
            latency = EngineService.latencyMs;
        }
        chipLatency.setText(latency >= 0 ? "延迟 " + latency + " ms" : "延迟 —");

        String exit = "";
        if (upstream) {
            if (!EngineService.exitIP.isEmpty()) {
                exit = EngineService.country.isEmpty()
                        ? EngineService.exitIP
                        : EngineService.country + " " + EngineService.exitIP;
            }
        } else if (!lastEndpoint.isEmpty()) {
            exit = lastEndpoint;
        }
        chipExit.setText(exit.isEmpty() ? "出口 —" : "出口 " + exit);

        long uptimeMs = upstream ? EngineService.uptimeMs : 0;
        if (uptimeMs <= 0 && connectStartAt > 0 && (upstream || TunnelManager.state() == Tunnel.State.UP)) {
            uptimeMs = System.currentTimeMillis() - connectStartAt;
        }
        chipUptime.setText("时长 " + clock(Math.max(0, uptimeMs)));
    }

    private void markReady() {
        connectStartAt = System.currentTimeMillis();
        connectionReady = true;
        connectionFailed = false;
        startWatchdog();
    }

    private void startWatchdog() {
        stopWatchdog();
        watchdogRunning = true;
        lastRxBytes = 0;
        watchdogThread = new Thread(new Runnable() {
            public void run() {
                int failures = 0;
                int tick = 0;
                while (watchdogRunning) {
                    sleep(5000);
                    if (!watchdogRunning || userDown) {
                        return;
                    }
                    tick++;
                    checkUpstreamConnectStall();
                    if (lastEngine == 3 && (EngineService.needRecover
                            || "error".equals(EngineService.state))) {
                        log("看门狗：引擎判定出口已死（"
                                + ("error".equals(EngineService.state) ? EngineService.message : "needRecover")
                                + "），立即重连");
                        EngineService.needRecover = false;
                        failures = 3;
                    }
                    boolean healthy = failures >= 3 ? false : checkHealthy(tick);
                    failures = healthy ? 0 : failures + 1;
                    if (failures >= 3) {
                        failures = 0;
                        if (!reconnectTunnel()) {
                            log("看门狗：多次重连失败，停止自动重连");
                            watchdogRunning = false;
                            return;
                        }
                    }
                }
            }
        }, "mccx-watchdog");
        watchdogThread.start();
    }

    /**
     * Liveness check. It probes through the tunnel instead of trusting counters:
     * an idle-but-working tunnel has a stale handshake and no traffic growth, and
     * must not be torn down.
     */
    private boolean checkHealthy(int tick) {
        if (tick % 3 != 0) {
            return true;   // probe roughly every 15 seconds, not every tick
        }
        if (lastEngine == 3 && EngineService.running) {
            String state = EngineService.state;
            if ("error".equals(state)) {
                log("看门狗：上游引擎报错 " + EngineService.message);
                return false;
            }
            // connecting/stopping are transient: only a hard error counts.
            return true;
        }
        if (TunnelManager.state() != Tunnel.State.UP) {
            return false;
        }
        SelfCheck.Info info = SelfCheck.run();
        if (!info.error.isEmpty()) {
            log("看门狗：出口探测失败 " + info.error);
            return false;
        }
        return true;
    }
    private boolean reconnectTunnel() {
        long now = System.currentTimeMillis();
        if (reconnectWindowStart == 0 || now - reconnectWindowStart > 5 * 60 * 1000L) {
            reconnectWindowStart = now;
            reconnectCount = 0;
        }
        if (reconnectCount >= 3) {
            return false;
        }
        reconnectCount++;
        log("看门狗：出口无响应，第 " + reconnectCount + " 次重连…");
        watchdogRunning = false;
        ui.post(new Runnable() {
            public void run() {
                connectionReady = false;
                connectionFailed = false;
                render();
            }
        });
        if (lastEngine == 3) {
            if (lastUpstreamArgs == null) {
                return false;
            }
            ui.post(new Runnable() {
                public void run() {
                    restartUpstreamEngine();
                }
            });
            return true;
        }
        if (lastEngine == 0 && !lastWgConfig.isEmpty()) {
            applyUp(lastWgConfig);
        } else {
            return false;
        }
        return true;
    }

    private void stopWatchdog() {
        watchdogRunning = false;
        watchdogThread = null;
    }
    /**
     * Proves the tunnel carries traffic: mihomo fetches a URL through the proxy
     * and reports the delay. "接管" alone only means the fd arrived.
     */
        private void startDisconnect() {
        // Any in-flight handshake watcher or endpoint retry must not fire after
        // this point; the user asked for "off", not "try again".
        stopToken++;
        userDown = true;
        connectionReady = false;
        connectionFailed = false;
        stopWatchdog();
        busy = true;
        render();

        // Stop everything, not just "ask the library nicely": a leftover engine
        // or a system always-on VPN is what made the tunnel come back by itself.
        try {
            if (EngineService.running) {
                EngineService.stop(this);
            }
        } catch (Exception ignored) {
        }
        ui.postDelayed(new Runnable() {
            public void run() {
                String alwaysOn = "无";
                try {
                    String app = Settings.Secure.getString(getContentResolver(), "always_on_vpn_app");
                    if (app != null && !app.isEmpty()) {
                        alwaysOn = app;
                    }
                } catch (Exception ignored) {
                }
                if (!"无".equals(alwaysOn)) {
                    log("系统「始终开启的 VPN」= " + alwaysOn + "，它会在断开后自动重连");
                }
                render();
            }
        }, 1500);
        new Thread(new Runnable() {
            public void run() {
                try {
                    TunnelManager.down();
                } catch (IllegalStateException ignored) {
                    // mihomo-only session: the engine never attached to the WG backend.
                } catch (final Exception e) {
                    fail(e);
                    return;
                }
                try {
                    // Belt and braces: make the WG service go away even if the
                    // backend thought the tunnel was already down.
                    stopService(new Intent(MainActivity.this,
                            com.wireguard.android.backend.GoBackend.VpnService.class));
                } catch (Exception ignored) {
                }
                ui.post(new Runnable() {
                    public void run() {
                        busy = false;
                        exitInfo = "";
                        log("已断开");
                        render();
                    }
                });
            }
        }, "xehn-disconnect").start();
    }

    private void applyUp(final String configText) {
        busy = true;
        render();
        log("建立隧道…");
        new Thread(new Runnable() {
            public void run() {
                try {
                    TunnelManager.attach(MainActivity.this, MainActivity.this);
                    // up() on a live backend raises BackendException; make the
                    // reconnect path idempotent.
                    try {
                        if (TunnelManager.state() == Tunnel.State.UP) {
                            TunnelManager.down();
                            Thread.sleep(300);
                        }
                    } catch (Throwable ignored) {
                    }
                    TunnelManager.up(configText);
                    ui.post(new Runnable() {
                        public void run() {
                            busy = false;
                            render();
                            watchHandshake();
                        }
                    });
                } catch (final Exception e) {
                    fail(e);
                }
            }
        }, "xehn-tunnel").start();
    }

    /**
     * TUN up is not the same as a working tunnel: poll the counters for a
     * handshake, and fall back to the canonical endpoint once if it never comes.
     */
    private void watchHandshake() {
        final int token = stopToken;
        new Thread(new Runnable() {
            public void run() {
                TunnelManager.Snapshot last = null;
                for (int i = 0; i < 6; i++) {
                    sleep(2000);
                    if (token != stopToken || TunnelManager.state() != Tunnel.State.UP) {
                        return;
                    }
                    last = TunnelManager.snapshot();
                    if (!last.available) {
                        log("统计不可用，跳过握手判断");
                        break;
                    }
                    if (i == 0 || i == 2 || i == 5) {
                        log(TunnelManager.statsLine());
                    }
                    if (last.handshakeMs > 0) {
                        log("握手成功（端口 " + PORTS[portPlan[portAttempt]] + "）");
                        ui.post(new Runnable() { public void run() { markReady(); render(); } });
                        prefs().edit().putInt(KEY_PORT, portPlan[portAttempt]).apply();
                        startSelfCheck();
                        return;
                    }
                }
                if (token != stopToken) {
                    return;
                }
                // Only rebuild the tunnel on positive evidence: bytes went out
                // and not one came back. Anything less and a working tunnel
                // might be torn down for nothing.
                if (last != null && last.available && last.tx > 0 && last.rx == 0) {
                    if (portAttempt + 1 < portPlan.length) {
                        int failed = portPlan[portAttempt];
                        portAttempt++;
                        int next = portPlan[portAttempt];
                        log("端口 " + PORTS[failed] + " 没有回包，改试 " + PORTS[next] + "…");
                        reconnectWithPort(token, next);
                        return;
                    }
                    if (!retriedFixed) {
                        retriedFixed = true;
                        log("四个端口都没有回包，改用默认端点 " + Warp.DEFAULT_ENDPOINT);
                        reconnectWithFixedEndpoint(token);
                        return;
                    }
                    log("端口与默认端点都试过了：当前网络很可能封了 WARP 的 UDP");
                    return;
                }
                startSelfCheck();
            }
        }, "xehn-handshake").start();
    }

    /** Rebuilds the tunnel against the same edge on a different port. */
    private void reconnectWithPort(final int token, final int portIndex) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    Warp.Account account = Warp.Account.fromJson(prefs().getString(KEY_ACCOUNT, ""));
                    final Warp.Result retry = Warp.generateFixed(
                            "wg", endpointHost + ":" + PORTS[portIndex], account, logger);
                    if (token != stopToken) {
                        log("已取消端口重试");
                        return;
                    }
                    lastEndpoint = retry.endpoint;
                    lastWgResult = retry;
                    lastLatency = -1;
                    TunnelManager.down();
                    ui.post(new Runnable() {
                        public void run() {
                            if (token != stopToken) {
                                return;
                            }
                            applyUp(retry.config);
                        }
                    });
                } catch (final Exception e) {
                    fail(e);
                }
            }
        }, "xehn-port-retry").start();
    }

    private void reconnectWithFixedEndpoint(final int token) {
        log("改用默认端点 engage.cloudflareclient.com:2408 重试…");
        new Thread(new Runnable() {
            public void run() {
                try {
                    Warp.Account account = Warp.Account.fromJson(prefs().getString(KEY_ACCOUNT, ""));
                    final Warp.Result fixed = Warp.generateFixed("wg", Warp.DEFAULT_ENDPOINT, account, logger);
                    if (token != stopToken) {
                        log("已取消自动重试");
                        return;
                    }
                    lastEndpoint = fixed.endpoint;
                    lastWgResult = fixed;
                    lastLatency = -1;
                    TunnelManager.down();
                    ui.post(new Runnable() {
                        public void run() {
                            if (token != stopToken) {
                                return;
                            }
                            applyUp(fixed.config);
                        }
                    });
                } catch (final Exception e) {
                    fail(e);
                }
            }
        }, "xehn-fixed-endpoint").start();
    }

    /** Asks Cloudflare who we look like now; runs through the fresh tunnel. */
    private void startSelfCheck() {
        exitInfo = "自检中…";
        ui.post(new Runnable() {
            public void run() {
                render();
            }
        });
        new Thread(new Runnable() {
            public void run() {
                SelfCheck.Info info = null;
                for (int i = 0; i < 3; i++) {
                    info = SelfCheck.run();
                    if (info.error.isEmpty()) {
                        break;
                    }
                    if (TunnelManager.state() != Tunnel.State.UP) {
                        break;
                    }
                    sleep(3000);
                }
                final SelfCheck.Info result = info;
                ui.post(new Runnable() {
                    public void run() {
                        exitInfo = result.describe();
                        log(exitInfo);
                        if (!result.error.isEmpty()) {
                            // Exit verification is the gate, not the handshake:
                            // "no answer through the tunnel" means unusable.
                            connectionFailed = true;
                            log("出口验证失败：隧道没有真正承载流量");
                        } else if (!result.throughWarp()) {
                            log("警告：warp=off，流量可能没有从 WARP 出口出去");
                        }
                        render();
                    }
                });
            }
        }, "xehn-selfcheck").start();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_VPN) {
            return;
        }
        String configText = pendingConfig;
        pendingConfig = null;
        if (resultCode == RESULT_OK && configText != null) {
            launch(pendingEngine, configText, pendingResult);
        } else {
            busy = false;
            log("已取消 VPN 授权");
            render();
        }
    }

    // ---------------------------------------------------------- callbacks

    @Override
    public void onTunnelState(final Tunnel.State state) {
        // A VPN that comes back up right after the user switched it off is almost
        // always the system (always-on VPN) or a stale retry; honour the user.
        if (state == Tunnel.State.UP && userDown) {
            if (recloseCount++ < 2) {
                log("隧道被重新拉起，正在再次关闭…");
                new Thread(new Runnable() {
                    public void run() {
                        try {
                            TunnelManager.down();
                        } catch (Exception ignored) {
                        }
                    }
                }, "xehn-reclose").start();
            } else {
                log("隧道反复被系统拉起：多半开启了系统设置里的『始终开启的 VPN』，关掉它即可");
            }
            return;
        }
        ui.post(new Runnable() {
            public void run() {
                busy = false;
                // The backend reports the old state once while tearing down, which
                // is not news to the user: only log real transitions.
                if (state != lastState) {
                    lastState = state;
                    log(state == Tunnel.State.UP ? "状态：已连接" : "状态：已断开");
                }
                if (state != Tunnel.State.UP) {
                    exitInfo = "";
                }
                render();
            }
        });
    }

    // -------------------------------------------------------------- utils

    private SharedPreferences prefs() {
        return getSharedPreferences(PREFS, MODE_PRIVATE);
    }

    private void log(final String line) {
        appendLog(line);
    }

    private void appendLog(final String line) {
        LogStore.append(line);
        ui.post(new Runnable() {
            public void run() {
                logLines.append(line).append('\n');
                int lines = 0;
                for (int i = 0; i < logLines.length(); i++) {
                    if (logLines.charAt(i) == '\n') {
                        lines++;
                    }
                }
                while (lines > LOG_LINES) {
                    int cut = logLines.indexOf("\n");
                    logLines.delete(0, cut + 1);
                    lines--;
                }
                logView.setText(logLines.toString());
            }
        });
    }

    private void checkUpdate() {
        log("检查更新…");
        new Thread(new Runnable() {
            public void run() {
                final Updater.Info info = Updater.check();
                ui.post(new Runnable() {
                    public void run() {
                        int current = Updater.currentVersionCode(MainActivity.this);
                        if (!info.error.isEmpty()) {
                            log(info.describe());
                            toast(info.describe());
                            return;
                        }
                        if (!info.isNewerThan(current)) {
                            log("已是最新版本（" + current + "）");
                            toast("已是最新版本");
                            return;
                        }
                        log(info.describe());
                        new AlertDialog.Builder(MainActivity.this)
                                .setTitle("发现新版本")
                                .setMessage(info.describe() + "\n\n下载并安装？")
                                .setPositiveButton("更新", new DialogInterface.OnClickListener() {
                                    public void onClick(DialogInterface dialog, int which) {
                                        startInstall(info);
                                    }
                                })
                                .setNegativeButton("取消", null)
                                .show();
                    }
                });
            }
        }, "xehn-update-check").start();
    }

    private void startInstall(final Updater.Info info) {
        log("开始下载 " + info.versionName + "…");
        new Thread(new Runnable() {
            public void run() {
                try {
                    Updater.downloadAndInstall(MainActivity.this, info, new Updater.Log() {
                        public void log(String line) {
                            appendLog(line);
                        }
                    });
                } catch (Exception e) {
                    final String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
                    ui.post(new Runnable() {
                        public void run() {
                            log("更新失败：" + message);
                            toast("更新失败：" + message);
                        }
                    });
                }
            }
        }, "xehn-update-install").start();
    }

    /**
     * Probes the one precondition the subprocess design depends on: whether
     * Android lets an app execute a binary shipped as lib*.so inside
     * nativeLibraryDir. Some ROMs refuse, and the answer decides the design.
     */
    private void postProbe(final String report) {
        ui.post(new Runnable() {
            public void run() {
                log(report);
                toast("内核探测完成");
            }
        });
    }

    /** Forgets the registered WARP device so the next connect starts fresh. */
    private void resetDevice() {
        prefs().edit()
                .remove(KEY_ACCOUNT)
                .apply();
        logLines.setLength(0);
        log("已清除本机 WARP 设备，下次连接会重新注册");
        toast("已重置");
        render();
    }

    /** Shares the in-memory view plus the on-disk file path. */
    private void shareLog() {
        String text = logLines.toString();
        if (text.isEmpty()) {
            toast("还没有日志");
            return;
        }
        java.io.File file = LogStore.file();
        String note = file == null ? "" : "\n\n完整日志：" + file.getAbsolutePath();
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_SUBJECT, "MccX log");
        intent.putExtra(Intent.EXTRA_TEXT, text + note);
        startActivity(Intent.createChooser(intent, "分享日志"));
    }

    private void copyLog() {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText("xehn-log", logLines.toString()));
        toast("日志已复制");
    }

    private void fail(final Exception e) {
        final String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        ui.post(new Runnable() {
            public void run() {
                busy = false;
                log("失败：" + message);
                render();
                Toast.makeText(MainActivity.this, "连接失败：" + message, Toast.LENGTH_LONG).show();
            }
        });
    }

    private void toast(final String text) {
        ui.post(new Runnable() {
            public void run() {
                Toast.makeText(MainActivity.this, text, Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    private int dp(int value) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value,
                getResources().getDisplayMetrics());
    }
}
























































