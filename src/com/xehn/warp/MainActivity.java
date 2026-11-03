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
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
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
    private static final String PREFS = "xehn";
    private static final String KEY_ACCOUNT = "account";
    private static final String KEY_PORT = "port_index";
    private static final int[] PORTS = {2408, 500, 1701, 443};
    private static final int LOG_LINES = 12;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final StringBuilder logLines = new StringBuilder();

    private TextView statusView;
    private TextView detailView;
    private TextView logView;
    private Button connectButton;
    private Spinner portSpinner;
    private Spinner engineSpinner;
    private Warp.Result pendingResult;
    private boolean pendingMihomo;

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
    private int recloseCount;

    private final Warp.Log logger = new Warp.Log() {
        public void log(String line) {
            appendLog(line);
        }
    };

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(buildUi());
        // The backend is constructed on the connect worker: loading libwg-go.so
        // on the UI thread would make the first frame stutter.
        render();
        autoCheckUpdate();
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
    protected void onResume() {
        super.onResume();
        render();
    }

    // ------------------------------------------------------------------ ui

    private View buildUi() {
        int pad = dp(22);

        ScrollView root = new ScrollView(this);
        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        column.setPadding(pad, pad, pad, pad);
        root.addView(column, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView title = new TextView(this);
        title.setText("MccX");
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 26);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        column.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("WARP 客户端 · 内置 WireGuard 内核 · 一键全局");
        subtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        subtitle.setTextColor(Color.GRAY);
        subtitle.setPadding(0, dp(2), 0, dp(24));
        column.addView(subtitle);

        statusView = new TextView(this);
        statusView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 30);
        statusView.setTypeface(Typeface.DEFAULT_BOLD);
        column.addView(statusView);

        detailView = new TextView(this);
        detailView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        detailView.setTextColor(Color.GRAY);
        detailView.setPadding(0, dp(6), 0, dp(20));
        column.addView(detailView);

        LinearLayout portRow = new LinearLayout(this);
        portRow.setOrientation(LinearLayout.HORIZONTAL);
        portRow.setGravity(android.view.Gravity.CENTER_VERTICAL);

        TextView portLabel = new TextView(this);
        portLabel.setText("端点端口");
        portLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        portLabel.setTextColor(Color.DKGRAY);
        portLabel.setPadding(0, 0, dp(12), 0);
        portRow.addView(portLabel);

        portSpinner = new Spinner(this);
        ArrayAdapter<String> ports = new ArrayAdapter<String>(this, android.R.layout.simple_spinner_item);
        ports.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        for (int p : PORTS) {
            ports.add(String.valueOf(p));
        }
        portSpinner.setAdapter(ports);
        portSpinner.setSelection(prefs().getInt(KEY_PORT, 2));  // 1701 by default
        portRow.addView(portSpinner, new LinearLayout.LayoutParams(dp(110), dp(44)));
        column.addView(portRow);

        LinearLayout engineRow = new LinearLayout(this);
        engineRow.setOrientation(LinearLayout.HORIZONTAL);
        engineRow.setGravity(android.view.Gravity.CENTER_VERTICAL);
        engineRow.setPadding(0, dp(8), 0, 0);

        TextView engineLabel = new TextView(this);
        engineLabel.setText("隧道引擎");
        engineLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        engineLabel.setTextColor(Color.DKGRAY);
        engineLabel.setPadding(0, 0, dp(12), 0);
        engineRow.addView(engineLabel);

        engineSpinner = new Spinner(this);
        ArrayAdapter<String> engines = new ArrayAdapter<String>(this, android.R.layout.simple_spinner_item);
        engines.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        engines.add("内置 WireGuard");
        engines.add("mihomo（实验）");
        engineSpinner.setAdapter(engines);
        engineRow.addView(engineSpinner, new LinearLayout.LayoutParams(dp(180), dp(44)));
        column.addView(engineRow);

        connectButton = new Button(this);
        connectButton.setAllCaps(false);
        connectButton.setTextSize(TypedValue.COMPLEX_UNIT_SP, 17);
        connectButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                onConnectClicked();
            }
        });
        LinearLayout.LayoutParams buttonLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(56));
        buttonLp.setMargins(0, dp(12), 0, 0);
        column.addView(connectButton, buttonLp);

        TextView logTitle = new TextView(this);
        logTitle.setText("运行日志");
        logTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        logTitle.setTextColor(Color.DKGRAY);
        logTitle.setPadding(0, dp(22), 0, dp(6));
        column.addView(logTitle);

        logView = new TextView(this);
        logView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextColor(Color.DKGRAY);
        logView.setBackgroundColor(Color.rgb(246, 246, 246));
        logView.setPadding(dp(10), dp(10), dp(10), dp(10));
        logView.setTextIsSelectable(true);
        ScrollView logScroll = new ScrollView(this);
        logScroll.addView(logView, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        column.addView(logScroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(200)));

        LinearLayout logActions = new LinearLayout(this);
        logActions.setOrientation(LinearLayout.HORIZONTAL);
        logActions.setPadding(0, dp(6), 0, 0);

        Button retest = new Button(this);
        retest.setText("重新自检");
        retest.setAllCaps(false);
        retest.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        retest.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (TunnelManager.state() == Tunnel.State.UP) {
                    startSelfCheck();
                } else {
                    toast("请先连接");
                }
            }
        });
        logActions.addView(retest);

        Button probe = new Button(this);
        probe.setText("测试内核");
        probe.setAllCaps(false);
        probe.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        probe.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                probeMihomo();
            }
        });
        logActions.addView(probe);

        Button copyLog = new Button(this);
        copyLog.setText("复制日志");
        copyLog.setAllCaps(false);
        copyLog.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        copyLog.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                copyLog();
            }
        });
        logActions.addView(copyLog);

        Button update = new Button(this);
        update.setText("检查更新");
        update.setAllCaps(false);
        update.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        update.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                checkUpdate();
            }
        });
        logActions.addView(update);
        column.addView(logActions);

        TextView footnote = new TextView(this);
        footnote.setText("全局流量经 Cloudflare WARP 出口。\n引擎逻辑源自 github.com/hezhanleiok/xehn（仅学习交流，禁止售卖）。");
        footnote.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        footnote.setTextColor(Color.GRAY);
        footnote.setPadding(0, dp(16), 0, 0);
        column.addView(footnote);

        return root;
    }

    private void render() {
        boolean up = MihomoVpnService.running || TunnelManager.state() == Tunnel.State.UP;
        if (busy) {
            statusView.setText("连接中…");
            statusView.setTextColor(Color.rgb(230, 140, 20));
            connectButton.setText("请稍候");
            connectButton.setEnabled(false);
        } else if (up) {
            statusView.setText("已连接");
            statusView.setTextColor(Color.rgb(20, 140, 60));
            connectButton.setText("断开");
            connectButton.setEnabled(true);
        } else {
            statusView.setText("未连接");
            statusView.setTextColor(Color.rgb(120, 120, 120));
            connectButton.setText("连接");
            connectButton.setEnabled(true);
        }

        StringBuilder detail = new StringBuilder();
        if (up || (!lastEndpoint.isEmpty() && !busy)) {
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

        logView.setText(logLines.toString());
    }

    // ------------------------------------------------------------- actions

    private void onConnectClicked() {
        if (busy) {
            return;
        }
        if (TunnelManager.state() == Tunnel.State.UP) {
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

    private void startConnect() {
        userDown = false;
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
        final boolean useMihomo = engineSpinner.getSelectedItemPosition() == 1;
        portPlan = orderPorts(portIndex);
        portAttempt = 0;

        new Thread(new Runnable() {
            public void run() {
                try {
                    Warp.Account existing = Warp.Account.fromJson(prefs().getString(KEY_ACCOUNT, ""));
                    Warp.Result result = Warp.generate("wg", port, true, existing, logger);
                    prefs().edit()
                            .putString(KEY_ACCOUNT, result.account.toJson())
                            .putInt(KEY_PORT, portIndex)
                            .apply();
                    lastEndpoint = result.endpoint;
                    lastLatency = result.latencyMs;
                    int split = result.endpoint.lastIndexOf(':');
                    endpointHost = split > 0 ? result.endpoint.substring(0, split) : result.endpoint;

                    final String configText = result.config;
                    final Warp.Result finalResult = result;
                    ui.post(new Runnable() {
                        public void run() {
                            Intent consent = VpnService.prepare(MainActivity.this);
                            if (consent != null) {
                                pendingConfig = configText;
                                pendingMihomo = useMihomo;
                                pendingResult = finalResult;
                                startActivityForResult(consent, REQ_VPN);
                            } else {
                                launch(useMihomo, configText, finalResult);
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
    private void launch(boolean mihomo, String configText, Warp.Result result) {
        if (!mihomo) {
            applyUp(configText);
            return;
        }
        try {
            int split = result.endpoint.lastIndexOf(':');
            String host = result.endpoint.substring(0, split);
            int port = Integer.parseInt(result.endpoint.substring(split + 1));
            MihomoVpnService.start(this, MihomoConfig.build(result.account, host, port, false, false));
            log("mihomo 内核启动中…");
            ui.postDelayed(new Runnable() {
                public void run() {
                    busy = false;
                    if (MihomoVpnService.running) {
                        log("mihomo 已接管隧道");
                        String tail = MihomoVpnService.recentLog();
                        if (!tail.isEmpty()) {
                            log("—— 内核输出 ——");
                            log(tail);
                        }
                        startMihomoCheck();
                    } else {
                        log("mihomo 未启动：" + MihomoVpnService.lastLog);
                        String engineLog = MihomoVpnService.recentLog();
                        if (!engineLog.isEmpty()) {
                            log("—— 内核输出 ——");
                            log(engineLog);
                        }
                    }
                    render();
                }
            }, 3000);
        } catch (Exception e) {
            fail(e);
        }
    }

    /**
     * Proves the tunnel carries traffic: mihomo fetches a URL through the proxy
     * and reports the delay. "接管" alone only means the fd arrived.
     */
    private void startMihomoCheck() {
        new Thread(new Runnable() {
            public void run() {
                String lastError = "启动器未响应";
                for (int i = 0; i < 6; i++) {
                    try {
                        int delay = MihomoApi.delay("warp", 5000);
                        log("mihomo 隧道可用，出口延迟 " + delay + " ms");
                        return;
                    } catch (Exception e) {
                        lastError = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
                    }
                    sleep(1500);
                }
                log("mihomo 隧道不通：" + lastError);
                String tail = MihomoVpnService.recentLog();
                if (!tail.isEmpty()) {
                    log("—— 内核输出 ——");
                    log(tail);
                }
            }
        }, "mihomo-check").start();
    }

    private void startDisconnect() {
        // Any in-flight handshake watcher or endpoint retry must not fire after
        // this point; the user asked for "off", not "try again".
        stopToken++;
        userDown = true;
        busy = true;
        render();
        if (MihomoVpnService.running) {
            log("断开 mihomo…");
            MihomoVpnService.stop(this);
            busy = false;
            exitInfo = "";
            ui.postDelayed(new Runnable() {
                public void run() {
                    log(MihomoVpnService.running ? "mihomo 仍在运行" : "已断开");
                    render();
                }
            }, 1200);
            return;
        }
        log("断开隧道…");
        new Thread(new Runnable() {
            public void run() {
                try {
                    TunnelManager.down();
                    ui.post(new Runnable() {
                        public void run() {
                            busy = false;
                            exitInfo = "";
                            log("已断开");
                            render();
                        }
                    });
                } catch (final Exception e) {
                    fail(e);
                }
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
                        if (result.error.isEmpty() && !result.throughWarp()) {
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
            launch(pendingMihomo, configText, pendingResult);
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
    private void probeMihomo() {
        log("探测 mihomo 内核…");
        new Thread(new Runnable() {
            public void run() {
                StringBuilder report = new StringBuilder();
                File bin = new File(getApplicationInfo().nativeLibraryDir, "libmihomo.so");
                report.append("路径 ").append(bin.getAbsolutePath()).append('\n');
                report.append("存在 ").append(bin.exists()).append(" · 可执行 ").append(bin.canExecute()).append('\n');
                if (!bin.exists()) {
                    report.append("结论：当前 ABI 没打包 mihomo（目前只带 arm64-v8a）");
                    postProbe(report.toString());
                    return;
                }
                if (!bin.canExecute()) {
                    report.append("chmod +x → ").append(bin.setExecutable(true)).append('\n');
                }
                if (!bin.canExecute()) {
                    report.append("结论：拿不到执行权限，子进程方案不可行");
                    postProbe(report.toString());
                    return;
                }

                final Process process;
                try {
                    process = new ProcessBuilder(bin.getAbsolutePath(), "-v")
                            .redirectErrorStream(true).start();
                } catch (Exception e) {
                    report.append("启动失败：").append(e.getMessage());
                    postProbe(report.toString());
                    return;
                }

                final StringBuilder out = new StringBuilder();
                Thread reader = new Thread(new Runnable() {
                    public void run() {
                        try {
                            BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream()));
                            String line;
                            while ((line = r.readLine()) != null) {
                                out.append(line).append('\n');
                            }
                        } catch (Exception ignored) {
                        }
                    }
                });
                reader.start();

                boolean finished = false;
                try {
                    finished = process.waitFor(8, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                }
                if (!finished) {
                    process.destroyForcibly();
                }
                try {
                    reader.join(1500);
                } catch (InterruptedException ignored) {
                }

                report.append("退出码 ").append(finished ? String.valueOf(process.exitValue()) : "超时").append('\n');
                report.append("输出 ").append(out.toString().trim());
                postProbe(report.toString());
            }
        }, "xehn-probe").start();
    }

    private void postProbe(final String report) {
        ui.post(new Runnable() {
            public void run() {
                log(report);
                toast("内核探测完成");
            }
        });
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















