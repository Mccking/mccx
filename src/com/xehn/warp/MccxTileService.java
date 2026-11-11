package com.xehn.warp;

import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

/**
 * Quick Settings tile: one tap to connect or disconnect.
 *
 * <p>Disconnecting is handled here directly (stopping the engine is just a
 * service call). Connecting has to open the app, because the first connection
 * needs the system VPN consent dialog, and a tile cannot host that.
 */
public final class MccxTileService extends TileService {

    @Override
    public void onStartListening() {
        refreshTile();
    }

    @Override
    public void onClick() {
        if (isTunnelUp()) {
            disconnectNow();
            refreshTile();
            return;
        }
        // Connect without opening the app. The activity is only needed the very
        // first time, for the system VPN consent dialog.
        if (HeadlessConnect.consentGranted(this)) {
            HeadlessConnect.connect(this);
            refreshTile();
            scheduleRefresh(2500);
            scheduleRefresh(8000);
            return;
        }
        Intent intent = new Intent(this, MainActivity.class)
                .setAction(MainActivity.ACTION_CONNECT)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        collapseTo(intent);
        refreshTile();
    }

    /** Keeps the tile honest while the tunnel comes up in the background. */
    private void scheduleRefresh(long delayMs) {
        android.os.Handler handler = new android.os.Handler(getMainLooper());
        handler.postDelayed(new Runnable() {
            public void run() {
                refreshTile();
            }
        }, delayMs);
    }

    private boolean isTunnelUp() {
        try {
            return EngineService.running || TunnelManager.isUp();
        } catch (Throwable t) {
            return false;
        }
    }

    private void disconnectNow() {
        try {
            if (EngineService.running) {
                EngineService.stop(this);
            }
        } catch (Throwable ignored) {
        }
        try {
            if (TunnelManager.isUp()) {
                new Thread(new Runnable() {
                    public void run() {
                        try {
                            TunnelManager.down();
                        } catch (Throwable ignored) {
                        }
                    }
                }, "tile-down").start();
            }
        } catch (Throwable ignored) {
        }
    }

    /** Android 14 wants a PendingIntent; older releases take the Intent. */
    private void collapseTo(Intent intent) {
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                PendingIntent pending = PendingIntent.getActivity(this, 0, intent,
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
                startActivityAndCollapse(pending);
            } else {
                startActivityAndCollapse(intent);
            }
        } catch (Throwable ignored) {
        }
    }

    private void refreshTile() {
        try {
            Tile tile = getQsTile();
            if (tile == null) {
                return;
            }
            boolean up = isTunnelUp();
            if (up) {
                tile.setState(Tile.STATE_ACTIVE);
                tile.setLabel("MccX 已连接");
            } else if (HeadlessConnect.connecting) {
                tile.setState(Tile.STATE_UNAVAILABLE);
                tile.setLabel("MccX 连接中…");
            } else if (!HeadlessConnect.lastError.isEmpty()) {
                tile.setState(Tile.STATE_INACTIVE);
                tile.setLabel("MccX 连接失败");
            } else {
                tile.setState(Tile.STATE_INACTIVE);
                tile.setLabel("MccX");
            }
            tile.updateTile();
        } catch (Throwable ignored) {
        }
    }
}
