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
        Intent intent = new Intent(this, MainActivity.class)
                .setAction(MainActivity.ACTION_CONNECT)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        collapseTo(intent);
        refreshTile();
    }

    private boolean isTunnelUp() {
        try {
            return EngineService.running || TunnelManager.isUp() || MihomoVpnService.running;
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
            if (MihomoVpnService.running) {
                MihomoVpnService.stop(this);
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
            tile.setState(up ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
            tile.setLabel(up ? "MccX 已连接" : "MccX");
            tile.updateTile();
        } catch (Throwable ignored) {
        }
    }
}
