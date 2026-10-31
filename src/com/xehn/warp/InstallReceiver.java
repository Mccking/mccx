package com.xehn.warp;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.widget.Toast;

/**
 * Receives the installer's verdict. {@code STATUS_PENDING_USER_ACTION} carries
 * the confirmation activity the system wants us to show — without forwarding it
 * the install silently stalls.
 */
public final class InstallReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
        String message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);

        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            Intent confirm = intent.getParcelableExtra(Intent.EXTRA_INTENT);
            if (confirm != null) {
                confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                try {
                    context.startActivity(confirm);
                } catch (Exception ignored) {
                    // Nothing to do: the user will see the failure toast below.
                }
            }
            return;
        }
        if (status == PackageInstaller.STATUS_SUCCESS) {
            Toast.makeText(context, "已安装，重新打开 MccX 生效", Toast.LENGTH_LONG).show();
            return;
        }
        Toast.makeText(context, "安装失败：" + status + " " + (message == null ? "" : message),
                Toast.LENGTH_LONG).show();
    }
}
