package dev.forgesworn.release;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * Receives the PackageInstaller session's status (declared in the manifest,
 * not exported: the system calls it through the PendingIntent that Updater
 * hands to commit). It only passes the answer to Updater, which parks the
 * system's confirm Intent for the Activity to launch.
 */
public final class UpdateReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        try {
            Updater.onInstallStatus(intent);
        } catch (Throwable t) {
            Log.w("release-kit", "updater: receiver", t);
        }
    }
}
