package me.ibrahimrafi.bwphone

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Brings the listener back after a reboot and after an app update; without
 * the latter an update stops the service for good. Auth-bound keys are
 * unavailable until the first unlock after a reboot, so a start before
 * that serves nothing yet, which is the Direct Boot dead window by design.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (!Prefs(context).isPaired) return
        try {
            ListenerService.start(context)
        } catch (e: IllegalStateException) {
            // ForegroundServiceStartNotAllowedException on Android 12+, a subclass. Boot and
            // package-replaced broadcasts, and the battery optimisation exemption, are all
            // exempt from that rule, so this should not happen; opening the app starts it.
            Log.w("bwphone.boot", "background start refused: $e")
        }
    }
}
