package me.ibrahimrafi.bwphone

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        AppState.init()
        val nm = getSystemService(NotificationManager::class.java)
        // Two channels on purpose, so the persistent "listening" notification can be
        // switched off in the system's notification settings while unlock requests
        // stay on. Minimum importance: silent, collapsed, no icon in the status bar.
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_LISTENER, getString(R.string.channel_listener), NotificationManager.IMPORTANCE_MIN).apply {
                setShowBadge(false)
            }
        )
        // High importance: heads-up, sound, and it wakes the screen from the lock screen.
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_UNLOCK, getString(R.string.channel_unlock), NotificationManager.IMPORTANCE_HIGH).apply {
                setBypassDnd(false)
                lockscreenVisibility = android.app.Notification.VISIBILITY_PUBLIC
            }
        )
    }

    companion object {
        const val CHANNEL_LISTENER = "listener"
        const val CHANNEL_UNLOCK = "unlock"
    }
}
