package me.ibrahimrafi.bwphone

import android.Manifest
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.produceState
import androidx.core.app.ActivityCompat
import androidx.core.net.toUri
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import me.ibrahimrafi.bwphone.ui.BwTheme
import me.ibrahimrafi.bwphone.ui.HomeActions
import me.ibrahimrafi.bwphone.ui.HomeData
import me.ibrahimrafi.bwphone.ui.HomeScreen

/** Status, the setup checks, pairing and enrolment, history, and Revoke — prominent, usable with no PC. */
class MainActivity : BaseActivity() {
    private lateinit var prefs: Prefs
    /** Bumped on resume: the setup checks change in system settings, outside the app. */
    private val resumes = mutableIntStateOf(0)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = Prefs(this)
        if (savedInstanceState == null && Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFICATIONS)
        }
        if (prefs.isPaired) ListenerService.start(this)

        val actions = object : HomeActions {
            override fun pair() = startActivity(Intent(this@MainActivity, PairActivity::class.java))
            override fun enrol() = startActivity(Intent(this@MainActivity, EnrolActivity::class.java))
            override fun fixBattery() = startActivity(
                Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, "package:$packageName".toUri())
            )
            override fun fixNotifications() = allowNotifications()
            override fun settings() = startActivity(Intent(this@MainActivity, SettingsActivity::class.java))
            override fun revoke(accountHex: String) {
                Keystore.delete(accountHex)
                prefs.removeAccount(accountHex)
            }
            override fun revokeAll() {
                for (id in prefs.accountIds()) Keystore.delete(id)
                prefs.clearEverything()
                stopService(Intent(this@MainActivity, ListenerService::class.java))
            }
        }

        setContent {
            BwTheme {
                val changes by AppState.changes.collectAsStateWithLifecycle()
                val listener by AppState.listener.collectAsStateWithLifecycle()
                val resumed = resumes.intValue
                val data by produceState<HomeData?>(null, changes, resumed) {
                    value = withContext(Dispatchers.IO) { load() }
                }
                HomeScreen(data = data, listener = listener, actions = actions)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        resumes.intValue++
    }

    private fun load(): HomeData {
        val pm = getSystemService(PowerManager::class.java)
        val invalidated = prefs.invalidated
        val accounts = prefs.accountIds().map { id ->
            HomeData.Account(
                id = id,
                label = prefs.label(id),
                unlocks = prefs.unlockCount(id),
                lastUnlock = prefs.lastUnlock(id),
                invalidated = id in invalidated,
                unfinished = prefs.pin(id) == null,
            )
        }.sortedBy { it.label.lowercase() }
        val history = prefs.history().mapNotNull { line ->
            val parts = line.split('|', limit = 3)
            if (parts.size != 3) null else HomeData.Event(parts[0].toLongOrNull() ?: 0L, parts[1], parts[2])
        }
        return HomeData(
            paired = prefs.isPaired,
            pcAddress = prefs.pcAddress,
            accounts = accounts,
            history = history,
            batteryExempt = pm.isIgnoringBatteryOptimizations(packageName),
            notificationsAllowed = notificationsAllowed(),
        )
    }

    /** Notifications on, and the unlock channel not switched off: the listener's own channel may be. */
    private fun notificationsAllowed(): Boolean {
        val nm = getSystemService(NotificationManager::class.java)
        val channel = nm.getNotificationChannel(App.CHANNEL_UNLOCK)
        return nm.areNotificationsEnabled() && (channel == null || channel.importance != NotificationManager.IMPORTANCE_NONE)
    }

    private fun allowNotifications() {
        val nm = getSystemService(NotificationManager::class.java)
        when {
            Build.VERSION.SDK_INT >= 33 &&
                checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
                shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS) ->
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFICATIONS)
            nm.areNotificationsEnabled() -> startActivity(
                Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                    .putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
                    .putExtra(Settings.EXTRA_CHANNEL_ID, App.CHANNEL_UNLOCK)
            )
            else -> startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        resumes.intValue++
    }

    companion object {
        private const val REQ_NOTIFICATIONS = 1
    }
}
